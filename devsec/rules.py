"""R1 and R2: event-time sliding windows, deterministic reconciliation, single worker."""
from collections import Counter, defaultdict, deque
from itertools import groupby
from urllib.parse import unquote
import re
from datetime import datetime, timedelta
import hashlib
import json
import logging
import time
from sqlalchemy import select, delete
from .config import settings
from .database import database, Event, Incident, IncidentEvidence, utcnow

WINDOW = timedelta(minutes=5)


def episodes(events):
    """Group qualifying windows; a gap > 5 min starts a new episode.

    Only events belonging to a qualifying window become evidence.
    A successful login does not cancel already-observed failed attempts.
    """
    groups = defaultdict(list)
    for row in events:
        data = json.loads(row.payload)
        key = (row.service, data['environment'], data['user_id'], data['source_ip'])
        groups[key].append((datetime.fromisoformat(row.event_time), row.id))
    result = []
    for key, items in groups.items():
        queue, current, previous = deque(), None, None
        for stamp, event_id in sorted(items):
            if previous is not None and stamp - previous > WINDOW:
                queue.clear()
                current = None
            previous = stamp
            queue.append((stamp, event_id))
            while queue and stamp - queue[0][0] > WINDOW:
                queue.popleft()
            if len(queue) < 5:
                continue
            if current is None:
                current = {'key': key, 'evidence': {}, 'peak': 0}
                result.append(current)
            current['evidence'].update({identifier: at for at, identifier in queue})
            current['peak'] = max(current['peak'], len(queue))
    return result


# The demo has no route registry for unmatched requests. Generalise common ID segments.
ID_SEGMENT = re.compile(r"(?:[0-9]+|[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", re.I)
HTTP_WINDOW = timedelta(seconds=60)


def normalized_route(path):
    parts = [unquote(part) for part in path.split("/") if part]
    return tuple("{id}" if ID_SEGMENT.fullmatch(part) else part for part in parts)


def http_episodes(events):
    groups = defaultdict(list)
    for row in events:
        data = json.loads(row.payload)
        key = (row.service, data["environment"], "", data["source_ip"])
        groups[key].append((datetime.fromisoformat(row.event_time), row.id,
                            normalized_route(data["path"]), data["status_code"] in (403, 404)))

    results = []
    for key, items in groups.items():
        window = deque()
        routes = Counter()
        errors = 0
        current = previous_hit = None
        for stamp, arrivals in groupby(sorted(items), key=lambda item: item[0]):
            while window and stamp - window[0][0] > HTTP_WINDOW:
                _, _, route, failed = window.popleft()
                errors -= failed
                routes[route] -= 1
                if not routes[route]:
                    del routes[route]
            for entry in arrivals:
                window.append(entry)
                routes[entry[2]] += 1
                errors += entry[3]
            if len(routes) < 20 or 2 * errors < len(window):
                continue
            if previous_hit is None or previous_hit < window[0][0]:
                current = {"key": key, "evidence": {}, "peak": 0}
                results.append(current)
            previous_hit = stamp
            current["peak"] = max(current["peak"], len(routes))
            current["evidence"].update((identifier, at) for at, identifier, _, _ in window)
    return results


def privilege_episodes(events, maintenance):
    groups = defaultdict(list)
    for row in events:
        data = json.loads(row.payload)
        account = (row.service, data["environment"], data["user_id"])
        groups[account].append((datetime.fromisoformat(row.event_time), row.id, data))

    results = []
    for account, entries in groups.items():
        periods = [w for w in maintenance if (w.service, w.environment, w.user_id) == account]
        promotion = incident = None
        for stamp, identifier, data in sorted(entries):
            if data["event_type"] == "audit.role_change":
                promotion = (stamp, identifier) if data["new_role"] == "admin" else None
                incident = None
                continue
            if promotion is None:
                continue
            start, role_id = promotion
            if not start < stamp <= start + timedelta(minutes=15):
                continue
            if any(w.start <= start and stamp < w.end for w in periods):
                continue
            if incident is None:
                incident = {"key": (*account, data["source_ip"]), "evidence": {role_id: start}, "peak": 0}
                results.append(incident)
            incident["evidence"][identifier] = stamp
            incident["peak"] += 1
    return results


def task_violations(events):
    """The latest delegation replaces the previous one for this account and service."""
    grants = {}
    incidents = []
    for row in events:
        data = json.loads(row.payload)
        key = (row.service, data["environment"], data["user_id"])
        stamp = datetime.fromisoformat(row.event_time)
        if row.event_type == "audit.task_granted":
            grants[key] = (row.id, stamp, data)
            continue
        if row.event_type == "audit.role_change":
            if data["new_role"] == "user":
                grants.pop(key, None)
            continue
        if data["result"] == "denied":
            continue

        evidence = {row.id: stamp}
        grant = grants.get(key)
        if grant:
            grant_id, granted_at, scope = grant
            if (scope["resource"] == data["resource"] and scope["operation"] == data["operation"]
                    and stamp < datetime.fromisoformat(scope["expires_at"].replace("Z", "+00:00"))):
                continue
            evidence[grant_id] = granted_at
        incidents.append({"key": (*key, data["source_ip"]), "identity": ("task", row.external_id),
                          "peak": 1, "evidence": evidence})
    return incidents


def missed_schedules(events, schedules):
    results = []
    for row in events:
        data = json.loads(row.payload)
        if schedules.assess(data)["status"] == "Hors planning":
            results.append({"key": (row.service, data["environment"], data["user_id"], data["source_ip"]),
                            "identity": (row.source, row.external_id), "severity": "low", "peak": 1,
                            "evidence": {row.id: datetime.fromisoformat(row.event_time)}})
    return results


def evaluate(sessions, maintenance=(), schedules=None):
    # One worker only in this increment. The transaction reconciles late arrivals
    # and batch reordering; raw events are immutable and never deleted here.
    with sessions.begin() as db:
        if db.bind.dialect.name == 'postgresql':
            from sqlalchemy import text
            db.execute(text('SELECT pg_advisory_xact_lock(138001)'))
        else:
            from sqlalchemy import text
            db.execute(text('BEGIN IMMEDIATE'))
        links = defaultdict(set)
        for link in db.scalars(select(IncidentEvidence)).all():
            links[link.incident_id].add(link.event_id)
        total = 0
        for rule, event_type, detect in (("R1", "auth.failure", episodes), ("R2", "http.access", http_episodes)):
            events = db.scalars(select(Event).where(Event.event_type == event_type))
            candidates = detect(events)
            reconcile(db, rule, candidates, links)
            total += len(candidates)
        audit = db.scalars(select(Event).where(Event.event_type.in_(("audit.role_change", "audit.sensitive_action"))))
        candidates = privilege_episodes(audit, maintenance)
        tasks = select(Event).where(Event.event_type.in_(("audit.task_granted", "audit.task_action", "audit.role_change")))
        candidates.extend(task_violations(db.scalars(tasks.order_by(Event.event_time, Event.id))))
        reconcile(db, "R3", candidates, links)
        total += len(candidates)
        if schedules is not None:
            successes = db.scalars(select(Event).where(Event.event_type == "auth.success"))
            candidates = missed_schedules(successes, schedules)
            reconcile(db, "R4", candidates, links)
            total += len(candidates)
        return total


def reconcile(db, rule, candidates, links):
    old = db.scalars(select(Incident).where(Incident.rule == rule)).all()
    used = set()
    for candidate in candidates:
        key = candidate['key']
        entity = hashlib.sha256(json.dumps(candidate.get("identity", key)).encode()).hexdigest()
        proof = set(candidate['evidence'])
        matching = [r for r in old if r.id not in used and r.entity_key == entity and links[r.id] & proof]
        row = min(matching, key=lambda r: r.id) if matching else Incident(rule=rule, entity_key=entity, detected_at=utcnow())
        stamps = candidate['evidence'].values()
        start, end = min(stamps).isoformat(), max(stamps).isoformat()
        unchanged = row.id is not None and links[row.id] == proof and row.peak_count == candidate['peak']
        row.service, row.environment, row.user_id, row.source_ip = key
        row.severity = candidate.get("severity", "medium")
        row.started_at, row.last_event_at, row.peak_count = start, end, candidate['peak']
        if not unchanged:
            row.updated_at = utcnow()
        db.add(row)
        db.flush()
        used.add(row.id)
        if not unchanged:
            db.execute(delete(IncidentEvidence).where(IncidentEvidence.incident_id == row.id))
            db.add_all([IncidentEvidence(incident_id=row.id, event_id=identifier) for identifier in sorted(proof)])
    # Late events may merge formerly separated episodes. Keep the oldest
    # matching identifier, retire only redundant generated incidents.
    for row in old:
        if row.id not in used:
            db.execute(delete(IncidentEvidence).where(IncidentEvidence.incident_id == row.id))
            db.delete(row)


def main():
    logging.basicConfig(level=logging.INFO)
    from .schemas import MaintenanceWindow
    from .schedules import Schedules
    config = settings()
    schedules = Schedules(config)
    maintenance = [MaintenanceWindow.model_validate(w) for w in config.get("maintenance_windows", [])]
    engine, sessions = database(config["database_url"])
    try:
        while True:
            try:
                evaluate(sessions, maintenance, schedules)
            except Exception:
                logging.exception('Règles : évaluation interrompue, reprise au prochain cycle')
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
