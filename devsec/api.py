import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import IPvAnyAddress, ValidationError
from sqlalchemy import select, func, text, delete, cast, type_coerce, JSON
from sqlalchemy.exc import IntegrityError
from .config import settings, password_hash
from .database import CIIncident, database, Event, LoginSession, CollectorStatus, LoginAttempt, Incident, IncidentEvidence, utcnow
from .schemas import Batch, AuthEvent, event_adapter, Heartbeat

HERE = Path(__file__).parent


def create_app(config=None):
    config = config or settings()
    engine, sessions = database(config["database_url"])
    app = FastAPI(title="Agent DevSec — collecte", docs_url=None, redoc_url=None)
    app.state.engine, app.state.sessions = engine, sessions
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    @app.middleware("http")
    async def limits(request, call_next):
        # Enforce limit while reading the stream, including chunked transfers.
        if request.method == "POST":
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 1_048_576:
                    return JSONResponse({"detail": "Lot trop volumineux"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'"
        return response

    def collector_auth(request: Request):
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied, "Bearer " + config["collector_token"]):
            raise HTTPException(401, "Collecteur non autorisé")

    def authenticated(request):
        token = request.cookies.get("devsec_session", "")
        with sessions() as db:
            row = db.get(LoginSession, hashlib.sha256(token.encode()).hexdigest())
            return row is not None and row.expires_at > utcnow()

    def viewer(request: Request):
        if not authenticated(request):
            raise HTTPException(401, "Connexion requise")

    def check_origin(request):
        if request.headers.get("origin") != config["api_url"]:
            raise HTTPException(403, "Origine non autorisée")

    @app.get("/health")
    def health():
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ok", "component": "agent-api"}

    @app.get("/login")
    def login_page(request: Request):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": None})

    @app.post("/login")
    async def login(request: Request):
        check_origin(request)
        fields = parse_qs((await request.body()).decode("utf-8", errors="replace"))
        username, password = fields.get("username", [""])[0], fields.get("password", [""])[0]
        key = hashlib.sha256((request.client.host if request.client else "unknown").encode()).hexdigest()
        now = datetime.now(timezone.utc)
        with sessions.begin() as db:
            attempt = db.get(LoginAttempt, key)
            if not attempt:
                attempt = LoginAttempt(key=key, count=0, window_start=now.isoformat())
                db.add(attempt)
            if now - datetime.fromisoformat(attempt.window_start) > timedelta(minutes=5):
                attempt.count, attempt.window_start = 0, now.isoformat()
            blocked = attempt.count >= 10
            if not blocked:
                attempt.count += 1
        if blocked:
            return templates.TemplateResponse(request=request, name="login.html", context={"error": "Trop de tentatives. Réessaie dans 5 minutes."}, status_code=429)
        valid = len(password) <= 256 and hmac.compare_digest(username.encode(), config["admin_username"].encode()) and hmac.compare_digest(password_hash(password, config["password_salt"]), config["password_hash"])
        if not valid:
            return templates.TemplateResponse(request=request, name="login.html", context={"error": "Identifiants incorrects."}, status_code=401)
        token = secrets.token_urlsafe(32)
        with sessions.begin() as db:
            db.execute(delete(LoginSession).where(LoginSession.expires_at <= now.isoformat()))
            db.add(LoginSession(token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=(now + timedelta(hours=8)).isoformat()))
            db.get(LoginAttempt, key).count = 0
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("devsec_session", token, httponly=True, samesite="strict", secure=config["api_url"].startswith("https"), max_age=28800)
        return response

    @app.post("/logout")
    def logout(request: Request):
        check_origin(request)
        with sessions.begin() as db:
            db.execute(delete(LoginSession).where(LoginSession.token_hash == hashlib.sha256(request.cookies.get("devsec_session", "").encode()).hexdigest()))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("devsec_session")
        return response

    @app.get("/")
    def dashboard(request: Request):
        if not authenticated(request):
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(request=request, name="dashboard.html", context={"demo_url": config["demo_url"]})

    @app.get("/events", dependencies=[Depends(viewer)])
    def events(event_type: str = "", before: int | None = None, source_ip: IPvAnyAddress | None = None):
        if event_type not in ("", "auth.failure", "auth.success", "http.access", "audit.task_granted", "audit.task_action", "audit.role_change", "audit.sensitive_action"):
            raise HTTPException(422, "Type inconnu")
        with sessions() as db:
            query = select(Event)
            if source_ip is not None:
                payload = cast(Event.payload, JSON) if engine.dialect.name == "postgresql" else type_coerce(Event.payload, JSON)
                query = query.where(payload["source_ip"].as_string() == str(source_ip))
            if event_type:
                query = query.where(Event.event_type == event_type)
            if before is not None:
                query = query.where(Event.id < before)
            rows = db.scalars(query.order_by(Event.id.desc()).limit(51)).all()
            return {"items": [{"id": r.id, "received_at": r.received_at, **json.loads(r.payload)} for r in rows[:50]], "next_cursor": rows[49].id if len(rows) > 50 else None}

    @app.get("/stats", dependencies=[Depends(viewer)])
    def stats():
        with sessions() as db:
            total = db.scalar(select(func.count()).select_from(Event))
            failures = db.scalar(select(func.count()).select_from(Event).where(Event.outcome == "failure"))
            successes = db.scalar(select(func.count()).select_from(Event).where(Event.event_type == "auth.success"))
            row = db.get(CollectorStatus, "demo-auth")
            return {"total": total, "failures": failures, "successes": successes, "incidents": db.scalar(select(func.count()).select_from(Incident)), "storage": engine.dialect.name,
                    "collector": {"last_seen_at": row.last_seen_at, "pending": row.pending, "quarantined": row.quarantined} if row else None}

    @app.get("/ci/incidents", dependencies=[Depends(viewer)])
    def ci_incidents():
        with sessions() as db:
            rows = db.scalars(select(CIIncident).order_by(CIIncident.updated.desc()).limit(50))
            return {"items": [{**{c.name: getattr(row, c.name) for c in CIIncident.__table__.columns},
                               "url": f"https://github.com/{row.repo}/actions/runs/{row.run_id}/attempts/{row.attempt}"}
                              for row in rows]}

    def incident_json(row):
        return {column.name: getattr(row, column.name) for column in Incident.__table__.columns}

    @app.get('/incidents', dependencies=[Depends(viewer)])
    def incidents(before: int | None = None):
        with sessions() as db:
            query = select(Incident)
            if before is not None:
                query = query.where(Incident.id < before)
            rows = db.scalars(query.order_by(Incident.id.desc()).limit(51)).all()
            return {'items': [incident_json(row) for row in rows[:50]], 'next_cursor': rows[49].id if len(rows)>50 else None}

    @app.get('/incidents/{incident_id}', dependencies=[Depends(viewer)])
    def incident_detail(incident_id: int):
        with sessions() as db:
            row = db.get(Incident, incident_id)
            if row is None:
                raise HTTPException(404, 'Incident inconnu')
            proofs = db.scalars(select(Event).join(IncidentEvidence, IncidentEvidence.event_id == Event.id).where(IncidentEvidence.incident_id == incident_id).order_by(Event.event_time, Event.id)).all()
            if row.rule == "R3":
                title = "Action sensible après élévation de rôle"
                explanation = "Le même compte a obtenu le rôle admin puis modifié un paramètre sous 15 minutes, hors intervention autorisée couvrant la séquence."
                if any(p.event_type == "audit.task_action" for p in proofs):
                    title = "Action exécutée hors autorisation"
                    explanation = "Aucune délégation valide ne couvre cette opération sur cette ressource au moment de son exécution."
            elif row.rule == "R2":
                title = "Scan HTTP possible"
                explanation = "Au moins 20 routes distinctes en 60 secondes, avec au moins 50 % de réponses 403 ou 404 pour cette IP et ce service."
            else:
                title = "Échecs de connexion répétés"
                explanation = "Au moins 5 échecs du même compte et de la même IP sur 5 minutes."
            return {**incident_json(row), "title": title, "explanation": explanation,
                    "evidence": [json.loads(event.payload) for event in proofs]}

    @app.post("/events/batch", status_code=202, dependencies=[Depends(collector_auth)])
    def ingest(batch: Batch):
        accepted, duplicates, rejected = [], [], []
        with sessions.begin() as db:
            for index, raw in enumerate(batch.events):
                try:
                    item = event_adapter.validate_python(raw)
                except (ValidationError, ValueError):
                    rejected.append({"index": index, "code": "invalid_event"})
                    continue
                payload = item.model_dump(mode="json")
                try:
                    with db.begin_nested():
                        db.add(Event(source=item.source, external_id=item.event_id, event_time=item.event_time.isoformat(), received_at=utcnow(), event_type=item.event_type, outcome=item.outcome if isinstance(item, AuthEvent) else item.source.removeprefix("demo-"), service=item.service, payload=json.dumps(payload)))
                        db.flush()
                    accepted.append(item.event_id)
                except IntegrityError:
                    old = db.scalar(select(Event).where(Event.source == item.source, Event.external_id == item.event_id))
                    if old is None:
                        raise
                    if json.loads(old.payload) != payload:
                        rejected.append({"index": index, "code": "event_id_conflict"})
                    else:
                        duplicates.append(item.event_id)
        return {"batch_id": batch.batch_id, "accepted": accepted, "duplicates": duplicates, "rejected": rejected}

    @app.post("/collectors/heartbeat", dependencies=[Depends(collector_auth)])
    def heartbeat(data: Heartbeat):
        with sessions.begin() as db:
            row = db.get(CollectorStatus, data.source)
            if row is None:
                row = CollectorStatus(source=data.source)
                db.add(row)
            row.last_seen_at, row.pending, row.quarantined = utcnow(), data.pending, data.quarantined
        return {"status": "ok"}

    return app
