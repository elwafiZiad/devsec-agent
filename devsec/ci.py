"""Import failed GitHub Actions attempts for this repository, using read-only requests."""
import logging
import os
import re
import subprocess
import time

import httpx
from sqlalchemy.exc import IntegrityError

from .config import ROOT, settings
from .database import CIIncident, database

REPO = "elwafiZiad/devsec-agent"
API = f"https://api.github.com/repos/{REPO}"
TEST_FAILURE = re.compile(r"\b(FAILED|ERROR) (tests/[\w./-]+\.py::[\w:.-]+)")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def credentials():
    token = os.environ.get("DEVSEC_GITHUB_TOKEN")
    if not token:
        # Reuse the local Git login for this repository without opening prompts.
        result = subprocess.run(
            ["git", "credential", "fill"], cwd=ROOT, capture_output=True, text=True,
            input=f"protocol=https\nhost=github.com\npath={REPO}.git\n\n", timeout=10,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"},
        )
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        token = fields.get("password")
    return {"Authorization": f"Bearer {token}"} if token else {}


def extract_evidence(log):
    # Retain only the pytest result and numeric assertion, never the full raw log.
    for n, line in enumerate(ANSI.sub("", log).splitlines(), start=1):
        match = TEST_FAILURE.search(line)
        if match:
            excerpt = f"Ligne {n} · {match[0]}"
            assertion = re.search(r"\bassert (-?\d+) == (-?\d+)(?:\s|$)", line[match.end():])
            if assertion:
                excerpt += f" · {assertion[0].strip()}"
            return match[2], excerpt
    return "", ""


def get_json(client, path, headers, **params):
    response = client.get(API + path, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def synchronize(client, sessions, headers):
    runs = get_json(client, "/actions/workflows/tests.yml/runs", headers, status="failure", per_page=30)
    for run in runs["workflow_runs"]:
        run_id, attempt = int(run["id"]), int(run["run_attempt"])
        with sessions() as db:
            if db.get(CIIncident, (run_id, attempt)):
                continue
        jobs = get_json(client, f"/actions/runs/{run_id}/attempts/{attempt}/jobs", headers)
        job = next((job for job in jobs["jobs"] if job["conclusion"] == "failure"), None)
        if not job:
            continue
        step = next((s["name"] for s in job["steps"] if s["conclusion"] == "failure"), job["name"])
        response = client.get(API + f"/actions/jobs/{int(job['id'])}/logs", headers=headers)
        if response.is_redirect:
            # Signed download URL. No GitHub credentials go to the storage host.
            response = client.get(response.headers["location"], follow_redirects=True)
        if response.status_code in (404, 410):
            test, proof = "", "Journal indisponible sur GitHub."
        else:
            response.raise_for_status()
            test, proof = extract_evidence(response.text)
        incident = CIIncident(run_id=run_id, attempt=attempt, repo=REPO, branch=run["head_branch"] or "",
                              sha=run["head_sha"], job=job["name"], step=step, test=test,
                              evidence=proof or f"Étape en échec : {step}", updated=run["updated_at"])
        with sessions.begin() as db:
            try:
                with db.begin_nested():
                    db.add(incident)
                    db.flush()
            except IntegrityError:
                if db.get(CIIncident, (run_id, attempt)) is None:
                    raise


def main():
    engine, sessions = database(settings()["database_url"])
    try:
        with httpx.Client(timeout=25) as client:
            while True:
                try:
                    synchronize(client, sessions, credentials())
                except httpx.HTTPStatusError as exc:
                    logging.warning("Import CI indisponible (HTTP %s)", exc.response.status_code)
                except Exception as exc:
                    logging.warning("Import CI interrompu (%s)", type(exc).__name__)
                time.sleep(60)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
