from datetime import datetime, timedelta, timezone
from typing import Literal
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
import uuid
from fastapi import FastAPI, Request, HTTPException
from starlette.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from .config import settings
from .database import utcnow


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


def create_demo(config=None):
    config = config or settings()
    app = FastAPI(title="Application de laboratoire", docs_url=None, redoc_url=None)
    lock = threading.Lock()
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    def write_event(event):
        path = Path(config["log_file"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with lock, path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        started = utcnow()
        request.state.request_id = str(uuid.uuid4())
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            path = request.scope["raw_path"].split(b"?", 1)[0].decode("ascii")
            await run_in_threadpool(write_event, {
                "schema_version": "1.0", "event_type": "http.access", "source": "demo-http",
                "event_id": str(uuid.uuid4()), "request_id": request.state.request_id,
                "event_time": started, "service": "demo-app", "environment": "lab",
                "source_ip": request.client.host, "method": request.method,
                "path": path, "status_code": status, "synthetic": True,
            })

    @app.get("/")
    def home(request: Request):
        return templates.TemplateResponse(request=request, name="demo.html", context={"agent_url": config["api_url"]})

    @app.get("/health")
    def health():
        return {"status": "ok", "component": "demo-app"}

    @app.post("/auth/login")
    def login(data: Credentials, request: Request):
        if request.headers.get("origin") != config["demo_url"]:
            raise HTTPException(403, "Origine non autorisée")
        success = hmac.compare_digest(data.username.encode(), b"etudiant") and hmac.compare_digest(data.password.encode(), b"demo-lab")
        event_id = str(uuid.uuid4())
        event = {"schema_version": "1.0", "event_id": event_id, "source": "demo-auth", "event_type": "auth.success" if success else "auth.failure",
                 "event_time": utcnow(), "service": "demo-app", "environment": "lab", "source_ip": request.client.host,
                 "user_id": "usr-" + hmac.new(bytes.fromhex(config["pseudonym_key"]), data.username.encode(), hashlib.sha256).hexdigest()[:24],
                 "session_id": None, "request_id": request.state.request_id, "outcome": "success" if success else "failure", "synthetic": True,
                 "raw_redacted": "authentication succeeded" if success else "authentication failed"}
        write_event(event)
        # This is a deliberate login simulator, not a session for protected resources.
        return {"success": success, "event_id": event_id, "message": "Connexion de test acceptée." if success else "Connexion de test refusée."}

    @app.post("/simulation/privileges")
    def simulate_privileges(request: Request, scenario: Literal["authorized", "outside", "denied"] = "outside"):
        if request.headers.get("origin") != config["demo_url"]:
            raise HTTPException(403, "Origine non autorisée")
        # A fresh fictional account keeps independent classroom exercises separate.
        user = "usr-" + uuid.uuid4().hex[:24]
        common = {"schema_version": "1.0", "source": "demo-audit", "service": "demo-app",
                  "environment": "lab", "user_id": user, "synthetic": True,
                  "source_ip": request.client.host, "request_id": request.state.request_id}
        start = datetime.now(timezone.utc)
        principal = hmac.new(bytes.fromhex(config["pseudonym_key"]), b"lab-supervisor", hashlib.sha256)
        write_event({**common, "event_id": str(uuid.uuid4()), "event_time": start.isoformat(),
                     "event_type": "audit.task_granted", "granted_by": "usr-" + principal.hexdigest()[:24],
                     "operation": "service.restart", "resource": "demo-worker",
                     "expires_at": (start + timedelta(hours=1)).isoformat()})
        def record_action(operation, result):
            write_event({**common, "event_id": str(uuid.uuid4()), "event_time": utcnow(),
                         "event_type": "audit.task_action", "operation": operation,
                         "resource": "demo-worker", "result": result})

        record_action("service.restart", "executed")
        if scenario != "authorized":
            record_action("settings.update", "denied" if scenario == "denied" else "executed")
        return {"user_id": user}

    return app
