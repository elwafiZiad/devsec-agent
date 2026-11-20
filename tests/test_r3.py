from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from devsec.demo import create_demo
from devsec.rules import evaluate
from devsec.schemas import MaintenanceWindow
from test_pipeline import config, send
from test_r1 import setup


@pytest.mark.parametrize("case", ["suspect", "autre compte", "maintenance", "maintenance partielle",
                                  "ordre inverse", "expiré", "rôle révoqué", "IP différente", "limite"])
def test_privilege_sequence(config, case):
    app, client = setup(config)
    # Persisted audit v1 events retain their original interpretation.
    common = dict(schema_version="1.0", source="demo-audit", service="demo-app", environment="lab",
                  synthetic=True, source_ip="127.0.0.1", user_id="usr-"+"b"*24, request_id="legacy")
    role = dict(common, event_id="role", event_type="audit.role_change", old_role="user", new_role="admin")
    action = dict(common, event_id="action", event_type="audit.sensitive_action", role="admin", operation="settings.update")
    start = datetime(2026, 11, 19, tzinfo=timezone.utc)
    end = start + timedelta(minutes=2)
    periods = []
    extra = []
    if case == "autre compte":
        action["user_id"] = "usr-" + "a" * 24
    elif case.startswith("maintenance"):
        periods.append(MaintenanceWindow(service="demo-app", environment="lab", user_id=role["user_id"],
                       start=start, end=end + timedelta(seconds=1) if case == "maintenance" else end))
    elif case == "ordre inverse":
        end = start - timedelta(seconds=1)
    elif case == "expiré":
        end = start + timedelta(minutes=15, seconds=1)
    elif case == "limite":
        end = start + timedelta(minutes=15)
    elif case == "rôle révoqué":
        extra.append(dict(role, event_id="demotion", event_time=(start + timedelta(seconds=1)).isoformat(),
                          old_role="admin", new_role="user"))
    elif case == "IP différente":
        action["source_ip"] = "192.0.2.5"
    role["event_time"], action["event_time"] = start.isoformat(), end.isoformat()
    assert not send(client, config, [action]).json()["rejected"]
    assert evaluate(app.state.sessions, periods) == 0
    assert not send(client, config, [role] + extra).json()["rejected"]
    expected = int(case in {"suspect", "maintenance partielle", "IP différente", "limite"})
    assert evaluate(app.state.sessions, periods) == expected
    if expected:
        item = client.get("/incidents").json()["items"][0]
        detail = client.get(f"/incidents/{item['id']}").json()
        assert detail["rule"] == "R3"
        assert [e["event_id"] for e in detail["evidence"]] == [role["event_id"], action["event_id"]]
        assert evaluate(app.state.sessions, periods) == 1
        assert client.get("/incidents").json()["items"] == [item]

@pytest.mark.parametrize("case,count", [("authorized",0), ("outside",1), ("denied",0), ("expired",1),
                                       ("wrong resource",1), ("late authorized",0), ("late outside",1),
                                       ("missing grant",1), ("different account",1)])
def test_task_scope(config, case, count):
    app, client = setup(config)
    demo = TestClient(create_demo(config), client=("127.0.0.1", 51000))
    scenario = case if case in {"authorized", "outside", "denied"} else "authorized"
    response = demo.post("/simulation/privileges", params={"scenario":scenario}, headers={"Origin":config["demo_url"]})
    assert response.status_code == 200
    data = [json.loads(line) for line in Path(config["log_file"]).read_text().splitlines()][:-1]
    grant, action = data[:2]
    if case == "expired":
        action["event_time"] = grant["expires_at"]
    if case == "wrong resource":
        action["resource"] = "demo-api"
    if case.startswith("late"):
        action["event_time"] = (datetime.fromisoformat(grant["event_time"])+timedelta(minutes=45)).isoformat()
        if case == "late outside":
            action["operation"] = "settings.update"
    if case == "different account":
        action["user_id"] = "usr-"+"a"*24
    if case == "missing grant":
        data = [action]
    assert not send(client, config, list(reversed(data))).json()["rejected"]
    assert evaluate(app.state.sessions) == count
    assert evaluate(app.state.sessions) == count
    if count:
        incident = client.get("/incidents").json()["items"][0]
        detail = client.get(f"/incidents/{incident['id']}").json()
        assert detail["title"] == "Action exécutée hors autorisation"
        assert detail["evidence"][-1]["event_id"] == data[-1]["event_id"]
