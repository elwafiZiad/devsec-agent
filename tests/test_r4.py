from pathlib import Path
import json

import pytest
from fastapi.testclient import TestClient

from devsec.demo import create_demo
from devsec.rules import evaluate
from devsec.schedules import Schedules, account_id
from test_pipeline import config, sample, send
from test_r1 import setup


@pytest.mark.parametrize("user,stamp,status", [
    ("etudiant", "2026-11-17T09:00:00Z", "Dans le créneau"),
    ("etudiant", "2026-11-17T17:00:00Z", "Hors planning"),
    ("etudiant", "2026-11-21T12:00:00Z", "Hors planning"),
    ("technicien", "2026-11-17T22:00:00Z", "Dans le créneau"),
    ("technicien", "2026-11-18T06:59:00+01:00", "Dans le créneau"),
    ("technicien", "2026-11-18T06:00:00Z", "Hors planning"),
    ("technicien", "2026-11-17T02:00:00Z", "Hors planning"),
    ("stagiaire", "2026-11-17T08:30:00Z", "Dans le créneau"),
    ("visiteur", "2026-11-17T23:00:00Z", "Horaire inconnu"),
])
def test_slots(config, user, stamp, status):
    event = dict(sample(), user_id=account_id(config, user), event_time=stamp)
    assert Schedules(config).assess(event)["status"] == status


def test_four_accounts_same_hour(config):
    app, client = setup(config)
    demo = TestClient(create_demo(config), client=("127.0.0.1", 51000))
    for account in ("etudiant", "technicien", "stagiaire", "visiteur"):
        assert demo.post("/simulation/horaire", params={"account": account},
                         headers={"Origin": config["demo_url"]}).status_code == 200
    data = [json.loads(line) for line in Path(config["log_file"]).read_text().splitlines()]
    assert not send(client, config, data).json()["rejected"]
    schedules = Schedules(config)
    for _ in range(2):
        assert evaluate(app.state.sessions, schedules=schedules) == 2
    incidents = client.get("/incidents").json()["items"]
    assert {i["user_id"] for i in incidents} == {account_id(config,u) for u in ("etudiant","stagiaire")}
    for incident in incidents:
        assert incident["rule"] == "R4" and incident["severity"] == "low"
        detail = client.get(f"/incidents/{incident['id']}").json()
        assert detail["evidence"][0]["schedule"]["status"] == "Hors planning"
