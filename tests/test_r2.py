from datetime import datetime, timedelta, timezone

import pytest

from devsec.rules import evaluate, normalized_route
from test_pipeline import config, send
from test_r1 import events, setup


def accesses():
    start = datetime(2026, 11, 19, tzinfo=timezone.utc)
    return [
        {"schema_version": "1.0", "source": "demo-http", "event_type": "http.access",
         "event_id": f"http-{i}", "request_id": f"r-{i}", "service": "demo-app",
         "environment": "lab", "source_ip": "192.0.2.45", "method": "GET",
         "event_time": (start + timedelta(seconds=60 if i == 19 else i)).isoformat(),
         "path": f"/page-{i}", "status_code": (403 if i % 2 else 404) if i < 10 else 200,
         "synthetic": True}
        for i in range(20)
    ]


def test_r2_with_r1_and_late_delivery(config):
    app, client = setup(config)
    data = accesses()
    send(client, config, events(range(5)))
    send(client, config, data[1:])
    assert evaluate(app.state.sessions) == 1
    send(client, config, data[:1])
    assert evaluate(app.state.sessions) == 2
    incidents = client.get("/incidents").json()["items"]
    incident = next(row for row in incidents if row["rule"] == "R2")
    detail = client.get(f"/incidents/{incident['id']}").json()
    assert detail["peak_count"] == 20 and detail["title"] == "Scan HTTP possible"
    assert [e["event_id"] for e in detail["evidence"]] == [e["event_id"] for e in data]
    send(client, config, data)
    assert evaluate(app.state.sessions) == 2
    assert client.get("/incidents").json()["items"] == incidents


@pytest.mark.parametrize("case", ["19 routes", "moins de 50 %", "61 secondes", "autre IP", "acces repete", "identifiants"])
def test_no_r2(config, case):
    app, client = setup(config)
    data = accesses()
    if case == "19 routes":
        data[-1]["path"] = data[0]["path"]
    elif case == "moins de 50 %":
        data[0]["status_code"] = 500
    elif case == "61 secondes":
        data[-1]["event_time"] = "2026-11-19T00:01:01+00:00"
    elif case == "autre IP":
        data[-1]["source_ip"] = "192.0.2.46"
    elif case == "acces repete":
        data.append(dict(data[-1], event_id="extra"))
    else:
        for i, event in enumerate(data):
            event["path"] = f"/produit/{i}/"
    assert not send(client, config, data).json()["rejected"]
    assert evaluate(app.state.sessions) == 0


def test_route_id_normalization():
    assert normalized_route("/produit/%31/") == normalized_route("/produit/123")
    assert normalized_route("/x/df53eb44-5832-48d7-917c-621d46349bb3") == normalized_route("/x/1")
