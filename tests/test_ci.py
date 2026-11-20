import httpx
from fastapi.testclient import TestClient

from devsec.api import create_app
from devsec.ci import synchronize
from test_pipeline import config, login


def test_import_failed_attempt_once(config):
    app = create_app(config)
    api = TestClient(app)
    assert api.get("/ci/incidents").status_code == 401
    run = {"id": 44648482329, "run_attempt": 1, "head_branch": "demo-ci",
           "head_sha": "a"*40, "updated_at": "2026-11-20T18:00:00Z"}
    downloads = []

    def respond(request):
        if request.url.path.endswith("/runs"):
            return httpx.Response(200, json={"workflow_runs": [run]})
        if request.url.path.endswith("/jobs"):
            return httpx.Response(200, json={"jobs": [{"id": 5, "name": "tests", "conclusion": "failure",
                                  "steps": [{"name": "pytest", "conclusion": "failure"}]}]})
        if request.url.path.endswith("/logs"):
            return httpx.Response(302, headers={"location": "https://storage.example/log"})
        assert "Authorization" not in request.headers
        downloads.append(True)
        return httpx.Response(200, text="unused\nFAILED tests/test_demo.py::test_one - assert 1 == 2")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        for _ in range(2):
            synchronize(client, app.state.sessions, {"Authorization": "Bearer test"})
    login(api)
    items = api.get("/ci/incidents").json()["items"]
    assert len(items) == len(downloads) == 1
    assert items[0]["test"] == "tests/test_demo.py::test_one"
    assert items[0]["evidence"] == "Ligne 2 · FAILED tests/test_demo.py::test_one · assert 1 == 2"
    assert items[0]["sha"] == run["head_sha"]
