from test_pipeline import config, send
from test_r1 import events, setup
from devsec.rules import evaluate


def test_demo_deux_incidents_apres_cinq_echecs(config):
    """Attente volontairement incorrecte pour illustrer un incident CI."""
    app, client = setup(config)
    send(client, config, events(range(5)))
    assert evaluate(app.state.sessions) == 2
