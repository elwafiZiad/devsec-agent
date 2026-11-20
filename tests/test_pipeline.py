import copy
import json
from pathlib import Path
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func
from devsec.api import create_app
from devsec.collector import Collector
from devsec.config import password_hash
from devsec.database import Event
from devsec.demo import create_demo


@pytest.fixture
def config(tmp_path):
    salt = 'ab' * 16
    return {"database_url": "sqlite:///" + (tmp_path/'events.db').as_posix(), "admin_username":"admin", "password_salt":salt,
            "password_hash":password_hash('test-password',salt), "collector_token":"test-collector-key", "pseudonym_key":"cd"*32,
            "api_url":"http://testserver", "demo_url":"http://testserver", "log_file":str(tmp_path/'demo.jsonl'), "collector_db":str(tmp_path/'spool.db')}


def sample(event_id='e-1'):
    return {"schema_version":"1.0", "event_id":event_id, "source":"demo-auth", "event_type":"auth.failure",
            "event_time":"2026-11-13T10:00:00Z", "service":"demo-app", "environment":"lab", "source_ip":"127.0.0.1",
            "user_id":"usr-"+'a'*24, "session_id":None, "request_id":"r-1", "outcome":"failure", "synthetic":True,
            "raw_redacted":"authentication failed"}


def login(client):
    return client.post('/login',headers={'Origin':'http://testserver'},data={'username':'admin','password':'test-password'})


def send(client,config,items):
    return client.post('/events/batch',headers={'Authorization':'Bearer '+config['collector_token']},json={'batch_id':'batch-1','events':items})


def test_full_demo_collector_database_interface(config):
    app=create_app(config)
    api=TestClient(app)
    demo=TestClient(create_demo(config), client=("127.0.0.1", 50000))
    result=demo.post('/auth/login',headers={'Origin':'http://testserver'},json={'username':'etudiant','password':'SECRET-WRONG-PASSWORD'})
    assert result.status_code==200 and result.json()['success'] is False
    raw=Path(config['log_file']).read_text()
    assert 'SECRET-WRONG-PASSWORD' not in raw and 'etudiant' not in raw
    collector=Collector(config,api)
    collector.tick()
    assert login(api).status_code==200
    rows=api.get('/events').json()['items']
    assert len(rows)==2
    access, auth = rows
    assert auth['event_id']==result.json()['event_id']
    assert access['request_id']==auth['request_id']
    assert (access['method'],access['path'],access['status_code'])==('POST','/auth/login',200)
    assert api.get('/stats').json()['successes']==0
    assert 'SECRET-WRONG-PASSWORD' not in json.dumps(rows)
    assert api.get('/').status_code==200
    assert api.get('/stats').json()['collector']['pending']==0
    collector.close()


def test_duplicate_and_identity_conflict(config):
    client=TestClient(create_app(config))
    assert send(client,config,[sample()]).json()['accepted']==['e-1']
    assert send(client,config,[sample()]).json()['duplicates']==['e-1']
    changed=sample();changed['request_id']='other'
    assert send(client,config,[changed]).json()['rejected'][0]['code']=='event_id_conflict'
    login(client)
    assert client.get('/stats').json()['total']==1


def test_partial_rejection_and_no_sensitive_echo(config):
    client=TestClient(create_app(config))
    invalid=sample('bad');invalid['password']='do-not-echo'
    response=send(client,config,[sample(),invalid])
    assert response.status_code==202 and response.json()['accepted']==['e-1']
    assert response.json()['rejected']==[{'index':1,'code':'invalid_event'}]
    assert 'do-not-echo' not in response.text


def test_authentication_origin_and_logout(config):
    client=TestClient(create_app(config))
    assert client.get('/events').status_code==401
    assert client.get('/stats').status_code==401
    assert client.get('/',follow_redirects=False).headers['location']=='/login'
    assert client.post('/events/batch',json={'batch_id':'b','events':[sample()]}).status_code==401
    assert client.post('/login',data={'username':'admin','password':'test-password'}).status_code==403
    assert login(client).status_code==200
    assert client.get('/events').status_code==200
    assert client.post('/logout',headers={'Origin':'http://testserver'}).status_code==200
    assert client.get('/events').status_code==401


def test_login_rate_limit(config):
    client=TestClient(create_app(config))
    for _ in range(10):
        assert client.post('/login',headers={'Origin':'http://testserver'},data={'username':'admin','password':'bad'}).status_code==401
    assert login(client).status_code==429


def test_body_size_limit(config):
    client=TestClient(create_app(config))
    assert client.post('/events/batch',content=b'x'*1_048_577).status_code==413


def test_restart_and_partial_line(config):
    path=Path(config['log_file'])
    encoded=json.dumps(sample())
    path.write_text(encoded[:40])
    collector=Collector(config,TestClient(create_app(config)))
    collector.tick()
    assert collector.counts()['pending']==0
    collector.close()
    with path.open('a') as out:out.write(encoded[40:]+'\n')
    client=TestClient(create_app(config));collector=Collector(config,client)
    collector.tick();collector.close()
    client=TestClient(create_app(config));collector=Collector(config,client)
    collector.tick();login(client)
    assert client.get('/stats').json()['total']==1
    collector.close()


def test_api_down_then_resume(config):
    Path(config['log_file']).write_text(json.dumps(sample())+'\n')
    def fail(request):raise httpx.ConnectError('offline')
    collector=Collector(config,httpx.Client(transport=httpx.MockTransport(fail),base_url='http://testserver'))
    with pytest.raises(httpx.ConnectError):collector.tick()
    assert collector.counts()['pending']==1
    collector.close()
    client=TestClient(create_app(config));collector=Collector(config,client)
    collector.tick();login(client)
    assert client.get('/stats').json()['total']==1 and collector.counts()['pending']==0
    collector.close()


def test_lost_ack_deduplicates(config):
    Path(config['log_file']).write_text(json.dumps(sample())+'\n')
    client=TestClient(create_app(config))
    class LostAck:
        def post(self,*args,**kwargs):
            client.post(*args,**kwargs)
            raise httpx.ReadTimeout('ack lost')
        def close(self):pass
    collector=Collector(config,LostAck())
    with pytest.raises(httpx.ReadTimeout):collector.tick()
    collector.close()
    collector=Collector(config,client);collector.tick();login(client)
    assert client.get('/stats').json()['total']==1 and collector.counts()['pending']==0
    collector.close()


def test_rotation_invalid_line_and_oversize(config):
    path=Path(config['log_file']);path.write_text(json.dumps(sample())+'\n'+'invalid SECRET\n'+'x'*70000+'\n')
    client=TestClient(create_app(config));collector=Collector(config,client)
    collector.tick();collector.close()
    path.rename(str(path)+'.1');path.write_text(json.dumps(sample('e-2'))+'\n')
    client=TestClient(create_app(config));collector=Collector(config,client)
    collector.tick();login(client)
    assert client.get('/stats').json()['total']==2
    assert collector.counts()['quarantined']==2
    assert 'SECRET' not in str(collector.db.execute('SELECT * FROM quarantine').fetchall())
    collector.close()


def test_filters_and_keyset_pagination(config):
    client=TestClient(create_app(config))
    send(client,config,[sample(f'e-{i}') for i in range(55)])
    success=sample('success');success.update(event_type='auth.success',outcome='success',raw_redacted='authentication succeeded')
    send(client,config,[success]);login(client)
    first=client.get('/events').json()
    second=client.get('/events',params={'before':first['next_cursor']}).json()
    assert len(first['items'])==50 and len(second['items'])==6
    assert len({r['event_id'] for r in first['items']+second['items']})==56
    assert len(client.get('/events?event_type=auth.success').json()['items'])==1


def test_naive_timestamp_and_mismatched_outcome_rejected(config):
    client=TestClient(create_app(config))
    naive=sample('naive');naive['event_time']='2026-11-13T10:00:00'
    mismatch=sample('mismatch');mismatch['outcome']='success'
    assert len(send(client,config,[naive,mismatch]).json()['rejected'])==2


def test_unicode_credentials_are_rejected_cleanly(config):
    client=TestClient(create_app(config))
    assert client.post('/login',headers={'Origin':'http://testserver'},data={'username':'étudiant','password':'étrange'}).status_code==401
    demo=TestClient(create_demo(config),client=('127.0.0.1',50000))
    result=demo.post('/auth/login',headers={'Origin':'http://testserver'},json={'username':'étudiant','password':'étrange'})
    assert result.status_code==200 and result.json()['success'] is False

def test_access_history_per_ip(config):
    demo = create_demo(config)
    visitor = TestClient(demo, client=("192.0.2.10", 50000))
    other = TestClient(demo, client=("192.0.2.11", 50001))
    assert visitor.get("/").status_code == 200
    assert visitor.get("/absente?token=SECRET").status_code == 404
    assert other.get("/health").status_code == 200
    assert "SECRET" not in Path(config["log_file"]).read_text()
    api = TestClient(create_app(config))
    collector = Collector(config, api)
    collector.tick()
    login(api)
    response = api.get("/events", params={"source_ip": "192.0.2.10", "event_type": "http.access"})
    rows = response.json()["items"]
    assert [(r["path"], r["status_code"]) for r in rows] == [("/absente", 404), ("/", 200)]
    assert api.get("/events?source_ip=incorrect").status_code == 422
    assert api.get("/stats").json()["total"] == 3
    collector.close()
