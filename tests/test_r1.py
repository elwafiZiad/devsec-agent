from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from test_pipeline import config, sample, send, login
from devsec.api import create_app
from devsec.rules import evaluate, episodes
from devsec.database import Event
from sqlalchemy import select
import json


def events(times, prefix='e', user='a', ip='127.0.0.1'):
    start=datetime(2026,11,13,12,tzinfo=timezone.utc)
    output=[]
    for index, seconds in enumerate(times):
        item=sample(f'{prefix}-{index}')
        item.update(event_time=(start+timedelta(seconds=seconds)).isoformat(),user_id='usr-'+user*24,source_ip=ip)
        output.append(item)
    return output


def setup(config):
    app=create_app(config);client=TestClient(app);login(client)
    return app,client


def test_threshold_and_evidence(config):
    app,client=setup(config);data=events([0,10,20,30,40,50])
    send(client,config,data[:4]);assert evaluate(app.state.sessions)==0
    send(client,config,data[4:5]);assert evaluate(app.state.sessions)==1
    row=client.get('/incidents').json()['items'][0]
    detail=client.get(f"/incidents/{row['id']}").json()
    assert len(detail['evidence'])==5 and detail['severity']=='medium'
    send(client,config,data);evaluate(app.state.sessions)
    rows=client.get('/incidents').json()['items']
    assert len(rows)==1 and rows[0]['id']==row['id'] and rows[0]['peak_count']==6
    assert len(client.get(f"/incidents/{row['id']}").json()['evidence'])==6


def test_inclusive_boundary_and_outside_window(config):
    app,client=setup(config)
    send(client,config,events([0,60,120,180,300],user='a'))
    send(client,config,events([0,60,120,180,301],prefix='outside',user='b'))
    assert evaluate(app.state.sessions)==1
    assert client.get('/incidents').json()['items'][0]['user_id']=='usr-'+'a'*24


def test_distinct_accounts_ips_and_success(config):
    app,client=setup(config)
    for i in range(5):send(client,config,events([i],prefix=str(i),user=hex(i)[2:],ip=f'127.0.0.{i+1}'))
    good=events([1,2,3,4,5],prefix='success')
    for item in good:item.update(event_type='auth.success',outcome='success',raw_redacted='authentication succeeded')
    send(client,config,good);assert evaluate(app.state.sessions)==0
    send(client,config,events([1,2,3,4],prefix='a',user='a',ip='127.0.0.8'))
    send(client,config,events([5],prefix='b',user='a',ip='127.0.0.9'))
    assert evaluate(app.state.sessions)==0


def test_out_of_order_and_restart(config):
    app,client=setup(config);data=events([0,20,40,60,80])
    send(client,config,list(reversed(data[1:])));assert evaluate(app.state.sessions)==0
    send(client,config,data[:1]);assert evaluate(app.state.sessions)==1
    identifier=client.get('/incidents').json()['items'][0]['id']
    app2,client2=setup(config);assert evaluate(app2.state.sessions)==1
    assert client2.get('/incidents').json()['items'][0]['id']==identifier


def test_quiet_gap_new_episode_and_late_merge(config):
    app,client=setup(config)
    send(client,config,events([0,10,20,30,40,600,610,620,630,640]));assert evaluate(app.state.sessions)==2
    # A late bridge reduces the silence between episodes to <=5 minutes.
    send(client,config,events([320],prefix='bridge'));assert evaluate(app.state.sessions)==1
    assert len(client.get('/incidents').json()['items'])==1


def test_service_environment_are_part_of_key():
    rows=[]
    for i,item in enumerate(events([0,1,2,3,4])):
        item['environment']='lab' if i<4 else 'other'
        rows.append(Event(id=i+1,service='demo-app',event_time=item['event_time'],payload=json.dumps(item)))
    assert episodes(rows)==[]
    item['environment']='lab';rows[-1].payload=json.dumps(item);rows[-1].service='other-service'
    assert episodes(rows)==[]


def test_incidents_require_auth_and_missing_id(config):
    client=TestClient(create_app(config))
    assert client.get('/incidents').status_code==401
    assert client.get('/incidents/1').status_code==401
    login(client);assert client.get('/incidents/999').status_code==404
