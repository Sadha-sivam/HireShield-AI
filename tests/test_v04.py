from fastapi.testclient import TestClient
import backend.main as m

def setup_client(tmp_path,monkeypatch):
    monkeypatch.setattr(m,'DB',tmp_path/'v04.db')
    monkeypatch.setenv('HIRESHIELD_ADMIN_PASSWORD','correct-horse-123')
    c=TestClient(m.app)
    login=c.post('/api/login',json={'username':'admin','password':'correct-horse-123'})
    assert login.status_code==200
    c.headers.update({'Authorization':'Bearer '+login.json()['token']})
    return c

def test_auth_required(tmp_path,monkeypatch):
    c=setup_client(tmp_path,monkeypatch)
    c.headers.pop('Authorization',None)
    assert c.get('/api/cases').status_code==401
    assert c.post('/api/url',content='http://example.invalid').status_code==401

def test_login_rejects_bad_password(tmp_path,monkeypatch):
    c=setup_client(tmp_path,monkeypatch)
    assert c.post('/api/login',json={'username':'admin','password':'bad'}).status_code==401

def test_case_create_and_attach_investigation(tmp_path,monkeypatch):
    c=setup_client(tmp_path,monkeypatch)
    inv=c.post('/api/url',content='https://example.invalid/a').json()['investigation_id']
    case=c.post('/api/cases',json={'title':'Suspicious link review','description':'triage'}); assert case.status_code==200
    cid=case.json()['id']
    assert c.post(f'/api/cases/{cid}/investigations/{inv}').status_code==200
    result=c.get(f'/api/cases/{cid}').json()
    assert len(result['investigations'])==1 and result['investigations'][0]['id']==inv

def test_alert_correlation_and_audit(tmp_path,monkeypatch):
    c=setup_client(tmp_path,monkeypatch)
    c.post('/api/url',content='http://example.invalid/login')
    c.post('/api/url',content='http://example.invalid/verify')
    groups=c.post('/api/alerts/correlate').json()['groups']
    assert any(g['count']>=2 for g in groups)
    audit=c.get('/api/audit').json()
    assert any(x['action']=='correlate' for x in audit)
    assert any(x['action']=='create' and x['object_type']=='investigation' for x in audit)

def test_case_status_validation_and_logout(tmp_path,monkeypatch):
    c=setup_client(tmp_path,monkeypatch)
    cid=c.post('/api/cases',json={'title':'Case'}).json()['id']
    assert c.patch(f'/api/cases/{cid}',json={'status':'bad'}).status_code==400
    assert c.post('/api/logout').status_code==200
    assert c.get('/api/cases').status_code==401
