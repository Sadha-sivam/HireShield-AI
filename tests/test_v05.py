from fastapi.testclient import TestClient
import backend.main as m

def client(tmp_path, monkeypatch):
    monkeypatch.setattr(m,'DB',tmp_path/'v05.db')
    monkeypatch.setenv('HIRESHIELD_ADMIN_PASSWORD','admin-password-123')
    c=TestClient(m.app)
    token=c.post('/api/login',json={'username':'admin','password':'admin-password-123'}).json()['token']
    c.headers.update({'Authorization':'Bearer '+token})
    return c

def test_admin_creates_analyst_and_role(tmp_path,monkeypatch):
    c=client(tmp_path,monkeypatch)
    r=c.post('/api/users',json={'username':'analyst1','password':'analyst-password-123','role':'analyst'})
    assert r.status_code==200
    assert any(u['username']=='analyst1' and u['role']=='analyst' for u in c.get('/api/users').json())
    assert c.post('/api/users',json={'username':'weak','password':'short','role':'analyst'}).status_code==400

def test_non_admin_cannot_create_users(tmp_path,monkeypatch):
    c=client(tmp_path,monkeypatch)
    c.post('/api/users',json={'username':'analyst1','password':'analyst-password-123','role':'analyst'})
    login=c.post('/api/login',json={'username':'analyst1','password':'analyst-password-123'}).json()['token']
    a=TestClient(m.app); a.headers.update({'Authorization':'Bearer '+login})
    assert a.post('/api/users',json={'username':'x','password':'long-password-123','role':'analyst'}).status_code==403

def test_assignment_case_timeline_and_metrics(tmp_path,monkeypatch):
    c=client(tmp_path,monkeypatch)
    c.post('/api/users',json={'username':'analyst1','password':'analyst-password-123','role':'analyst'})
    case=c.post('/api/cases',json={'title':'Assigned case','assigned_to':'analyst1'}).json()
    inv=c.post('/api/url',content='https://example.invalid/one').json()['investigation_id']
    assert c.post(f"/api/cases/{case['id']}/investigations/{inv}").status_code==200
    detail=c.get('/api/cases/'+case['id']).json()
    assert detail['assigned_to']=='analyst1'
    assert any(e['event']=='Investigation linked' for e in detail['timeline'])
    assert c.get('/api/metrics').json()['open_cases']==1

def test_alert_filters_and_correlation_details(tmp_path,monkeypatch):
    c=client(tmp_path,monkeypatch)
    c.post('/api/url',content='https://example.invalid/a')
    c.post('/api/url',content='https://example.invalid/b')
    assert len(c.get('/api/alerts?q=example.invalid').json())==2
    groups=c.post('/api/alerts/correlate').json()['groups']
    assert groups and groups[0]['grouping_basis']
    assert groups[0]['severity_counts']
