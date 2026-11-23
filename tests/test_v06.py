from fastapi.testclient import TestClient
import backend.main as m

def setup(tmp_path,monkeypatch):
 monkeypatch.setattr(m,'DB',tmp_path/'v06.db'); monkeypatch.setenv('HIRESHIELD_ADMIN_PASSWORD','admin-password-123')
 c=TestClient(m.app); token=c.post('/api/login',json={'username':'admin','password':'admin-password-123'}).json()['token']; c.headers.update({'Authorization':'Bearer '+token}); return c

def test_alert_ack_resolution_and_timeline(tmp_path,monkeypatch):
 c=setup(tmp_path,monkeypatch); c.post('/api/url',content='https://test.invalid/a'); alert=c.get('/api/alerts').json()[0]; aid=alert['id']
 assert c.patch('/api/alerts/'+aid,json={'status':'acknowledged'}).json()['status']=='acknowledged'
 assert c.patch('/api/alerts/'+aid,json={'status':'resolved'}).json()['status']=='resolved'
 assert len(c.get('/api/alerts/'+aid+'/timeline').json())==2
 assert c.patch('/api/alerts/'+aid,json={'status':'bogus'}).status_code==400

def test_case_filters_notifications_security_headers(tmp_path,monkeypatch):
 c=setup(tmp_path,monkeypatch); c.post('/api/cases',json={'title':'Filter target case','priority':'high'})
 assert len(c.get('/api/cases?q=target&priority=high').json())==1
 assert c.get('/api/cases?q=target&priority=low').json()==[]
 assert c.get('/api/notifications').json()
 assert c.get('/api/health').headers.get('x-frame-options')=='DENY'

def test_login_throttle(tmp_path,monkeypatch):
 c=setup(tmp_path,monkeypatch); c.headers.pop('Authorization',None)
 for _ in range(5): assert c.post('/api/login',json={'username':'admin','password':'wrong'}).status_code==401
 assert c.post('/api/login',json={'username':'admin','password':'admin-password-123'}).status_code==429
