import json
from hireshield.ai import explain
from hireshield.report_pdf import make_pdf

def test_ollama_graceful_unavailable(monkeypatch):
    def fail(*a,**k): raise OSError('offline')
    monkeypatch.setattr('urllib.request.urlopen',fail)
    r=explain({'findings':[{'title':'test','severity':'low'}]},timeout=0.1)
    assert r['status']=='unavailable' and r['advisory_only'] is True

def test_pdf_report_generated():
    result={'investigation_id':'demo','created':'now','kind':'url','reference':'https://example.invalid','risk':{'score':0,'severity':'low'},'findings':[],'analyst_notes':'test'}
    b=make_pdf(result,[{'created':'now','event':'created','details':'unit test'}])
    assert b.startswith(b'%PDF') and len(b)>500

def test_pdf_report_escapes_markup():
    result={'investigation_id':'<unsafe>','findings':[{'title':'<script>','evidence':'&','severity':'low'}]}
    b=make_pdf(result); assert b.startswith(b'%PDF')
def test_api_investigation_timeline_and_pdf(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import backend.main as m
    monkeypatch.setattr(m,'DB',tmp_path/'test.db')
    client=TestClient(m.app)
    monkeypatch.setenv('HIRESHIELD_ADMIN_PASSWORD','test-password-123')
    auth=client.post('/api/login',json={'username':'admin','password':'test-password-123'}); assert auth.status_code==200
    client.headers.update({'Authorization':'Bearer '+auth.json()['token']})
    r=client.post('/api/url',content='http://127.0.0.1/login')
    assert r.status_code==200
    inv=r.json()['investigation_id']
    t=client.get(f'/api/investigations/{inv}/timeline'); assert t.status_code==200 and len(t.json())>=1
    pdf=client.get(f'/api/report/{inv}/pdf'); assert pdf.status_code==200 and pdf.content.startswith(b'%PDF')
    upd=client.patch(f'/api/investigations/{inv}',json={'status':'reviewing','notes':'note'}); assert upd.status_code==200
    assert len(client.get(f'/api/investigations/{inv}/timeline').json())>=2
