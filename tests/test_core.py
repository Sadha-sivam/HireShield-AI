from hireshield.core import analyze_url, analyze_email, score, inspect_file

def test_ip_url():
 r=analyze_url('http://192.0.2.1/login'); assert any('IP address' in f['title'] for f in r['findings'])
def test_url_not_fetch():
 r=analyze_url('https://example.invalid'); assert 'fetched' in r['note']
def test_email_mismatch():
 raw=b'From: a@example.com\nReply-To: b@evil.invalid\nSubject: urgent verify\n\nhttp://192.0.2.1\n'
 r=analyze_email(raw); assert r['urls'] and any('mismatch' in f['title'].lower() for f in r['findings'])
def test_score(): assert score([{'severity':'high'}])['score']==50  # a single high finding is floored to the 'high' band
def test_file_signature(): assert any('signature' in f['title'].lower() for f in inspect_file('x.pdf',b'wrong')['findings'])
def test_file_sha(): assert len(inspect_file('x.txt',b'abc')['sha256'])==64
