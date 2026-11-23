from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from pathlib import Path
from urllib.parse import unquote, urlsplit
import sqlite3, json, datetime, uuid, hashlib, os, secrets, hmac, base64, logging, importlib.util, shutil
from hireshield.core import analyze_email, analyze_url, inspect_file, score, MAX_BYTES
from hireshield.ai import explain
from hireshield.report_pdf import make_pdf

VERSION = '0.6.1'
log = logging.getLogger('hireshield')
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND = BASE_DIR / 'frontend' / 'index.html'
ADMIN_PLACEHOLDER = 'change-this-before-starting'  # value shipped in .env.example; never accepted
MIN_PASSWORD = 12
MAX_FAILED_PER_USER_IP = 5
MAX_FAILED_PER_IP = 50
LOCKOUT_MINUTES = 15

app = FastAPI(title='HireShield AI', version=VERSION)


class SecurityHeaders(BaseHTTPMiddleware):
 async def dispatch(self, request, call_next):
  response = await call_next(request)
  response.headers.update({
   'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
   'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Cache-Control': 'no-store',
   # The single-page console uses inline handlers, so 'unsafe-inline' is required until the JS is externalised.
   'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"})
  return response
app.add_middleware(SecurityHeaders)

DB = Path(os.environ.get('HIRESHIELD_DB', 'hireshield.db'))
_SCHEMA_READY = set()


def _now():
 return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _init_schema(c):
 c.execute('CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY, created TEXT, kind TEXT, reference TEXT, result TEXT, status TEXT, notes TEXT)')
 c.execute('CREATE TABLE IF NOT EXISTS timeline(id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, created TEXT, event TEXT, details TEXT)')
 c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, salt TEXT, password_hash TEXT, created TEXT, role TEXT DEFAULT 'analyst')")
 c.execute('CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, username TEXT, created TEXT, expires TEXT)')
 c.execute('CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, title TEXT, description TEXT, status TEXT, priority TEXT, created TEXT, updated TEXT, owner TEXT)')
 # additive migrations for existing v0.4 databases
 if 'role' not in [x['name'] for x in c.execute('PRAGMA table_info(users)').fetchall()]: c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'analyst'")
 if 'assigned_to' not in [x['name'] for x in c.execute('PRAGMA table_info(cases)').fetchall()]: c.execute('ALTER TABLE cases ADD COLUMN assigned_to TEXT')
 c.execute('CREATE TABLE IF NOT EXISTS case_events(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, created TEXT, username TEXT, event TEXT, details TEXT)')
 c.execute('CREATE TABLE IF NOT EXISTS case_items(case_id TEXT, investigation_id TEXT, added TEXT, PRIMARY KEY(case_id,investigation_id))')
 c.execute('CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, username TEXT, action TEXT, object_type TEXT, object_id TEXT, details TEXT)')
 c.execute('CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, investigation_id TEXT UNIQUE, created TEXT, title TEXT, severity TEXT, status TEXT, correlation_key TEXT)')
 c.execute('CREATE TABLE IF NOT EXISTS alert_events(id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, created TEXT, username TEXT, event TEXT, details TEXT)')
 c.execute('CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY, username TEXT, created TEXT, message TEXT, object_type TEXT, object_id TEXT, read INTEGER DEFAULT 0)')
 c.execute('CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, ip TEXT, created TEXT, success INTEGER)')
 c.execute('CREATE INDEX IF NOT EXISTS ix_login_attempts ON login_attempts(ip, username, created)')
 c.execute('CREATE INDEX IF NOT EXISTS ix_alerts_key ON alerts(correlation_key, status)')
 c.execute('CREATE INDEX IF NOT EXISTS ix_timeline_inv ON timeline(investigation_id)')
 c.execute('CREATE INDEX IF NOT EXISTS ix_notifications_user ON notifications(username, created)')
 c.execute('CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires)')
 c.commit()


def db():
 """Open a connection; the schema is created/migrated once per database file, not on every request."""
 key = str(DB); fresh = key not in _SCHEMA_READY or not Path(DB).exists()
 c = sqlite3.connect(DB, timeout=15); c.row_factory = sqlite3.Row
 if fresh:
  _init_schema(c); _SCHEMA_READY.add(key)
 return c


def _password_hash(password, salt):
 return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 240000).hex()


def _ensure_admin():
 password = os.environ.get('HIRESHIELD_ADMIN_PASSWORD')
 if not password: return
 c = db()
 try:
  if c.execute('SELECT 1 FROM users WHERE username=?', ('admin',)).fetchone(): return
  if password == ADMIN_PLACEHOLDER or len(password) < MIN_PASSWORD:
   log.warning('HIRESHIELD_ADMIN_PASSWORD rejected: it must be at least %d characters and not the .env.example placeholder; admin account NOT created.', MIN_PASSWORD)
   return
  salt = secrets.token_bytes(16)
  c.execute('INSERT OR IGNORE INTO users(username,salt,password_hash,created,role) VALUES(?,?,?,?,?)', ('admin', base64.b64encode(salt).decode(), _password_hash(password, salt), _now(), 'admin')); c.commit()
 finally: c.close()


def _audit(username, action, obj_type, obj_id, details=''):
 c = db()
 try:
  c.execute('INSERT INTO audit(created,username,action,object_type,object_id,details) VALUES(?,?,?,?,?,?)', (_now(), username, action, obj_type, str(obj_id), str(details)[:1000])); c.commit()
 finally: c.close()


def _auth(request: Request):
 token = request.headers.get('authorization', '')
 if not token.startswith('Bearer '): raise HTTPException(401, 'Authentication required')
 digest = hashlib.sha256(token[7:].encode()).hexdigest(); c = db()
 try: row = c.execute('SELECT s.username,s.expires,u.role FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=?', (digest,)).fetchone()
 finally: c.close()
 if not row or row['expires'] < _now(): raise HTTPException(401, 'Invalid or expired session')
 return {'username': row['username'], 'role': row['role']}


def _user(request: Request):
 return _auth(request)['username']


def _admin(request: Request):
 user = _auth(request)
 if user['role'] != 'admin': raise HTTPException(403, 'Administrator role required')
 return user['username']


def _role(username):
 c = db()
 try: row = c.execute('SELECT role FROM users WHERE username=?', (username,)).fetchone()
 finally: c.close()
 return row['role'] if row else 'analyst'


async def _json(request: Request):
 try: body = await request.json()
 except Exception: raise HTTPException(400, 'Request body must be valid JSON')
 if not isinstance(body, dict): raise HTTPException(400, 'A JSON object is required')
 return body


async def _read_body(request: Request, limit, what):
 """Read the request body but abort as soon as it exceeds `limit` instead of buffering it all first."""
 declared = request.headers.get('content-length')
 if declared and declared.isdigit() and int(declared) > limit: raise HTTPException(413, f'{what} exceeds size limit')
 chunks = []; size = 0
 async for chunk in request.stream():
  size += len(chunk)
  if size > limit: raise HTTPException(413, f'{what} exceeds size limit')
  chunks.append(chunk)
 return b''.join(chunks)


def _like(q):
 return '%' + q[:150].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def _notify(c, username, message, object_type, object_id):
 c.execute('INSERT INTO notifications(id,username,created,message,object_type,object_id,read) VALUES(?,?,?,?,?,?,0)', (str(uuid.uuid4()), username, _now(), message, object_type, str(object_id)))


def _case_event(c, case_id, username, event, details):
 c.execute('INSERT INTO case_events(case_id,created,username,event,details) VALUES(?,?,?,?,?)', (case_id, _now(), username, event, details[:1000]))


def _correlation_key(kind, reference, result):
 value = str(reference or '').lower().strip()
 if kind == 'url':
  try: value = urlsplit(value if '://' in value else 'http://' + value).hostname or value
  except Exception: pass
 elif kind == 'email': value = (result.get('sender', '').split('@')[-1].strip('> ')) or value
 elif kind == 'document': value = result.get('sha256') or value  # identical content correlates even if renamed
 return (kind + ':' + value)[:255]


def save(kind, reference, result, username='system'):
 findings = result.get('findings', []); result['risk'] = score(findings); result['investigation_id'] = str(uuid.uuid4()); result['created'] = _now(); result['status'] = 'open'; result['analyst_notes'] = ''
 c = db()
 try:
  c.execute('INSERT INTO investigations VALUES(?,?,?,?,?,?,?)', (result['investigation_id'], result['created'], kind, reference, json.dumps(result), 'open', ''))
  c.execute('INSERT INTO timeline(investigation_id,created,event,details) VALUES(?,?,?,?)', (result['investigation_id'], result['created'], 'Investigation created', kind + ' analysis completed'))
  sev = result['risk'].get('severity', 'low'); key = _correlation_key(kind, reference, result)
  c.execute('INSERT INTO alerts(id,investigation_id,created,title,severity,status,correlation_key) VALUES(?,?,?,?,?,?,?)', (str(uuid.uuid4()), result['investigation_id'], result['created'], kind + ' investigation', sev, 'open', key))
  c.commit()
 finally: c.close()
 _audit(username, 'create', 'investigation', result['investigation_id'], kind); return result


@app.post('/api/login')
async def login(request: Request):
 _ensure_admin(); body = await _json(request); username = str(body.get('username', ''))[:80]; password = str(body.get('password', ''))
 ip = request.client.host if request.client else 'unknown'; now = datetime.datetime.now(datetime.timezone.utc); cutoff = (now - datetime.timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
 c = db()
 try:
  # Housekeeping on every attempt: bounds table growth from failed-login floods and drops dead sessions.
  c.execute('DELETE FROM login_attempts WHERE created<?', (cutoff,)); c.execute('DELETE FROM sessions WHERE expires<?', (now.isoformat(),))
  per_user = c.execute('SELECT COUNT(*) FROM login_attempts WHERE username=? AND ip=? AND success=0 AND created>=?', (username, ip, cutoff)).fetchone()[0]
  per_ip = c.execute('SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND created>=?', (ip, cutoff)).fetchone()[0]  # stops username-rotation bypass
  if per_user >= MAX_FAILED_PER_USER_IP or per_ip >= MAX_FAILED_PER_IP:
   c.commit(); raise HTTPException(429, f'Too many failed login attempts. Try again in {LOCKOUT_MINUTES} minutes.', headers={'Retry-After': str(LOCKOUT_MINUTES * 60)})
  row = c.execute('SELECT salt,password_hash FROM users WHERE username=?', (username,)).fetchone()
  # Always run PBKDF2 so unknown usernames cannot be told apart from wrong passwords by response time.
  salt = base64.b64decode(row['salt']) if row else b'\x00' * 16
  computed = _password_hash(password, salt)
  valid = bool(row and hmac.compare_digest(computed, row['password_hash']))
  c.execute('INSERT INTO login_attempts(username,ip,created,success) VALUES(?,?,?,?)', (username, ip, now.isoformat(), 1 if valid else 0)); c.commit()
  if not valid: raise HTTPException(401, 'Invalid credentials')
  token = secrets.token_urlsafe(32); expires = (now + datetime.timedelta(hours=4)).isoformat(); digest = hashlib.sha256(token.encode()).hexdigest()
  c.execute('INSERT INTO sessions VALUES(?,?,?,?)', (digest, username, now.isoformat(), expires)); c.commit()
 finally: c.close()
 _audit(username, 'login', 'session', 'issued')
 return {'token': token, 'expires': expires, 'username': username}


@app.post('/api/logout')
def logout(request: Request, username: str = Depends(_user)):
 token = request.headers.get('authorization', '')[7:]; digest = hashlib.sha256(token.encode()).hexdigest(); c = db()
 try: c.execute('DELETE FROM sessions WHERE token_hash=?', (digest,)); c.commit()
 finally: c.close()
 _audit(username, 'logout', 'session', 'revoked'); return {'status': 'logged_out'}


@app.get('/api/me')
def me(username: str = Depends(_user)):
 return {'username': username, 'role': _role(username)}


@app.get('/', response_class=HTMLResponse)
def home(): return FRONTEND.read_text(encoding='utf-8')


@app.get('/api/cases')
def list_cases(username: str = Depends(_user), q: str = '', status: str = '', priority: str = '', assigned_to: str = ''):
 c = db(); sql = 'SELECT * FROM cases WHERE 1=1'; params = []
 if q: sql += " AND (title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')"; params.extend([_like(q)] * 2)
 if status: sql += ' AND status=?'; params.append(status)
 if priority: sql += ' AND priority=?'; params.append(priority)
 if assigned_to: sql += ' AND assigned_to=?'; params.append(assigned_to)
 try:
  rows = c.execute(sql + ' ORDER BY updated DESC LIMIT 500', params).fetchall()
  counts = {r[0]: r[1] for r in c.execute('SELECT case_id,COUNT(*) FROM case_items GROUP BY case_id').fetchall()}
 finally: c.close()
 return [dict(row) | {'investigation_count': counts.get(row['id'], 0)} for row in rows]


@app.get('/api/users')
def list_users(username: str = Depends(_user)):
 c = db()
 try: rows = c.execute('SELECT username,role,created FROM users ORDER BY username').fetchall()
 finally: c.close()
 return [dict(x) for x in rows]


@app.post('/api/users')
async def create_user(request: Request, username: str = Depends(_admin)):
 body = await _json(request); name = str(body.get('username', '')).strip()[:80]; password = str(body.get('password', '')); role = str(body.get('role', 'analyst'))
 if not name or len(password) < MIN_PASSWORD or role not in ('admin', 'analyst'): raise HTTPException(400, 'Username, 12-character password, and valid role required')
 salt = secrets.token_bytes(16); c = db()
 try:
  c.execute('INSERT INTO users(username,salt,password_hash,created,role) VALUES(?,?,?,?,?)', (name, base64.b64encode(salt).decode(), _password_hash(password, salt), _now(), role)); c.commit()
 except sqlite3.IntegrityError: raise HTTPException(409, 'Username already exists')
 finally: c.close()
 _audit(username, 'create', 'user', name, role); return {'username': name, 'role': role}


@app.post('/api/cases')
async def create_case(request: Request, username: str = Depends(_user)):
 body = await _json(request); title = str(body.get('title', '')).strip()[:200]; desc = str(body.get('description', ''))[:4000]
 if not title: raise HTTPException(400, 'Case title required')
 priority = str(body.get('priority', 'medium')); assigned = str(body.get('assigned_to') or username)
 if priority not in ('low', 'medium', 'high', 'critical'): raise HTTPException(400, 'Invalid priority')
 c = db()
 try:
  if not c.execute('SELECT username FROM users WHERE username=?', (assigned,)).fetchone(): raise HTTPException(400, 'Assigned analyst does not exist')
  cid = str(uuid.uuid4()); now = _now()
  c.execute('INSERT INTO cases(id,title,description,status,priority,created,updated,owner,assigned_to) VALUES(?,?,?,?,?,?,?,?,?)', (cid, title, desc, 'open', priority, now, now, username, assigned))
  _case_event(c, cid, username, 'Case created', title); _case_event(c, cid, username, 'Assigned', assigned); _notify(c, assigned, 'Case assigned: ' + title, 'case', cid); c.commit()
 finally: c.close()
 _audit(username, 'create', 'case', cid, title); return {'id': cid, 'title': title, 'status': 'open', 'priority': priority, 'assigned_to': assigned}


@app.get('/api/cases/{case_id}')
def get_case(case_id: str, username: str = Depends(_user)):
 c = db()
 try:
  row = c.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
  if not row: raise HTTPException(404, 'Case not found')
  items = c.execute('SELECT i.id,i.created,i.kind,i.reference,i.status,i.result FROM case_items ci JOIN investigations i ON i.id=ci.investigation_id WHERE ci.case_id=?', (case_id,)).fetchall()
  events = c.execute('SELECT created,username,event,details FROM case_events WHERE case_id=? ORDER BY id', (case_id,)).fetchall()
 finally: c.close()
 return dict(row) | {'investigations': [{'id': x['id'], 'created': x['created'], 'kind': x['kind'], 'reference': x['reference'], 'status': x['status'], 'result': json.loads(x['result'])} for x in items], 'timeline': [dict(x) for x in events]}


@app.post('/api/cases/{case_id}/investigations/{inv_id}')
def attach_case(case_id: str, inv_id: str, username: str = Depends(_user)):
 c = db()
 try:
  case = c.execute('SELECT id FROM cases WHERE id=?', (case_id,)).fetchone(); inv = c.execute('SELECT id FROM investigations WHERE id=?', (inv_id,)).fetchone()
  if not case or not inv: raise HTTPException(404, 'Case or investigation not found')
  now = _now(); cur = c.execute('INSERT OR IGNORE INTO case_items VALUES(?,?,?)', (case_id, inv_id, now))
  if cur.rowcount:  # only log a link event when a new link was actually created
   c.execute('UPDATE cases SET updated=? WHERE id=?', (now, case_id)); _case_event(c, case_id, username, 'Investigation linked', inv_id)
  c.commit()
 finally: c.close()
 _audit(username, 'attach', 'case-investigation', case_id, inv_id); return {'status': 'attached'}


@app.patch('/api/cases/{case_id}')
async def update_case(case_id: str, request: Request, username: str = Depends(_user)):
 body = await _json(request); c = db()
 try:
  row = c.execute('SELECT status,priority FROM cases WHERE id=?', (case_id,)).fetchone()
  if not row: raise HTTPException(404, 'Case not found')
  # Partial update: fields that are not supplied keep their stored value (previously they were reset to open/medium).
  status = str(body.get('status', row['status'])); priority = str(body.get('priority', row['priority']))
  if status not in ('open', 'investigating', 'resolved', 'closed') or priority not in ('low', 'medium', 'high', 'critical'): raise HTTPException(400, 'Invalid case status or priority')
  now = _now(); c.execute('UPDATE cases SET status=?,priority=?,updated=? WHERE id=?', (status, priority, now, case_id)); _case_event(c, case_id, username, 'Case updated', f'{row["status"]}/{row["priority"]} -> {status}/{priority}'); c.commit()
 finally: c.close()
 _audit(username, 'update', 'case', case_id, f'{status}/{priority}'); return {'id': case_id, 'status': status, 'priority': priority}


@app.patch('/api/cases/{case_id}/assignment')
async def assign_case(case_id: str, request: Request, username: str = Depends(_user)):
 body = await _json(request); assigned = str(body.get('assigned_to', '')); role = _role(username); c = db()
 try:
  case = c.execute('SELECT id,title,assigned_to FROM cases WHERE id=?', (case_id,)).fetchone(); user = c.execute('SELECT username FROM users WHERE username=?', (assigned,)).fetchone()
  if not case or not user: raise HTTPException(404, 'Case or analyst not found')
  if role != 'admin' and case['assigned_to'] != username: raise HTTPException(403, 'Only administrators or the assigned analyst may reassign')
  old = case['assigned_to']; now = _now()
  c.execute('UPDATE cases SET assigned_to=?,updated=? WHERE id=?', (assigned, now, case_id)); _case_event(c, case_id, username, 'Reassigned', f'{old} -> {assigned}')
  if assigned != old: _notify(c, assigned, 'Case reassigned to you: ' + case['title'], 'case', case_id)
  c.commit()
 finally: c.close()
 _audit(username, 'assign', 'case', case_id, assigned); return {'case_id': case_id, 'assigned_to': assigned}


@app.get('/api/cases/{case_id}/timeline')
def case_timeline(case_id: str, username: str = Depends(_user)):
 c = db()
 try:
  exists = c.execute('SELECT 1 FROM cases WHERE id=?', (case_id,)).fetchone(); rows = c.execute('SELECT created,username,event,details FROM case_events WHERE case_id=? ORDER BY id', (case_id,)).fetchall()
 finally: c.close()
 if not exists: raise HTTPException(404, 'Case not found')
 return [dict(x) for x in rows]


@app.get('/api/metrics')
def metrics(username: str = Depends(_user)):
 c = db()
 try:
  one = lambda sql: c.execute(sql).fetchone()[0]
  return {'investigations': one('SELECT COUNT(*) FROM investigations'), 'open_investigations': one("SELECT COUNT(*) FROM investigations WHERE status IN ('open','reviewing')"),
          'cases': one('SELECT COUNT(*) FROM cases'), 'open_cases': one("SELECT COUNT(*) FROM cases WHERE status IN ('open','investigating')"),
          'alerts': one('SELECT COUNT(*) FROM alerts'), 'open_alerts': one("SELECT COUNT(*) FROM alerts WHERE status='open'"),
          'severity': {x['severity']: x['n'] for x in c.execute('SELECT severity,COUNT(*) n FROM alerts GROUP BY severity').fetchall()}}
 finally: c.close()


@app.get('/api/alerts')
def list_alerts(username: str = Depends(_user), q: str = '', severity: str = '', status: str = '', kind: str = ''):
 sql = 'SELECT a.*,i.kind,i.reference FROM alerts a JOIN investigations i ON i.id=a.investigation_id WHERE 1=1'; params = []
 if q: sql += " AND (a.title LIKE ? ESCAPE '\\' OR a.correlation_key LIKE ? ESCAPE '\\' OR i.reference LIKE ? ESCAPE '\\')"; params.extend([_like(q)] * 3)
 if severity: sql += ' AND a.severity=?'; params.append(severity)
 if status: sql += ' AND a.status=?'; params.append(status)
 if kind: sql += ' AND i.kind=?'; params.append(kind)
 c = db()
 try: rows = c.execute(sql + ' ORDER BY a.created DESC LIMIT 500', params).fetchall()
 finally: c.close()
 return [dict(x) for x in rows]


@app.patch('/api/alerts/{alert_id}')
async def update_alert(alert_id: str, request: Request, username: str = Depends(_user)):
 body = await _json(request); status = str(body.get('status', '')); note = str(body.get('note', ''))[:1000]
 if status not in ('open', 'acknowledged', 'resolved'): raise HTTPException(400, 'Alert status must be open, acknowledged, or resolved')
 c = db()
 try:
  row = c.execute('SELECT a.id,a.status,a.investigation_id,i.reference FROM alerts a JOIN investigations i ON i.id=a.investigation_id WHERE a.id=?', (alert_id,)).fetchone()
  if not row: raise HTTPException(404, 'Alert not found')
  old = row['status']; now = _now(); inv = row['investigation_id']
  c.execute('UPDATE alerts SET status=? WHERE id=?', (status, alert_id))
  c.execute('INSERT INTO alert_events(alert_id,created,username,event,details) VALUES(?,?,?,?,?)', (alert_id, now, username, 'Status changed', f'{old} -> {status}; {note}'))
  c.execute('INSERT INTO timeline(investigation_id,created,event,details) VALUES(?,?,?,?)', (inv, now, 'Alert status changed', f'{old} -> {status} by {username}'))
  c.execute('INSERT INTO audit(created,username,action,object_type,object_id,details) VALUES(?,?,?,?,?,?)', (now, username, 'alert-status', 'alert', alert_id, f'{old}->{status}'))
  # notify assignees of cases linked to the investigation
  for o in c.execute('SELECT DISTINCT cases.assigned_to FROM cases JOIN case_items ON case_items.case_id=cases.id WHERE case_items.investigation_id=?', (inv,)).fetchall():
   if o['assigned_to'] and o['assigned_to'] != username: _notify(c, o['assigned_to'], f'Alert {status}: {row["reference"]}', 'alert', alert_id)
  c.commit()
 finally: c.close()
 return {'id': alert_id, 'status': status}


@app.get('/api/alerts/{alert_id}/timeline')
def alert_timeline(alert_id: str, username: str = Depends(_user)):
 c = db()
 try:
  exists = c.execute('SELECT 1 FROM alerts WHERE id=?', (alert_id,)).fetchone(); rows = c.execute('SELECT created,username,event,details FROM alert_events WHERE alert_id=? ORDER BY id', (alert_id,)).fetchall()
 finally: c.close()
 if not exists: raise HTTPException(404, 'Alert not found')
 return [dict(x) for x in rows]


@app.get('/api/notifications')
def notifications(username: str = Depends(_user)):
 c = db()
 try: rows = c.execute('SELECT id,created,message,object_type,object_id,read FROM notifications WHERE username=? ORDER BY created DESC LIMIT 100', (username,)).fetchall()
 finally: c.close()
 return [dict(x) for x in rows]


@app.patch('/api/notifications/{notification_id}/read')
def mark_notification(notification_id: str, username: str = Depends(_user)):
 c = db()
 try: cur = c.execute('UPDATE notifications SET read=1 WHERE id=? AND username=?', (notification_id, username)); c.commit(); found = cur.rowcount
 finally: c.close()
 if not found: raise HTTPException(404, 'Notification not found')
 return {'status': 'read'}


@app.post('/api/alerts/correlate')
def correlate(username: str = Depends(_user)):
 c = db(); result = []
 try:
  groups = c.execute("SELECT correlation_key,COUNT(*) n FROM alerts WHERE status='open' GROUP BY correlation_key HAVING COUNT(*)>1").fetchall()
  for g in groups:
   ids = [x[0] for x in c.execute("SELECT investigation_id FROM alerts WHERE correlation_key=? AND status='open'", (g['correlation_key'],)).fetchall()]
   meta = c.execute("SELECT severity,COUNT(*) FROM alerts WHERE correlation_key=? AND status='open' GROUP BY severity", (g['correlation_key'],)).fetchall()
   result.append({'correlation_key': g['correlation_key'], 'count': g['n'], 'investigation_ids': ids, 'severity_counts': {x[0]: x[1] for x in meta}, 'grouping_basis': 'normalized reference key (URL host / sender domain / file SHA-256); heuristic'})
 finally: c.close()
 _audit(username, 'correlate', 'alerts', 'batch', f'{len(result)} groups'); return {'groups': result}


@app.get('/api/audit')
def audit_log(username: str = Depends(_user)):
 c = db()
 try: rows = c.execute('SELECT created,username,action,object_type,object_id,details FROM audit ORDER BY id DESC LIMIT 500').fetchall()
 finally: c.close()
 return [dict(x) for x in rows]


@app.get('/api/health')
def health(request: Request):
 _ensure_admin(); out = {'status': 'ok', 'version': VERSION}
 try: _auth(request)
 except HTTPException: return out  # unauthenticated callers get liveness only, not paths or installed-tool details
 spec = importlib.util.find_spec
 out.update({'database': DB.name, 'optional_tools': {'clamav': bool(shutil.which('clamscan')), 'yara_python': bool(spec('yara')), 'pypdf': bool(spec('pypdf')), 'ollama': 'optional'}})
 return out


@app.post('/api/email')
async def email(request: Request, username: str = Depends(_user)):
 data = await _read_body(request, MAX_BYTES, 'Email')
 if not data.strip(): raise HTTPException(400, 'Email content required')
 try: r = await run_in_threadpool(analyze_email, data)
 except Exception: raise HTTPException(400, 'Unable to parse email input')
 return save('email', r.get('subject', 'email'), r, username)


@app.post('/api/url')
async def url(request: Request, username: str = Depends(_user)):
 u = (await _read_body(request, 8192, 'URL')).decode('utf-8', 'replace').strip()
 if not u or len(u) > 2048: raise HTTPException(400, 'URL required (max 2048 characters)')
 r = analyze_url(u); return save('url', u, r, username)


@app.post('/api/file')
async def file(request: Request, username: str = Depends(_user)):
 # The console percent-encodes the name so non-ASCII file names survive the HTTP header.
 name = unquote(request.headers.get('x-filename', 'upload.bin')).strip()
 if not name or len(name) > 255 or '/' in name or '\\' in name or name in ('.', '..') or any(ord(ch) < 32 for ch in name): raise HTTPException(400, 'Invalid filename')
 data = await _read_body(request, MAX_BYTES, 'File')
 if not data: raise HTTPException(400, 'Empty file')
 r = await run_in_threadpool(inspect_file, name, data)  # scanners are blocking; keep the event loop free
 return save('document', name, r, username)


@app.get('/api/investigations')
def investigations(username: str = Depends(_user)):
 c = db()
 try: rows = c.execute('SELECT id,created,kind,reference,status FROM investigations ORDER BY created DESC LIMIT 500').fetchall()
 finally: c.close()
 return [{'id': x[0], 'created': x[1], 'kind': x[2], 'reference': x[3], 'status': x[4]} for x in rows]


def _get_investigation(id):
 c = db()
 try: row = c.execute('SELECT result FROM investigations WHERE id=?', (id,)).fetchone()
 finally: c.close()
 if not row: raise HTTPException(404, 'Investigation not found')
 return json.loads(row[0])


def _timeline_rows(id):
 c = db()
 try:
  exists = c.execute('SELECT 1 FROM investigations WHERE id=?', (id,)).fetchone(); rows = c.execute('SELECT created,event,details FROM timeline WHERE investigation_id=? ORDER BY id', (id,)).fetchall()
 finally: c.close()
 if not exists: raise HTTPException(404, 'Investigation not found')
 return [{'created': x[0], 'event': x[1], 'details': x[2]} for x in rows]


@app.get('/api/investigations/{id}')
def get_inv(id: str, username: str = Depends(_user)):
 return _get_investigation(id)


@app.patch('/api/investigations/{id}')
async def update(id: str, request: Request, username: str = Depends(_user)):
 body = await _json(request); c = db()
 try:
  row = c.execute('SELECT result FROM investigations WHERE id=?', (id,)).fetchone()
  if not row: raise HTTPException(404, 'Not found')
  r = json.loads(row[0]); old = r.get('status', 'open'); old_notes = r.get('analyst_notes', '')
  # Partial update: omitted fields are preserved (previously a status-only PATCH wiped the notes and reset status to open).
  status = str(body.get('status', old)); notes = str(body['notes'])[:5000] if 'notes' in body else old_notes
  if status not in ('open', 'reviewing', 'closed'): raise HTTPException(400, 'Invalid status')
  r['status'] = status; r['analyst_notes'] = notes
  c.execute('UPDATE investigations SET result=?,status=?,notes=? WHERE id=?', (json.dumps(r), status, notes, id))
  c.execute('INSERT INTO timeline(investigation_id,created,event,details) VALUES(?,?,?,?)', (id, _now(), 'Investigation updated', f'Status: {old} -> {status}; notes {"edited" if notes != old_notes else "unchanged"}')); c.commit()
 finally: c.close()
 _audit(username, 'update', 'investigation', id, status); return r


@app.get('/api/investigations/{id}/timeline')
def timeline(id: str, username: str = Depends(_user)):
 return _timeline_rows(id)


@app.post('/api/investigations/{id}/ai-explain')
def ai_explain(id: str, username: str = Depends(_user)):
 r = _get_investigation(id)
 result = explain(r, model=os.environ.get('HIRESHIELD_OLLAMA_MODEL', 'qwen2.5:3b'))
 c = db()
 try:
  # Re-read after the (slow) model call so notes/status edited meanwhile are not overwritten with a stale copy.
  row = c.execute('SELECT result FROM investigations WHERE id=?', (id,)).fetchone()
  if row:
   latest = json.loads(row[0]); latest['ai_explanation'] = result
   c.execute('UPDATE investigations SET result=? WHERE id=?', (json.dumps(latest), id))
   c.execute('INSERT INTO timeline(investigation_id,created,event,details) VALUES(?,?,?,?)', (id, _now(), 'Local AI explanation requested', result.get('status', 'unknown'))); c.commit()
 finally: c.close()
 _audit(username, 'ai-explain', 'investigation', id, result.get('status', 'unknown')); return result


@app.get('/api/report/{id}')
def report(id: str, username: str = Depends(_user)):
 return JSONResponse(_get_investigation(id), headers={'Content-Disposition': f'attachment; filename="HireShield-{id}.json"'})


@app.get('/api/report/{id}/pdf')
def pdf_report(id: str, username: str = Depends(_user)):
 r = _get_investigation(id); content = make_pdf(r, _timeline_rows(id))
 return Response(content, media_type='application/pdf', headers={'Content-Disposition': f'attachment; filename="HireShield-{id}.pdf"'})
