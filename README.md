# HireShield AI v0.6.1

Local-first HR/SOC security triage for suspicious email, URLs and recruitment documents. It is an investigation aid, **not** an automated hiring/rejection system.

## Run locally

Python 3.10+ recommended. From this project folder:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
export HIRESHIELD_ADMIN_PASSWORD='replace-with-a-long-unique-password'   # PowerShell: $env:HIRESHIELD_ADMIN_PASSWORD = "..."
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` and sign in as `admin`. The password must be at least 12 characters and must not be the placeholder from `.env.example`, otherwise the admin account is **not** created. Run tests using `pytest -q` (or `python -m pytest -q`).

Environment variables: `HIRESHIELD_ADMIN_PASSWORD` (required before first login), `HIRESHIELD_DB` (SQLite path, default `hireshield.db` in the working directory), `HIRESHIELD_YARA_DIR`, `HIRESHIELD_CLAM_TIMEOUT` (seconds, default 90), `HIRESHIELD_OLLAMA_MODEL`, `HIRESHIELD_OLLAMA_TIMEOUT` (seconds, default 120). The app does not read `.env` by itself; export the variables, or run `uvicorn ... --env-file .env` (needs `pip install python-dotenv`).

## v0.2 document features

- PDF parsing with pypdf: bounded text extraction, annotation links and action indicators; no actions are executed.
- DOCX/XLSX/PPTX ZIP/XML inspection: external relationship links, macro-capable package parts and embedded-object indicators; bounded archive inspection, no extraction to disk.
- URL extraction from inspected content and heuristic analysis. URLs are not visited.
- Optional YARA (`pip install yara-python`): rules in `detection/yara` (or override with `HIRESHIELD_YARA_DIR`). The included rule only matches a synthetic test marker.
- Optional ClamAV: install ClamAV and ensure `clamscan` is on PATH. Signature database availability is managed by your ClamAV installation.
- Legacy `.doc/.xls/.ppt`: signature and OLE identification only; no deep analysis.

## Other features

Email `.eml` parsing, URL heuristics, SQLite investigation history, notes/status and JSON report endpoint. See `docs/DEPENDENCIES.md` and `docs/SECURITY.md`.

## API

(All endpoints except `/`, `/api/login` and a minimal `/api/health` need `Authorization: Bearer <token>` — see v0.4 below.) `POST /api/email` raw email bytes; `POST /api/url` raw URL text; `POST /api/file` raw file bytes with a percent-encoded `x-filename` header; `GET /api/investigations`; `GET /api/investigations/{id}`; `PATCH /api/investigations/{id}`; `GET /api/report/{id}`; `GET /api/report/{id}/pdf`; `GET /api/investigations/{id}/timeline`; `POST /api/investigations/{id}/ai-explain`; `GET /api/users`; `GET /api/health`.

## Safety and limitations

8 MiB upload cap. Document parsers are best-effort and are not a sandbox or guarantee of safety. Run locally or in an isolated environment; this prototype has no authentication. Do not upload sensitive applicant data unless authorized. See `docs/SECURITY.md`.

## v0.3 features
- Optional local Ollama explanations: click **Generate local AI explanation** on an investigation. AI text is advisory and cannot alter evidence, findings or risk score. The feature gracefully reports unavailable service/model.
- Timeline: **View timeline** for creation and investigation status/notes changes, plus AI-explanation requests.
- PDF: **Download PDF report** or `/api/report/{id}/pdf` for findings, timeline, notes and risk caveat.
- Office analysis heuristics expanded for VBA project markers, embedded/ActiveX content, hidden worksheet states, and potentially risky formula patterns.

### Ollama (optional)
Install and start Ollama separately, then pull a model of your choice (example: `ollama pull qwen2.5:3b`). HireShield uses `http://127.0.0.1:11434` and model `qwen2.5:3b` by default. Set `HIRESHIELD_OLLAMA_MODEL` to select another model name. AI functionality is optional; detection and report workflows remain available without it. Live Ollama inference was not verified in the v0.3 build environment.

See `TEST_REPORT.md`, `PROJECT_PROGRESS.md`, and `HANDOFF.md` for verification and limitations.

## v0.4 SOC management

Set the bootstrap admin password **before first run**. On Windows PowerShell:

```powershell
$env:HIRESHIELD_ADMIN_PASSWORD = "replace-with-a-long-unique-password"
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

On Linux/macOS:

```bash
export HIRESHIELD_ADMIN_PASSWORD='replace-with-a-long-unique-password'
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The bootstrap `admin` account is created on the first successful login request if the environment variable is set and the user does not already exist. The password is stored as PBKDF2-HMAC-SHA256 (salted, 240,000 iterations). Login issues a bearer token with an eight-hour expiry; the session token is stored hashed in SQLite. Login is local-only by default. Do not expose the development server to untrusted networks. This version has a single bootstrap administrator, not a full role/permission system.

### v0.4 API

- `POST /api/login` JSON `{ "username": "admin", "password": "..." }`
- `POST /api/logout` (Bearer token)
- `GET /api/me`
- `GET /api/cases`, `POST /api/cases`, `GET /api/cases/{case_id}`, `PATCH /api/cases/{case_id}`
- `POST /api/cases/{case_id}/investigations/{investigation_id}`
- `GET /api/alerts`, `POST /api/alerts/correlate`
- `GET /api/audit` (latest 500 records)

All analysis, case, report, timeline, and audit endpoints require a bearer token. `/`, `/api/health`, and `/api/login` are intentionally available without authentication. Alert correlation groups open alerts using a simple normalized type/reference key; it is a triage aid, not advanced SIEM correlation. The audit log is append-only via application endpoints, not tamper-proof against local database administrators.

## v0.5 — SOC workflow improvements

- Multi-user local accounts (`admin` and `analyst` roles), created by an admin through `POST /api/users`.
- Case assignment and reassignment (`PATCH /api/cases/{case_id}/assignment`). Administrators can reassign; an assigned analyst may reassign their own case.
- Case activity timeline (`GET /api/cases/{case_id}/timeline`) and investigation links.
- Alert filters via `q`, `severity`, `status`, and `kind` query parameters.
- Heuristic alert-correlation summaries include group size and severity counts.
- Real database dashboard metrics at `GET /api/metrics`.

Account creation example (administrator token required):

```json
POST /api/users
{"username":"analyst1","password":"Use-a-long-unique-password","role":"analyst"}
```

## v0.5 limitations and deployment guidance

This release is intended for a localhost/lab deployment. It is not a production-ready multi-tenant SOC service. Before exposing it to a network, add HTTPS and secure cookie/token handling, CSRF protections if cookie auth is adopted, rate-limited login, a hardened deployment configuration, backup/retention controls, and review the authorization model. The audit trail is database-backed and can be modified by someone with direct DB access. Correlation is heuristic and not proof of a common threat actor.


## v0.6 additions

- Alert lifecycle states: `open`, `acknowledged`, and `resolved`; status changes are recorded in an alert timeline and audit trail.
- Local analyst notifications for case assignment/reassignment and alert status updates to linked case assignees. Notifications can be marked read.
- Login throttling: five failed attempts per username/IP in a rolling 15-minute window; blocked attempts return HTTP 429. Session duration reduced to four hours.
- Case query filters: `q`, `status`, `priority`, and `assigned_to` on `GET /api/cases`.
- Security headers: nosniff, frame denial, no-referrer, restrictive permissions policy and no-store.
- Alert APIs: `PATCH /api/alerts/{id}` and `GET /api/alerts/{id}/timeline`; notifications APIs: `GET /api/notifications`, `PATCH /api/notifications/{id}/read`.

Login throttling is local database-backed and is not a substitute for reverse-proxy rate limiting, MFA, TLS, or hardened deployment. Keep this app on localhost or a trusted isolated network.

## Verification (v0.6)

Run `python -m pytest -q` from the project directory. The suite currently reports 72 passing tests (29 original + 43 audit regression tests). See `TEST_REPORT.md` for compile, API smoke and archive checks. Optional tools (YARA, ClamAV, Ollama) require separate installation/configuration and are not guaranteed by the core test run.

## v0.6.1 — audit fixes

A full code audit of v0.6 found and fixed the following (details and evidence in `AUDIT_REPORT.md`):

- **Detection:** `microsoft.com`-style hosts were flagged as URL shorteners; every Office file scored ~40/"medium" because XML namespace URLs were treated as links; the `[Content_Types].xml` macro check and `veryHidden` sheet check never fired; remote-template / UNC relationships were not detected; "macro"/"JavaScript" words in ordinary resumes raised findings; PDF JavaScript/OpenAction detection missed real structures; PDFs with a junk-prefixed header were not parsed; a large decoy entry in a ZIP could hide a macro entry; a confirmed ClamAV hit scored only "medium".
- **API:** partial `PATCH` calls reset case priority/status and wiped investigation notes; malformed JSON caused HTTP 500; uploads were fully buffered before the size check; scans blocked the event loop; non-ASCII filenames and the JSON/PDF download buttons were broken in the console; the frontend, YARA rules and `.env` expectations depended on the working directory.
- **Hardening:** login timing oracle, unbounded login/session tables, username-rotation throttle bypass, placeholder/weak admin password accepted, unauthenticated `/api/health` disclosed paths, no CSP, SQL double-quoted string literals.
- **Packaging/docs:** `pytest -q` failed (only `python -m pytest` worked); `httpx` missing from requirements; truncated MIT license text; stale security notes.
