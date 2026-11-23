# Security notes (v0.4)

- Bootstrap admin account: configure `HIRESHIELD_ADMIN_PASSWORD` before first use. Only a single `admin` account is provisioned automatically; no RBAC or user-management interface exists yet.
- Password storage: PBKDF2-HMAC-SHA256 with per-user salt and 240,000 iterations.
- Session tokens: random bearer tokens, SHA-256 hashes stored in SQLite, four-hour expiry (since v0.6). Use localhost/private lab only; no TLS or cookie-based session/CSRF controls are included. Login throttling was added in v0.6.
- Audit events: application actions are appended to an SQLite audit table. Local DB access can alter the log; it is not cryptographically tamper-proof.
- Alert correlation: grouping by normalized kind/reference key only. This is a heuristic and not validated correlation logic.
- Detection engine, risk score and findings remain independent of optional AI. AI explanation is advisory and must not influence candidate suitability or hiring decisions.
- Uploaded content is never intentionally executed; this is not a sandbox. Avoid exposing the app to untrusted users or public networks.

## v0.5 security notes

- Local user roles: administrator and analyst. Admin-only account provisioning; case assignment permissions are checked server-side.
- Passwords are salted PBKDF2-HMAC-SHA256 hashes. Bearer tokens are stored as SHA-256 digests and expire after four hours (v0.6+).
- Network-facing deployment hardening and tamper-evident audit storage are not implemented; keep this lab service on localhost. (Login throttling arrived in v0.6.)
- Alert correlation is heuristic; it should not be treated as attribution or definitive linkage.

## v0.6.1 security notes

- Admin bootstrap password must be >= 12 characters and not the `.env.example` placeholder; otherwise no admin is created (a warning is logged).
- Login: PBKDF2 is computed even for unknown users (no timing oracle); failures are throttled per username+IP **and** per IP (50 / 15 min) with `Retry-After`; old attempts and expired sessions are pruned on every login.
- Uploads are read as a stream and rejected with 413 as soon as they pass the limit; scanners run in a worker thread so one scan cannot stall other users.
- `/api/health` returns only `status`/`version` to unauthenticated callers.
- A Content-Security-Policy is sent. It still allows `'unsafe-inline'` scripts because the console uses inline handlers; moving the JS to a separate file would allow a strict policy.
- Local AI explanations receive finding evidence as delimited, untrusted data. Evidence comes from hostile files/emails, so treat the output as advisory text that could still be influenced by prompt injection.

### Known limitations (design decisions, not fixed)
- Authorization is coarse: any signed-in analyst can read every investigation, case, user and the audit log, and can update any case/investigation. Only user creation is admin-only and reassignment is restricted. Define a role policy before exposing to more than a trusted team.
- No TLS, MFA, CSRF/cookie model, or tamper-evident audit store; client IP is the direct peer address (behind a reverse proxy all users share one IP for throttling).
- ClamAV is invoked via `clamscan`, which reloads signatures on each scan (slow); `clamd` would be faster. Office/PDF parsing is best-effort and is not a sandbox.
