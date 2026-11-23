# HireShield AI — v0.5 handoff

The existing v0.4 codebase was incrementally extended. Do not restart from scratch.

## v0.5 additions
- Users table includes role (`admin`/`analyst`); admin bootstrap remains via `HIRESHIELD_ADMIN_PASSWORD`.
- `POST /api/users` is admin-only; account password must be at least 12 characters.
- Cases have `assigned_to`; assignment route is `PATCH /api/cases/{case_id}/assignment`.
- Case events persisted in `case_events`; timelines available through case detail and `/timeline`.
- Alert filters: `q`, `severity`, `status`, `kind`.
- `/api/metrics` returns counts based on stored database records.
- Correlation includes heuristic group and severity counts.

## Run and verify
`python -m pytest -q` (26 tests passed in the build environment). Start with `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000` after setting `HIRESHIELD_ADMIN_PASSWORD`.

## Next work
1. Review and harden auth for network deployment (login throttling, TLS, secure token storage).
2. Add alert lifecycle actions and analyst notification.
3. Expand dashboard case assignment and linking controls.
4. Consider audit integrity controls and database backups.
5. Add more granular permissions only after validating a role policy.


## v0.6 handoff

Alert lifecycle is `open` → `acknowledged` → `resolved` (also permits status reopen). Events are in `alert_events`; status-change events also append to the investigation timeline. Notifications table is local and user-scoped; case assignment changes notify the assignee. Login attempts tracked in `login_attempts`; five failures per username/IP within 15 minutes lock login temporarily.

## Validation and release

Release v0.6 passed 29 tests, compileall, API smoke checks on an isolated temporary DB, and ZIP integrity validation. Review `TEST_REPORT.md`. Optional integrations were not live-validated in the release smoke test.

## v0.6.1 handoff (audit release)

Code audit + repairs on top of v0.6; no features were removed and all v0.6 API shapes are unchanged (`/api/health` is now minimal when unauthenticated). See `AUDIT_REPORT.md` for every finding. Run `pytest -q` (72 tests). Behaviour changes worth knowing: `PATCH /api/cases/{id}` and `PATCH /api/investigations/{id}` are now true partial updates; risk severity is floored by the highest finding (critical → critical, high → high); documents correlate by SHA-256; admin password must be 12+ chars; `x-filename` is percent-encoded by the console.

Open items (not changed; need a product decision): role/permission policy (analysts can see all cases/audit), strict CSP (needs JS moved out of inline handlers), TLS/MFA/CSRF for network deployment, clamd instead of clamscan, RTF/HTML-smuggling/link-text-vs-href detections.
