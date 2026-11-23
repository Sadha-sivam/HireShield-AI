# HireShield AI — Project progress

## v0.6
- Alert status lifecycle: open, acknowledged, resolved; event timeline and investigation timeline/audit entries.
- Local analyst notifications for case creation/assignment/reassignment and lifecycle updates to linked case assignees.
- Notification read state and endpoints.
- Login throttling: five failed attempts per username/IP within 15 minutes, HTTP 429 thereafter; four-hour sessions.
- Security response headers and case query filters (search, status, priority, assigned analyst).
- Updated dashboard alert lifecycle actions, case filters, notifications.
- **29 automated tests passed**; compile and API smoke checks passed.

## Preserved from prior versions
Email, URL and document analysis engines, heuristic findings and scoring, report generation, timeline, case and correlation workflow, optional local AI explanations. AI explanations remain advisory and do not modify detection evidence or severity.

## v0.6.1 (audit release)
- Independent audit of all source, tests, docs and packaging; defects reproduced before fixing (see `AUDIT_REPORT.md`).
- Detection-engine false positives/negatives repaired; scoring floors; content sniffing; PDF/OOXML/OLE checks fixed or added.
- API correctness (partial PATCH, 400 vs 500, streaming upload cap, threadpool scans), login hardening, CSP, cwd-independent paths.
- Frontend: authenticated downloads, unicode filenames, expired-session handling, case priority, user list, sign-out.
- **72 automated tests pass** (43 new; 38 of them fail on v0.6). Chromium end-to-end run of the console passed.
