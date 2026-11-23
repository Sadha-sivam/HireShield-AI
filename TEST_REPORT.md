# HireShield AI test report — v0.6.1 (audit release)

- `pytest -q` (and `python -m pytest -q`): **72 passed** (29 original + 43 audit regression tests in `tests/test_audit_v061.py`). One original assertion was intentionally updated (`score([high])` is now 50, the "high" floor).
- Regression value: the 43 new tests were run against the untouched v0.6 code — **38 failed** there, confirming they detect the defects.
- Compile check: `python -m compileall -q backend hireshield` — passed.
- Browser end-to-end (headless Chromium against a live uvicorn server, temporary DB): bad/good login, URL analysis, upload of a file with a non-ASCII name, JSON and PDF downloads (authenticated), notes/status save, case creation with priority, case timeline, correlation, user list, and graceful sign-out on an invalid token — all passed with no JavaScript errors and no server tracebacks.
- YARA: verified live with `yara-python` (rule matches from a different working directory).
- PDF report: rendered and inspected visually (wrapped long evidence, markup shown literally as text).
- **Not live-verified:** ClamAV (no `clamscan` in the test environment; the logic is covered with a mocked `clamscan`) and Ollama (covered with a mocked HTTP call).
