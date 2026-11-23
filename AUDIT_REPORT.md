# HireShield AI v0.6 — audit report

Scope: every file in the v0.6 archive (backend, detection engine, PDF/AI modules, frontend, tests, docs, packaging). Method: read all code, then reproduce each suspected defect with a script or live server **before** changing anything. Baseline: v0.6 passed its own 29 tests, which only cover the happy path. Result: 36 defects fixed (summary below); 5 design-level items reported but not changed.

## Detection engine (`hireshield/core.py`)
| # | Defect (reproduced) | Fix |
|---|---|---|
| 1 | Shortener regex matched substrings: `microsoft.com`, `habit.ly` flagged | Exact domain / subdomain match against a list |
| 2 | Every Office file produced ~5 "URL does not use HTTPS" findings (XML namespace URLs treated as links): a benign resume.docx scored 40 "medium" | Namespace declarations/relationship types are no longer extracted as links; namespace hosts filtered |
| 3 | `[Content_Types].xml` macro check never fired (`endswith('content_types.xml')` cannot match the `]`) | Exact match on `[content_types].xml` |
| 4 | `veryHidden` sheets missed (value compared case-sensitively) | Case-insensitive; veryHidden = medium |
| 5 | Remote template / UNC / `file:` external relationships not detected (only http(s) collected) | New high findings; linked OLE objects; non-web schemes |
| 6 | "macro" / "JavaScript" / "/js" byte markers fired on ordinary resumes and URLs | Only unambiguous markers; HTML script check for html files; OLE `VBA` storage check |
| 7 | PDF JavaScript check inspected `str(trailer)` (never contains it); OpenAction/annotation indirect objects not resolved | Structural checks: OpenAction/AA actions, Names/JavaScript, Launch, embedded files, URI annotations |
| 8 | PDF with junk before `%PDF` header was not parsed at all | Content sniffing; offset finding |
| 9 | Analysis chosen by file extension: `invoice.pdf` that is really a macro doc was not inspected | Sniff-based routing; mismatch still flagged |
| 10 | A large decoy ZIP entry stopped inspection, hiding later macro entries | Name checks run for every entry; only content reads are budgeted |
| 11 | ZIP traversal with backslashes / drive letters, encrypted entries, bombs, executables inside archives unchecked | Added |
| 12 | Single confirmed ClamAV hit scored 30 = "medium"; one "high" finding = "low" | Severity floors (critical ≥ 75, high ≥ 50) |
| 13 | URLs without a scheme or with decimal/hex IPs were not host-analysed | Handled |
| 14 | Duplicate findings and findings that did not say which URL they referred to | De-duplicated; URL appended to evidence |
| 15 | Trailing `.`/`,`/`)` captured into extracted URLs | Cleaned |
| 16 | Executable / double extension / bidi-spoofed names (`cv.pdf.exe`) and email attachment names unchecked | Added |
| 17 | YARA rules path relative to CWD (silently "not configured" elsewhere); nonsensical `which('python')` check; recompiled per request | Project-relative, cached |
| 18 | ClamAV: 20 s timeout (cold `clamscan` takes longer), temp path leaked in evidence | Configurable timeout; path redacted |
| 19 | XML entity declarations (billion-laughs) parsed | Skipped with a finding |

## Backend (`backend/main.py`)
| # | Defect | Fix |
|---|---|---|
| 20 | `PATCH /api/cases/{id}` reset priority→medium/status→open when a field was omitted | True partial update |
| 21 | `PATCH /api/investigations/{id}` wiped notes / reset status when omitted | True partial update |
| 22 | Malformed or non-object JSON → HTTP 500 | 400 |
| 23 | Upload fully buffered before size check; empty uploads accepted | Streaming cap → 413; empty → 400 |
| 24 | Blocking scans ran on the event loop (one 20 s ClamAV scan froze the server) | `run_in_threadpool` |
| 25 | `GET /` and YARA depended on CWD; `read_text()` used locale encoding (breaks on Windows) | Paths from `__file__`, UTF-8 |
| 26 | Login timing oracle (no PBKDF2 for unknown users) | Always hash |
| 27 | `login_attempts`/`sessions` grew without bound; throttle bypassed by rotating usernames | Pruned each login; per-IP cap; `Retry-After` |
| 28 | `.env.example` placeholder / short password accepted as admin password | Rejected, warning logged |
| 29 | Unauthenticated `/api/health` disclosed DB path and installed tools | Liveness only unless authenticated |
| 30 | No Content-Security-Policy | Added (see limitation below) |
| 31 | SQL used double-quoted string literals (`"open"`) — fails on SQLite builds without DQS | Single quotes |
| 32 | Schema DDL + PRAGMA executed on every request; connections leaked on errors | Once per DB file; try/finally |
| 33 | AI explanation overwrote notes/status edited during the model call; 12 s timeout made it fail almost always; evidence put unguarded in prompt | Re-read before write; 120 s configurable; delimited untrusted data |
| 34 | Duplicate "Investigation linked" events; reassignment notice showed a UUID; LIKE wildcards unescaped; documents correlated by filename | Idempotent, title, escaped, SHA-256 |

## PDF report
| 35 | Table cells were plain strings: long evidence ran off the page and was lost; escaped markup printed literally (`&lt;b&gt;`); control characters could break rendering | Paragraph cells, word-wrap, sanitising |

## Frontend
| 36 | JSON/PDF download buttons used `location.href` (cannot send the Bearer token → always 401 since v0.4); non-ASCII filenames threw in `fetch`; expired token left a broken UI; global `history()` shadowed `window.history`; case detail/correlation output appended repeatedly (duplicate element IDs); no priority input, no sign-out, empty user list | Fixed |

## Packaging / docs
`pytest -q` (the README command) failed; `httpx` missing; `backend/__init__.py` absent; **LICENSE warranty/liability text was truncated** (restored the standard MIT text); NOTICE omitted pypdf/ReportLab; README/SECURITY described v0.2–v0.5 behaviour (eight-hour sessions, "no throttling"); `.gitignore` incomplete.

## Reported, not changed (needs a decision)
1. Coarse authorization: every analyst can read all cases/investigations/users/audit log and update any case. 2. CSP keeps `'unsafe-inline'` (inline JS handlers). 3. No TLS/MFA/CSRF — keep on localhost. 4. `clamscan` instead of `clamd`. 5. Not detected: RTF exploits, HTML smuggling, link text vs. href mismatch, display-name spoofing.
