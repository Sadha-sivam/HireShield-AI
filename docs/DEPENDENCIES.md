# Dependencies and optional integrations (v0.6.1)

- **pypdf**: Python PDF parser used for bounded text and annotation URI extraction plus action-marker inspection. Parsing is best-effort; it is not a sandbox.
- **ClamAV**: optional external scanner via the `clamscan` executable. HireShield uses argument-list subprocess execution, a temporary file, and a configurable timeout (`HIRESHIELD_CLAM_TIMEOUT`, default 90 s). Installation/signature updates are managed by the OS/ClamAV installation. This integration was tested only if `clamscan` was available in the test environment; see TEST_REPORT.md.
- **YARA**: optional `yara-python` binding. Rules are loaded from the project's `detection/yara` folder (independent of the working directory) or `HIRESHIELD_YARA_DIR`, and compiled once and cached. A bundled rule detects a synthetic marker only; it is not a malware signature. Install the binding separately with `pip install yara-python`.
- **Office files**: DOCX/XLSX/PPTX are inspected as ZIP/XML packages using Python's standard library. XML parsing does not execute Office content. External relationships, macro-related package parts, and embedded objects are reported. Legacy OLE DOC/XLS/PPT files are identified but not deeply parsed.

No uploaded document is executed, no URL is fetched, and no content is sent to a reputation service.

- **httpx**: needed only to run the test suite (`fastapi.testclient`).
- **reportlab**: PDF report generation.
