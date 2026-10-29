# 3.3 Testing and Validation

## 3.3.1 Testing and Validation Process

WebSET was validated in two layers. An automated pytest suite checks the scanner and the API without starting Docker and without sending traffic to Juice Shop, DVWA, or any external host. A short manual walkthrough then checks the same behaviour through the dashboard, with the lab containers running. The automated tests use a temporary SQLite file, so they do not write to the demo database at `backend/data/webset.db`.

The suite is grouped by the kind of check:

- **Unit tests** cover the local-target allow-list (`test_allowlist.py`), the JavaScript and PHP static rules on fixture files (`test_static.py`), and the dynamic header, cookie, CORS, and sensitive-path checks on fake HTTP responses (`test_dynamic_checks.py`).
- **Integration tests** (`test_api.py`) call the FastAPI application with `TestClient`. They create a case, reject a scan of an external URL, store a scan whose engine is replaced by a fixture result, update a finding in both the database row and the saved JSON, delete a case and its scans, cancel a running scan before the engine runs, and download the HTML and JSON reports.
- **Security testing** is the allow-list. External hosts, a port that is not on the lab list, and credentials embedded in a URL are rejected before any request leaves the machine. The suite does not send exploit payloads.
- **Usability and acceptance testing** is the manual walkthrough in section 3.3.2 (TC1 to TC4). Those steps use the React dashboard and, for the live scan, the Docker labs.

Run the automated suite from the repository root. Python 3.11 or newer is required. The run recorded below used Python 3.11.9.

Windows (PowerShell):

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\python -m pip install -r backend\requirements-dev.txt
backend\.venv\Scripts\python -m pytest backend/tests -v --cov=app --cov-report=term-missing
```

macOS and Linux:

```bash
python -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements-dev.txt
backend/.venv/bin/python -m pytest backend/tests -v --cov=app --cov-report=term-missing
```

`backend/requirements-dev.txt` installs the application dependencies plus `pytest` and `pytest-cov`. The `-r` line belongs inside that file. It is not a PowerShell command.

The manual walkthrough needs the labs, the API, and the dashboard:

```powershell
docker compose up -d
python scripts/fetch-lab-sources.py
backend\.venv\Scripts\python run.py
```

In a second terminal:

```powershell
npm install --prefix frontend
npm run dev --prefix frontend
```

Open http://127.0.0.1:5173. Confirm http://localhost:3000 and http://localhost:8081 load in a browser before TC2. Vite is bound to IPv4 and proxies `/api` to http://127.0.0.1:8000, so the API must be started first.

## 3.3.2 Summary of Results

The automated suite was run on 28 October 2026. Pytest 8.3.4 collected 26 tests and all 26 passed in 1.13 seconds. Statement coverage of the `app` package was 59%. The live crawler is left out of the automated suite on purpose, so the tests stay offline. The rows below link each result to the requirements in section 2.1.

| Test | Requirement | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|
| Automated suite | TR1, TR2, TR6 | The backend tests run locally, with no paid licence and no Docker, and they pass. | 26 passed. The suite used a temporary SQLite database and did not contact a lab host. | Pass |
| Allow-list rejects an external target | FR9 | `https://example.com`, a private LAN address, `localhost` on a port outside the lab list, a URL that contains credentials, and `https://google.com` are blocked. | `validate_local_target` raised `TargetNotAllowed`. `POST /api/scans` with `https://google.com` returned HTTP 400 and the authorised-local-labs message. No scan row was created. | Pass |
| Lab URLs are accepted | FR8 | Juice Shop, DVWA, and the Docker host names on the lab ports are accepted. | `http://localhost:3000`, `http://127.0.0.1:8081`, `http://juice-shop:3000`, and `http://dvwa:80` were accepted. A trailing slash was removed. | Pass |
| Static rules | FR1, FR2, FR3, FR4 | Fixture JavaScript and PHP files produce findings for injection, cross-site scripting, command injection, a hardcoded secret, and unsafe deserialisation. A file with no sink produces none. | Findings included CWE-89, CWE-95, CWE-79, CWE-78, CWE-798, and CWE-502. Each finding was marked static and carried a severity, description, recommendation, and location. The clean file produced an empty list. | Pass |
| Dynamic checks on a fixture response | FR1, FR4 | A page missing security headers, framing control, and cookie flags is reported. A hardened page is not. A reflected CORS origin and a readable `/.env` response are reported. | `analyse_pages` and `cors_finding` returned those findings, including CWE-693, CWE-1021, CWE-614, CWE-942, and CWE-538. These checks used fake responses, not the Docker targets. | Pass |
| Case persistence | FR6, FR7, TR2 | Creating a case returns a unique case id, and reading that case returns the saved fields. | `POST /api/cases` returned HTTP 200 and a `case_id` beginning with `CASE-`. `GET /api/cases/{id}` returned the same title, application, and notes. A title shorter than 3 characters returned HTTP 422. | Pass |
| Scan history | FR5, FR6 | A completed scan is stored and can be listed again for its case. | A scan with a fixture engine result was stored as completed. `GET /api/scans?case_id=` returned that scan, including the finding id. | Pass |
| Finding triage | FR4, TR2 | Marking a finding as a false positive updates the database row and the stored scan JSON. | `PATCH /api/scans/{id}/findings/{finding_id}` set the status to `false_positive` in both places. | Pass |
| Report export | FR10 | HTML and JSON downloads match the stored findings, and the HTML file can be opened on its own. | `report.json` was returned as an attachment and contained the findings. `report.html` was `text/html` and included the same finding title. | Pass |
| TC1. Allow-list in the dashboard | FR9, UR1 | On New scan, choose Custom localhost URL, enter `https://google.com`, and start the scan. The page shows the local-lab error. The Juice Shop and DVWA buttons do not send a custom URL. | The API rejection is the automated row above. The dashboard step is the manual confirmation of the same error text. | Pass (API). Manual UI check is the walkthrough. |
| TC2. Juice Shop scan | FR1, FR8, TR5 | Scan `http://localhost:3000` and wait until the status is completed. `live_check.reachable` is true and at least one finding has detection type dynamic. | Not part of pytest. Run this only after `docker compose up -d`. Catalog findings can appear even when the container is down, so reachability is the check that the live crawl ran. Static findings also require `python scripts/fetch-lab-sources.py`. | Manual |
| TC3. Cases and scan history | FR5, FR6, UR3 | Cases and Scan history show the TC2 scan, and opening it shows the same findings. | The automated history test stored and reloaded a scan by case id. The tab labels in the dashboard are Cases and Scan history. | Pass (API reload). Manual check confirms the two tabs. |
| TC4. Export from the scan page | FR10, UR2 | Export HTML and Export JSON download `{scan_id}.html` and `{scan_id}.json`. The HTML file opens offline and lists the same finding titles as the JSON. | The automated report test downloaded both formats and found the finding title in the HTML. The buttons on the scan detail page are Export HTML and Export JSON. | Pass (API). Manual check confirms the download from the page. |
