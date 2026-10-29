# WebSET implementation roadmap

This document is the pick-up-ready design for work that was **not** built in the scanner + lifecycle pass. File paths refer to the current tree.

## 1. Auth and multi-user

**Goal:** replace the seeded demo profiles with real login, ownership, and roles.

### Suggested design
- Add password hash column on [`backend/app/models.py`](../backend/app/models.py) `User` (`password_hash`, `role` already exists: `analyst` / `instructor` / later `admin`).
- Use session cookies (HttpOnly, SameSite=Lax) or JWT in an HttpOnly cookie. Prefer server sessions in SQLite (`sessions` table) so logout is immediate.
- New router `backend/app/routers/auth.py`:
  - `POST /api/auth/register` (optional; can disable and seed the first instructor)
  - `POST /api/auth/login` `{email, password}`
  - `POST /api/auth/logout`
  - `GET /api/auth/me`
- FastAPI dependency `get_current_user` reads the cookie; inject it on cases/scans/reports.
- Ownership rules:
  - Analysts see and mutate their own cases/scans.
  - Instructors see all cases (teaching aid).
  - Creating a case always sets `owner_id` from the session; drop the client-supplied owner unless the caller is an instructor.
- Frontend: login page, persist nothing in localStorage except UI prefs, hide Delete/Edit when not owner.

### Libraries
- `pwdlib` or `passlib[bcrypt]` for hashes.
- Starlette `SessionMiddleware` **or** a signed cookie via `itsdangerous`.

### Out of scope unless required
- OAuth/SSO, email verification, password reset. Document as later.

---

## 2. Reporting upgrades

**Today:** HTML + JSON download from [`backend/app/routers/reports.py`](../backend/app/routers/reports.py) and [`backend/app/templates/report.html`](../backend/app/templates/report.html).

### PDF export
- Render the existing Jinja HTML and print to PDF with `playwright` (headless Chromium) **or** WeasyPrint if you want no browser.
- Add `GET /api/scans/{id}/report.pdf` with `Content-Disposition: attachment`.
- Frontend: third button next to HTML/JSON on [`frontend/src/pages/ScanDetail.jsx`](../frontend/src/pages/ScanDetail.jsx).

### NIST / SANS in the report
- The scan JSON already stores `nist` and `sans` on each finding.
- Extend `report.html` with a coverage table grouped by NIST control and SANS/CWE, mirroring the OWASP grid.
- Add `coverage.nist` / `coverage.sans` in [`shared/scan-result.schema.json`](../shared/scan-result.schema.json) if you want them first-class (bump `schema_version`).

### False-positive handling
- Reports should include a “triage” column and optionally omit `false_positive` findings (query param `?include_false_positives=false`).

---

## 3. Tests and CI

### Backend (pytest)
Add `backend/tests/` with `conftest.py` that points `DB_PATH` at a temp SQLite file.

Must-cover:
- `validate_local_target` allow-list / port / credential rejection ([`backend/app/scanner/allowlist.py`](../backend/app/scanner/allowlist.py)).
- Static rules against fixture files (`backend/tests/fixtures/js_sinks.js`, `php_sinks.php`) — assert CWE-89, eval, unserialize, etc.
- Dynamic checks against `httpx` mock transports (missing headers, Set-Cookie flags, canary reflection).
- API: create case, start scan with a mocked `run_scan`, PATCH finding status updates **both** `Finding.status` and `result_json`, DELETE case cascades.
- Cancel: set flag, `run_scan` returns `status=cancelled`.

Dev extra: `httpx==` already present; add `pytest` and `pytest-asyncio` to requirements-dev.

### Frontend
- Add Vitest + React Testing Library for `api.js` error handling and CaseDetail save/delete confirm path.
- Keep `npm run build` as the smoke test if unit tests are thin.

### GitHub Actions
`.github/workflows/ci.yml`:
1. `pip install -r backend/requirements.txt -r backend/requirements-dev.txt && pytest backend/tests`
2. `npm ci --prefix frontend && npm run build --prefix frontend`
3. Optional: `ruff check backend` / `eslint`

Do **not** scan external hosts in CI. Use fixtures only.

---

## 4. Packaging and deployment

WebSET is a local lab tool; “production” means “easy to run on a student’s machine”.

### Single image (API + built UI)
- `Dockerfile` at repo root:
  - Stage 1: `npm run build` in `frontend/`
  - Stage 2: Python 3.12-slim, install `backend/requirements.txt`, copy `backend/`, `shared/`, `frontend/dist`
  - `CMD uvicorn app.main:app --host 0.0.0.0 --port 8000` with `PYTHONPATH=backend`
- Persist SQLite with a volume on `/data/webset.db` (set `DB_PATH`).

### Compose
Extend [`docker-compose.yml`](../docker-compose.yml) with a `webset` service next to Juice Shop and DVWA:
- `webset` depends_on juice-shop, dvwa
- Scan URLs inside the compose network: `http://juice-shop:3000`, `http://dvwa:80` (already on `ALLOWED_HOSTS`)
- Optional bind of `./labs` for static analysis

### Lab sources in the image
Either:
- document `docker compose exec webset python scripts/fetch-lab-sources.py`, or
- a build arg `INCLUDE_LAB_SOURCES=1` that clones during image build (large). Prefer the exec path.

---

## 5. Competitive benchmark write-up

Capstone success criterion: compare functionality/usability against ImmuniWeb, Pentest-tools, and SSLTrust.

Suggested location: `docs/benchmark.md` with a table:

| Capability | WebSET | ImmuniWeb | Pentest-tools | SSLTrust |
|---|---|---|---|---|
| Price / audience | Free, local, teaching | Commercial SaaS | Freemium SaaS | Commercial |
| Authorised-target enforcement | Localhost allow-list | Cloud scan of customer URL | Cloud | Cloud |
| Static analysis | In-repo rules for JS/PHP labs | Varies (DAST-heavy) | Limited | Limited |
| Dynamic (non-exploit) | Crawl, headers, cookies, CORS, canary | Full DAST | DAST + extras | SSL/config focus |
| OWASP mapping | Top 10 on every finding | Yes | Yes | Partial |
| Case management / triage | Cases, history, FP/accept | Yes | Yes | Limited |
| Exploit payloads | Never | Often (authenticated DAST) | Often | N/A |
| Offline / air-gapped lab | Yes | No | No | No |

Fill cells after a 30-minute hands-on of each vendor’s public trial/docs. Be honest: WebSET is not a Burp/Veracode replacement; it is a **repeatable teaching and student-lab evaluator** with real static+dynamic checks on two stacks.

---

## 6. Optional scanner follow-ups

- Turn on supplemental SAST with `WEBSET_EXTERNAL_SAST=1` if `semgrep` / `bandit` are on PATH ([`backend/app/config.py`](../backend/app/config.py)).
- Authenticated DVWA crawl (login once, reuse PHPSESSID) — still no payloads.
- SPA route discovery for Juice Shop via `main.js` string extraction.
- Finding fingerprint stable across scans so triage can carry forward.
