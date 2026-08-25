# WebSET — Website Security Evaluation Tool

Demo prototype of a local-only website security evaluation tool: scan Juice Shop or DVWA, store results in a case database, review them on a dashboard, and export an evaluation report.

## Quick start

Requires Python 3.11+ and Node.js 18+.

```powershell
# Dashboard + API (from the repo root)
.\run.ps1
```

Or in two terminals:

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\pip install -r backend\requirements.txt
python run.py
```

```powershell
npm install --prefix frontend
npm run dev --prefix frontend
```

Open **http://127.0.0.1:5173**. The API is **http://127.0.0.1:8000**. If `localhost` works but `127.0.0.1` does not, use `127.0.0.1` — Vite is bound to IPv4.

Optional lab targets (local Docker only):

```powershell
docker compose up -d
```

Juice Shop is `http://localhost:3000`, DVWA is `http://localhost:4280`. Scans work without Docker: the engine still records the training-app catalog and notes that the live host was unreachable.

**Scope:** the scanner only accepts localhost / Docker lab hosts. It does not send exploit payloads. Catalog findings describe vulnerability *classes* for teaching apps, with header fingerprinting as the live check.

The JSON contract lives at `shared/scan-result.schema.json`.

---

> Original project brief (kept below for context).

## 1. Overview & Purpose

WebSET is a web application security scanning tool. Users upload or point the tool at a web application, and it runs static and dynamic analysis to identify vulnerabilities, bugs, and weaknesses. Findings are mapped against established security frameworks — **OWASP Top 10**, **NIST**, and **SANS** — and presented in a dashboard GUI, with results also available as an exportable evaluation report.

The core problem it solves: enterprise-grade scanning tools (Burp Suite Professional, Veracode, etc.) are priced out of reach for students, small teams, and startups — who are often the ones shipping insecure code. WebSET aims to give these users a free, repeatable, easy-to-understand scanning workflow instead of manual checking.

Secondary use case: a teaching aid. Because it's built and tested against deliberately vulnerable apps (OWASP Juice Shop, DVWA), it can demonstrate to students/CTF participants how coding flaws show up in scan results and how severity is assessed.

## 2. Core Features (for the demo/prototype)

Build these as the primary functional pieces:

1. **Scanning engine**
   - Static analysis (code-level) and dynamic analysis (running application) against a target web app.
   - Detection mapped to OWASP Top 10 categories (also referencing NIST/SANS where relevant).
   - Positive/negative vulnerability detection with severity scoring so critical issues surface first.
   - Only scans **authorised local targets** — designed to run against OWASP Juice Shop and DVWA in Docker, never live/external targets.

2. **Dashboard GUI**
   - Vulnerability totals
   - Detected technology stack(s)
   - Critical vulnerability mapping / severity breakdown
   - Scan history / "scans conducted" view
   - Drill-down into individual vulnerability details

3. **Case management / database**
   - Stores scan history with Case IDs, Scan IDs, and user profiles.
   - Supports querying scan history by case, enabling trend analysis over time (e.g., most common vulnerabilities, most-scanned tech stacks).

4. **Reporting**
   - Generates an evaluation report from scan results (exportable, not just on-screen).

5. **Standard data contract**
   - All scan results should be normalized into one agreed **JSON format** early on — this is the contract between the scanner (backend) and the dashboard (frontend), and what gets persisted to the database.

## 3. Suggested Tech Stack

- **Backend / scanning engine:** Python (primary), Java where relevant
- **Frontend / dashboard:** HTML, CSS, JavaScript, PHP (per original team's skillset — feel free to substitute a modern framework, e.g. React, for the demo)
- **Database:** relational DB for case management (schema: Case IDs, Scan IDs, user profiles, scan results)
- **Test targets:** OWASP Juice Shop and DVWA, run locally via Docker

## 4. Success Criteria / What "good" looks like

| Criteria | Description |
|---|---|
| Detection accuracy | Correct positive/negative results when scanning a target app |
| Usability | Non-technical users should be able to operate it and understand the output |
| Vulnerability coverage | Measured against OWASP Top 10 — track how many categories are actually detectable |
| Competitive benchmark | Compare functionality/usability against existing tools: ImmuniWeb, Pentest-tools, SSLTrust |

## 5. Development Approach

- Agile, short sprints.
- Lock the JSON scan-result format early (this unblocks frontend/backend integration).
- Use **dummy scan data** to integrate frontend and backend early, before the real scanner is finished — reduces integration risk.
- Test only against local, authorised targets (Juice Shop, DVWA in Docker) — real vulnerabilities, known baseline, legal to scan.
- Prioritize features with MoSCoW (Must/Should/Could/Won't) if scope needs trimming for the demo.

## 6. Scope Notes / Known Limitations to Design Around

- **Not everything is statically detectable.** Architectural issues like Broken Access Control and Insecure Design won't be caught by code scanning alone — need dynamic scanning, and some categories may be out of scope entirely. Document coverage honestly rather than overclaiming.
- **Dynamic scanning requires a live target you control** — scanning apps you don't own is illegal, hence Juice Shop/DVWA running locally in Docker.
- **Tech stack coverage should be scoped down** for a prototype — pick 1–2 stacks to fully support rather than trying to cover everything.
- **False positives** are the main risk with static analysis — plan for tuning rules and adding severity scoring so real issues aren't buried.

## 7. Suggested Build Priority for a Demo

1. Define the JSON scan-result schema.
2. Stand up Juice Shop/DVWA in Docker as the test target.
3. Build a minimal Python scanner that detects a handful of OWASP Top 10 issues against the test target and outputs the agreed JSON.
4. Build the dashboard GUI against dummy JSON data first, then wire it to the real scanner output.
5. Add the database/case management layer (store + query scans by Case ID).
6. Add report export.
7. Polish: severity scoring, framework mapping display (OWASP/NIST/SANS references), usability pass.

---
*Source: adapted from a UTS Cybersecurity Capstone (41909) Portfolio Component 3 proposal for "WebSET" by team Vector Zero.*