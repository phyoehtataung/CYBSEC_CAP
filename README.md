# WebSET — Website Security Evaluation Tool
## 1. Overview & Purpose

WebSET is a web application security scanning tool. Users upload or point the tool at a web application, and it runs static and dynamic analysis to identify vulnerabilities, bugs, and weaknesses. Findings are mapped against established security frameworks — **OWASP Top 10**, **NIST**, and **SANS** — and presented in a dashboard GUI, with results also available as an exportable evaluation report.

## 2. Core Features 

1. **Scanning engine**
   - Static and dynamic analysis (running application) against a target web application.
   - Detection mapped to OWASP Top 10 categories (also referencing NIST/SANS where relevant).
   - Positive/negative vulnerability detection with severity scoring so that critical issues surface first.
   - Only scans **authorised local targets**, designed to run against OWASP Juice Shop and DVWA in Docker.

2. **Dashboard GUI**
   - Vulnerability totals
   - Detected technology stack(s)
   - Critical vulnerability mapping / severity breakdown
   - Scan history view

3. **Case management / database**
   - Stores scan history with Case IDs, Scan IDs, and user profiles.
   - Supports querying scan history by case that allows for trend analysis (e.g., most common vulnerabilities, most-scanned tech stacks).

4. **Reporting**
   - Generates an exportable evaluation report from scan results.

## 3. Tech Stack
- **Backend:** (Scanning Engine) - Python (primary), Java where relevant
- **Frontend:** (Dashboard) - HTML, CSS, JavaScript, React
- **Database:** relational DB for case management (schema: Case IDs, Scan IDs, user profiles, scan results)
- **Test targets:** OWASP Juice Shop and DVWA, run locally via Docker

## 4. Success Criteria
- Detection accuracy: Correct positive/negative results when scanning the targeted web application
- Usability: Non-technical stakeholders should be able to use the tool and understand the vulnerability scan
- Vulnerability coverage: Measured against OWASP Top 10

## 5. Development Approach
- Agile sprints
- Test only against local and authorised targets such as Juice Shop

  

## Quick start

Requires Python 3.11+ and Node.js 18+.

Run PowerShell
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

Juice Shop is `http://localhost:3000`, DVWA is `http://localhost:4280`. Scans work without Docker: static analysis still runs if sources are cloned, and the training-app catalog fills OWASP classes the live checks did not confirm.

---
*Source: adapted from a UTS Cybersecurity Capstone (41909) Portfolio Component 3 proposal for "WebSET" by team Vector Zero.*
