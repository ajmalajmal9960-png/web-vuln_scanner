# Sentinel — Web Vulnerability Scanner (Minor Project)

A full-stack, real-time web vulnerability scanner covering SQL Injection,
Cross-Site Scripting (XSS), CSRF, insecure security headers, insecure
cookies, and server information disclosure — with a built-in **offline
demo/preview mode** so you can see a full report instantly, no live target
required.

> **⚠️ Authorized use only.** Only scan applications you own, or deliberately
> vulnerable *training* targets such as **OWASP WebGoat** and **OWASP
> NodeGoat** run locally. Scanning any other website without written
> permission is illegal in most jurisdictions (Computer Misuse Act / IT Act
> 2000 in India / CFAA in the US, etc.).

---

## What's new in this version

- **More accurate detection**
  - Expanded SQL error signatures across MySQL, PostgreSQL, Oracle, MSSQL, SQLite, and MongoDB
  - Time-based blind SQLi now compares against a **live baseline response time** for that specific form, instead of a fixed threshold — far fewer false positives on naturally slow endpoints
  - XSS detection uses a **unique per-request canary token**, so a match can never be confused with unrelated page content
  - New checks: **insecure cookie flags** (HttpOnly / Secure / SameSite) and **server/version information disclosure** (`Server`, `X-Powered-By`, etc.)
  - New **Critical** severity tier for confirmed SQL injection with a database error signature
- **Real-time crawling** — a bounded, polite, same-domain crawl (depth 1, up to 6 pages) now tests forms across multiple pages of a real site (login, search, contact, etc.), not just the one URL you paste in
- **URL parameter testing** — if the target URL itself has query parameters (`?q=...`), those are tested directly too, not just `<form>` elements
- **Offline demo/preview mode** — a "Try demo scan" button runs the *exact same* detection functions against a built-in simulated dataset (modeled on WebGoat/NodeGoat), so you always have a full, correct report to show, with zero network dependency
- **No more flask-cors dependency** — CORS headers are now added manually in three lines, removing an external package that could fail to install and break the whole app

---

## How it maps to your 10-point guidance

| # | Guidance point | Where it's implemented |
|---|---|---|
| 1 | Define scope (SQLi, XSS, CSRF, headers) | `backend/scanner.py` — payload lists, `SECURITY_HEADERS`, `INFO_DISCLOSURE_HEADERS` |
| 2 | Select target URLs (test sites only) | Entered in the dashboard, defaults to local WebGoat/NodeGoat; demo mode uses a built-in dataset |
| 3 | Collect request/response data via HTTP libraries | `requests` in `scanner.get_page` / `submit_form` / `discover_pages` |
| 4 | Preprocess inputs (parameters/forms) | `scanner.extract_forms`, `scanner.extract_url_params` using `BeautifulSoup` |
| 5 | Rule-based vulnerability detection | `check_sql_injection`, `check_xss`, `check_csrf`, `check_headers`, `check_cookies`, `check_info_disclosure` |
| 6 | Simulate attack payloads | `SQLI_PAYLOADS`, `XSS_PAYLOAD_VARIANTS` |
| 7 | Analyze server responses | error-signature regex matching, baseline-relative timing, canary-token reflection |
| 8 | Generate severity reports | `run_full_scan` sorts findings Critical → High → Medium → Low |
| 9 | Store results | `backend/database.py` → SQLite (`scans.db`), tagged `live` or `demo` |
| 10 | Validate manually | Dashboard shows exact payload + evidence + page crawled, so you can re-check by hand |

---

## Tech stack

- **Backend:** Python 3, Flask, `requests`, `BeautifulSoup4` (no flask-cors needed)
- **Frontend:** HTML, CSS, vanilla JavaScript (fetch API) — served by Flask, no build step
- **Database:** SQLite by default (zero-config, one file). MySQL is a drop-in swap — see §6.

---

## Project structure

```
webvuln-scanner/
├── backend/
│   ├── app.py            # Flask API + serves frontend + demo-scan endpoint
│   ├── scanner.py         # Live detection engine (SQLi/XSS/CSRF/headers/cookies/crawling)
│   ├── demo_data.py        # Offline preview dataset, reuses scanner.py's own detectors
│   ├── database.py        # SQLite persistence (tags scans as live/demo)
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
└── README.md
```

---

## 1. Try it instantly — no setup needed for a preview

Click **"Try demo scan (offline preview)"** on the dashboard. This runs the
real detection engine (`scanner.py`'s own signature lists and matching logic)
against a fixed, simulated dataset modeled on WebGoat/NodeGoat, so you get a
complete, accurate, severity-graded report in under a second — perfect for a
project demo or to show your instructor before doing a live scan.

## 2. Setting up a safe live target to scan

```bash
# OWASP WebGoat (Java) — https://github.com/WebGoat/WebGoat
docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat

# OWASP NodeGoat (Node.js/MongoDB) — https://github.com/OWASP/NodeGoat
git clone https://github.com/OWASP/NodeGoat.git
cd NodeGoat
docker-compose up
```

WebGoat will be at `http://localhost:8080/WebGoat`, NodeGoat typically at
`http://localhost:4000`. Paste the base URL into the dashboard — the scanner
will automatically crawl a few linked pages and test every form and URL
parameter it finds.

## 3. Running the project

```bash
cd webvuln-scanner/backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** — try the demo scan first, then paste your
WebGoat/NodeGoat URL and click **Run scan**. Results, severity summary, and
history are all stored in `backend/scans.db` and shown live in the UI.

---

## 4. Using MySQL instead of SQLite (optional)

If your course requires MySQL specifically:

```bash
pip install mysql-connector-python
```

Replace `get_connection()` in `database.py`:

```python
import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost", user="root", password="yourpassword", database="vuln_scanner"
    )
```

Change `?` placeholders to `%s` in the SQL statements (MySQL's paramstyle),
and create the `vuln_scanner` database and `scans` table manually first
(same columns as the `CREATE TABLE` in `init_db()`, plus the `mode` column).

---

## 5. Datasets & reference links

**Preview/demo dataset:** `backend/demo_data.py` — simulated request/response
pairs modeled on OWASP WebGoat and NodeGoat behavior, run through the same
detection functions as the live scanner.

**Live test targets:**
- OWASP WebGoat — https://github.com/WebGoat/WebGoat
- OWASP NodeGoat — https://github.com/OWASP/NodeGoat

**Reference material:**
- OWASP Top 10 — https://owasp.org/www-project-top-ten/
- Nikto (reference scanner to compare findings against) — https://github.com/sullo/nikto
- OWASP ZAP (reference scanner) — https://github.com/OWASP/owasp-zap

---

## 6. Extending it further (good "future scope" section for your report)

- Add more payload families (LFI/RFI, command injection, open redirect)
- Increase crawl depth beyond 1 hop, with a visited-page cap
- Add authenticated scanning (session cookies / login flow)
- Export PDF/CSV reports from scan history
- Add a rate-limit / concurrency control for large sites

---

## 7. Uploading this project to GitHub

From inside the `webvuln-scanner` folder:

```bash
# 1. Initialize git (only once)
git init

# 2. .gitignore already excludes venv/DB files
# 3. Stage and commit everything
git add .
git commit -m "Initial commit: Sentinel web vulnerability scanner minor project"

# 4. Create a new EMPTY repository on github.com (no README/license,
#    so it doesn't conflict with what you already have locally), then:
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```

After that, any future changes are just:

```bash
git add .
git commit -m "Describe what changed"
git push
```

**Tip:** create the empty repo first at github.com → "New repository" →
give it a name → do **not** check "Add a README" → copy the HTTPS URL it
shows you into the `git remote add origin ...` command above.
