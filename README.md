# PRISM — Prioritized Risk Intelligence and Scoring Matrix

A web-based vulnerability prioritization tool for small analyst teams. Analysts score vulnerabilities across six dimensions using the CARVER methodology, producing a risk tier (LOW / MEDIUM / EMERGENCY), a shareable email report, and a persistent assessment log.

---

## Table of Contents

1. [Tech Stack](#tech-stack)
2. [Scoring Methodology (CARVER)](#scoring-methodology-carver)
3. [Features](#features)
4. [Workflow](#workflow)
5. [Local Launcher](#local-launcher)
6. [SharePoint Export Workflow](#sharepoint-export-workflow)
7. [API Reference](#api-reference)
8. [User Management](#user-management)
9. [Setup — Development](#setup--development)
10. [Setup — Production](#setup--production)
11. [File Structure](#file-structure)
12. [Security Status](#security-status)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Web framework | Flask 3.1 |
| WSGI server (production) | gunicorn 21+ |
| Reverse proxy / TLS | nginx (see `nginx.conf`) |
| Database | SQLite (WAL mode, single file) |
| Password hashing | Werkzeug `pbkdf2:sha256` |
| HTML sanitization | nh3 0.2+ (Rust-backed) |
| Rate limiting | flask-limiter 3.5+ (in-memory, per-worker) |
| Excel export | openpyxl 3.1+ |
| Frontend | Vanilla JS, no build step |

---

## Scoring Methodology (CARVER)

PRISM applies the CARVER framework — a six-dimension model for scoring the priority of a vulnerability or threat. Each dimension is scored **1–5**; the six scores are summed for a **total of 6–30**.

| Letter | Dimension | Question |
|---|---|---|
| **C** | Criticality | How vital is the asset? How severe would its loss be? |
| **A** | Accessibility | How easily can an adversary reach the target? |
| **R** | Recoverability | How much time and effort is needed to restore after an attack? |
| **V** | Vulnerability | Does the target have exploitable weaknesses? |
| **E** | Effect | What are the broader, systemic consequences of a successful attack? |
| **R²** | Recognizability | Can an adversary easily identify and distinguish the target? |

### Risk Tiers

| Score | Tier | Recommended Action |
|---|---|---|
| 6 – 12 | **LOW** | Standard monitoring; patch in normal cycle |
| 13 – 24 | **MEDIUM** | Elevated attention; patch in current cycle; brief stakeholders |
| 25 – 30 | **EMERGENCY** | Immediate response; compensating controls; executive notification |
| — | **NOT_AFFECTED** | Asset confirmed not affected; CARVER scoring skipped; logged for audit trail |

> **Note:** Total score and risk tier are computed server-side. Client-supplied values are ignored.

---

## Features

### Header

- **PRISM branding** — optical prism SVG icon (white input ray dispersing into a five-color spectrum) with the name "PRISM" and its full acronym beneath it
- **SBOM button** — left of "Signed in as"; opens a modal listing all direct Python dependencies with their resolved installed versions (CISA software supply chain best practice); data served from `GET /api/sbom`
- **Signed in as** — shows the authenticated username, populated via `GET /api/me` on page load
- **Sign out** — flushes the browser's cached Basic Auth credentials

### Assessment Form (4-step wizard)

**Step 1 — Metadata**
- Analyst name (required)
- Assessment date (auto-filled to today, read-only)
- CVE identifier (optional)
- Vulnerability / threat name (required)
- Affected system / application (optional) — dropdown includes **Not Affected** option; selecting it hides the CARVER steps, reveals a "Confirmed By" field, and allows the assessment to be logged directly from Step 1 with a `NOT_AFFECTED` risk tier
- **Confirmed By** (required when Not Affected is selected) — person or team that verified the organisation is not affected
- **Asset Owner / Team** (optional) — configured dropdown; analysts select from a predefined list or choose "Other (specify below)" for free-text entry
- **Business Unit** (optional) — configured dropdown; same structure as Asset Owner / Team
- Threat actor (optional)
- MITRE ATT&CK technique(s) (optional)
- VPR score from scanner (optional)
- **Source Reports** (optional) — free-text field for vulnerability advisories, intelligence reports, and references; appears in exports immediately after VPR Score
- Suggested documentation checklist (affected versions, vendor advisory link, internal ticket, detection coverage, regulatory scope)

> **Configuring dropdowns:** The Asset Owner / Team and Business Unit options are defined as arrays near the top of `templates/index.html` (`OWNER_TEAMS` and `BUSINESS_UNITS`). Update these arrays before production deployment.

**Step 2 — Pre-Assessment Questions**

Three yes/no questions that inform CARVER score suggestions:
1. Is the vulnerability actively being exploited in the wild?
2. Is there a public proof-of-concept (PoC) exploit available?
3. Does the vulnerability affect an externally-facing asset?

Answers appear as labeled tags in the final report and all export formats.

**Step 3 — CARVER Matrix**

- Five-option selector per dimension (Minimal / Minor / Moderate / Major / Critical, labeled and scored 1–5)
- Live score display per dimension
- **Analyst Note field per dimension** — optional free-text textarea beneath each scoring card so the analyst can record *why* a particular score was selected (context, caveats, supporting evidence). Notes are stored in the database, shown in the Step 4 report, included in the email report, and exported in both CSV and Excel formats
- Auto-suggestion of V and A scores based on pre-assessment answers, with a warning banner; suggestions are overridable
- Running total not shown until report generation (prevents anchoring)

**Step 4 — Risk Report**

- Total score with color-coded risk bar and pip indicator
- Risk tier badge (LOW / MEDIUM / EMERGENCY)
- Full metadata summary
- Pre-assessment indicator tags
- CARVER matrix score table with level labels and per-dimension analyst notes (shown as shaded sub-rows when a note is present)
- Recommended action text per tier
- **Email report** — table-based HTML formatted for Outlook and Gmail paste; per-dimension notes included as sub-rows; generated client-side, sanitized server-side before storage; report title and footer branded as PRISM
- **Print / Save PDF** — browser print dialog; default filename is dynamically set to `<CVE>_<Vuln_Name>_<YYYY-MM-DD>`

### Report Output

| Format | How |
|---|---|
| Email (Outlook / Gmail) | Click **Copy for Outlook** — rich HTML (including dimension notes) copied to clipboard; paste directly into email body |
| HTML file | Click **Download .html** — downloads the sanitized report as `<vuln_name>_prism_report.html` |
| Print / PDF | Click **Print / Save PDF** — opens browser print dialog with default filename `<CVE>_<VulnName>_<Date>` |

### Assessment Log

- Shared across all analysts (any logged-in user sees all entries)
- Columns: server timestamp (UTC), authenticated login, analyst name (self-reported), vulnerability + CVE, affected system, score, risk tier, actions
- Per-row **Report** button — downloads the stored HTML report for that assessment; works for both scored assessments and Not Affected entries
- Per-row **Remove** button — soft-deletes the assessment (only the analyst who created the record may remove it; returns 403 otherwise)
- **Export CSV** — all active assessments as a structured CSV including CARVER scores, level labels, per-dimension analyst notes, pre-assessment answers, and metadata; Source Reports field positioned with other metadata (after VPR Score)
- **Export Excel (.xlsx)** — same data as CSV in a formatted workbook: frozen header row (navy/white), Risk Tier cells color-coded by severity, score columns stored as integers, auto-fitted column widths; suitable for SharePoint list import
- **Export Today (.xlsx)** — same workbook format filtered to assessments with today's assessment date only; designed for the daily SharePoint append workflow; shows a clear alert if no assessments exist for today
- Every create, update, and delete is recorded in the `audit_log` table; view it with `python manage.py audit`

### Authentication

- HTTP Basic Auth on every route
- Credentials checked against hashed passwords in the `users` table
- **Sign out** link in the header (returns 401 to flush browser credential cache)
- Accounts managed via `manage.py` CLI — no in-app registration

---

## Workflow

```
Analyst opens browser → Basic Auth prompt
         ↓
Step 1: Fill metadata (vuln name, CVE, system, source reports, etc.)
         │
         ├── [System status = Not Affected]
         │         ↓
         │   Fill "Confirmed By" field
         │         ↓
         │   Click "Log Assessment" → POST /api/assessments (NOT_AFFECTED tier)
         │         ↓
         │   Record appears in Assessment Log
         │   (Report button generates a Not Affected summary)
         │
         └── [Normal path]
                   ↓
         Step 2: Answer 3 pre-assessment yes/no questions
                   ↓
         Step 3: Score each CARVER dimension (1–5)
                 Optionally add an Analyst Note explaining why
                   ↓
         Step 4: Review risk report (scores + notes displayed)
                   ├── Copy / download email report (branded as PRISM)
                   ├── Print to PDF (filename: CVE_VulnName_Date)
                   └── Click "Log Assessment" → POST /api/assessments
                             ↓
                        Record appears in Assessment Log
                        (shared with all analysts)
```

Analysts can navigate back from any step to adjust scores or notes before logging. Clicking **Log Assessment** is the only action that writes to the database.

---

## Local Launcher

The tool is designed to run as a **local server on the analyst's workstation**. The Flask process binds to `127.0.0.1:5000` and is only accessible from the machine running it.

### Windows

Double-click **`start_carver.bat`** from the project folder on the shared drive.

- Locates Python in the `.venv\Scripts\` virtual environment
- Starts Flask in the foreground of the CMD window
- Opens `http://127.0.0.1:5000` in the default browser automatically after 3 seconds
- **Closing the window stops the server**

**First-time setup** (run once in a Command Prompt from the project folder):

```cmd
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python manage.py init-db
.venv\Scripts\python manage.py add-user <username>
```

### Linux / macOS

Run **`start_carver.sh`** from the project folder:

```bash
bash start_carver.sh
# or, after making it executable once:
chmod +x start_carver.sh && ./start_carver.sh
```

- Locates Python in `.venv/bin/python3` (falls back to `bin/python3` for a root-level venv)
- Starts Flask via `exec` so Ctrl+C or closing the terminal stops the server cleanly
- Opens the browser automatically using `xdg-open` (Linux) or `open` (macOS); browser stderr is suppressed so it does not pollute the terminal

**First-time setup:**

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python manage.py init-db
.venv/bin/python manage.py add-user <username>
```

---

## SharePoint Export Workflow

The tool supports a **daily append workflow** for maintaining a running SharePoint list of all assessments without overwriting prior entries.

### First-time list creation

1. At the end of the first day, click **Export Excel (.xlsx)** in the Assessment Log
2. In SharePoint: **New → List → From Excel** → select the downloaded file
3. SharePoint infers column types (dates as dates, scores as integers, text as text)
4. The list is now established with the correct column structure

### Daily append (subsequent days)

1. At end of each day, click **Export Today (.xlsx)** in the Assessment Log
   - Downloads `prism_assessments_YYYY-MM-DD.xlsx` containing only that day's assessments
   - If no assessments were recorded today, a clear alert is shown instead of producing an empty file
2. Open the SharePoint list → **Edit in grid view** (Quick Edit)
3. Open the Excel file, select all data rows (skip the header row — columns already match)
4. Paste into the SharePoint grid → **Exit grid view** to save

Each day's records are appended; no previous entries are affected.

> **Column matching:** The Export Today file uses the same column headers as the full export. As long as the SharePoint list was created from the full export (step above), columns will align automatically on paste.

---

## API Reference

All endpoints require HTTP Basic Auth. The server stamps `authenticated_as` and `created_at` — clients cannot set or overwrite these fields.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the single-page application |
| `GET` | `/logout` | Returns 401 to flush browser credential cache |
| `GET` | `/api/me` | Returns `{"username": "<authenticated_login>"}` |
| `GET` | `/api/sbom` | Returns direct Python dependencies with resolved installed versions |
| `POST` | `/api/assessments` | Create a new assessment record |
| `PUT` | `/api/assessments/<id>` | Update analyst fields (403 if not the creator) |
| `GET` | `/api/assessments` | List all assessments (summary fields only) |
| `DELETE` | `/api/assessments/<id>` | Soft-delete an assessment (403 if not the creator) |
| `GET` | `/api/assessments/export` | Download all assessments as CSV |
| `GET` | `/api/assessments/export/xlsx` | Download all assessments as formatted Excel workbook |
| `GET` | `/api/assessments/export/xlsx?today=1` | Download today's assessments only as Excel (404 if none exist) |
| `GET` | `/api/assessments/<id>/report` | Download stored HTML report for one assessment |

All state-mutating requests (POST, PUT, DELETE) must include the header `X-Requested-With: XMLHttpRequest`. Requests missing this header are rejected with 403. The frontend sends it automatically.

### GET /api/sbom

Returns a JSON object with the UTC generation timestamp and the list of direct dependencies, each with its name, resolved installed version, and the original requirement constraint:

```json
{
  "generated": "2026-06-06T14:30:00Z",
  "components": [
    { "name": "flask",        "version": "3.1.3",  "constraint": "flask>=3.0"        },
    { "name": "werkzeug",     "version": "3.1.8",  "constraint": "werkzeug>=3.0"     },
    { "name": "nh3",          "version": "0.3.5",  "constraint": "nh3>=0.2"          },
    { "name": "gunicorn",     "version": "26.0.0", "constraint": "gunicorn>=21.0"    },
    { "name": "flask-limiter","version": "4.1.1",  "constraint": "flask-limiter>=3.5"},
    { "name": "openpyxl",     "version": "3.1.5",  "constraint": "openpyxl>=3.1"     }
  ]
}
```

Versions are resolved at runtime via `importlib.metadata` — they reflect the actual installed package versions, not the requirement constraints.

### POST / PUT payload shape

```json
{
  "date":          "2026-05-17",
  "analyst":       "J. Smith",
  "vuln_name":     "Apache Log4Shell RCE",
  "cve":           "CVE-2021-44228",
  "system":        "Customer Portal (prod)",
  "owner":         "Platform Engineering",
  "business_unit": "Corporate IT",
  "threat_actor":  "APT29",
  "mitre":         "T1190",
  "vpr_score":     "9.8 (Critical)",
  "notes":         "Vendor advisory: ...",
  "pre_q1":        "yes",
  "pre_q2":        "yes",
  "pre_q3":        "yes",
  "scores":        { "C": 5, "A": 5, "R1": 4, "V": 5, "E": 5, "R2": 4 },
  "levels":        { "C": "Critical", "A": "Critical", "R1": "Major", "V": "Critical", "E": "Critical", "R2": "Major" },
  "dim_notes":     { "C": "DR Priority 0 — core billing system", "A": "Fully internet-facing, no WAF", "R1": "", "V": "Active ITW + public PoC", "E": "", "R2": "" },
  "email_html":    "<html>...</html>",

  // Not Affected path — omit pre_q*, scores, levels, dim_notes, and email_html:
  "not_affected":  true,
  "confirmed_by":  "Security Team / J. Smith"
}
```

> `total_score` and `risk_tier` in the payload are **ignored** — the server computes them from `scores`. Each score must be an integer 1–5 or the request is rejected with 400.
>
> `dim_notes` values are optional per-dimension free-text strings; empty or missing keys are stored as NULL.
>
> When `not_affected` is `true`, `confirmed_by` is required. `pre_q1`/`pre_q2`/`pre_q3` default to `"n/a"` and `scores` are set to 0 server-side; the risk tier is recorded as `NOT_AFFECTED`.

---

## User Management

All user operations are performed via `manage.py` on the server. There is no in-app user registration.

```bash
python manage.py init-db                   # Create DB tables (first run only)
python manage.py add-user    <username>    # Create a new analyst account
python manage.py remove-user <username>    # Delete an account
python manage.py reset-password <username> # Change a user's password
python manage.py list-users                # List all accounts and creation dates
python manage.py audit                     # Print the last 200 audit log entries
python manage.py clear-assessments        # Hard-delete all assessments (admin use only)
```

Passwords are hashed with Werkzeug's `pbkdf2:sha256` scheme. Plain-text passwords are never stored or logged.

---

## Setup — Development

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialise the database (first run only)
python manage.py init-db

# 4. Create the first analyst account
python manage.py add-user analyst1

# 5. Start the server
#    Option A — launcher script (recommended, opens browser automatically):
bash start_carver.sh        # Linux/macOS
# start_carver.bat          # Windows (double-click)

#    Option B — gunicorn (mirrors production):
gunicorn -w 2 -b 127.0.0.1:5000 app:app

#    Option C — Flask dev server:
flask --app app run --port 5000
```

> **SECRET_KEY**: For local dev a random key is generated automatically on each start. For production, set the `PRISM_SECRET_KEY` environment variable (see Setup — Production step 4).

Open `http://localhost:5000` and authenticate with the credentials you just created.

---

## Setup — Production

### Prerequisites

- A Linux server with Python 3.11+ and nginx installed
- A domain name pointing to the server
- `certbot` for Let's Encrypt TLS certificates

### Steps

```bash
# 1. Clone / copy the project (do NOT copy the venv — recreate it)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Initialise the database and create users
python manage.py init-db
python manage.py add-user analyst1
# Repeat for each team member

# 3. Lock down the database file
chmod 600 data/carver.db

# 4. Set a stable secret key
echo "PRISM_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
# Load it before starting gunicorn, e.g. in your systemd service:
#   EnvironmentFile=/opt/carver-tool-server/.env

# 5. Configure nginx
sudo cp nginx.conf /etc/nginx/sites-available/prism
# Edit /etc/nginx/sites-available/prism — replace 'your.domain'
sudo ln -s /etc/nginx/sites-available/prism /etc/nginx/sites-enabled/prism
sudo nginx -t

# 6. Obtain TLS certificate
sudo certbot --nginx -d your.domain

# 7. Create a systemd service (example)
sudo tee /etc/systemd/system/prism.service > /dev/null <<EOF
[Unit]
Description=PRISM Risk Assessment Tool
After=network.target

[Service]
User=prism
WorkingDirectory=/opt/carver-tool-server
EnvironmentFile=/opt/carver-tool-server/.env
ExecStart=/opt/carver-tool-server/.venv/bin/gunicorn -w 2 -b 127.0.0.1:5000 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now prism
```

---

## File Structure

```
carver-tool-server/
├── app.py              # Flask application — routes, auth, DB helpers, sanitizers, SBOM endpoint
├── manage.py           # CLI — user management and DB initialisation
├── requirements.txt    # Python direct dependencies (Flask, gunicorn, nh3, openpyxl, …)
├── start_carver.sh     # Local launcher — Linux/macOS (starts server + opens browser)
├── start_carver.bat    # Local launcher — Windows  (starts server + opens browser)
├── nginx.conf          # nginx reverse-proxy template (edit domain + cert paths)
├── data/
│   └── carver.db       # SQLite database (permissions: 600, not committed to git)
└── templates/
    └── index.html      # Single-page application (HTML + CSS + vanilla JS)
```

### Database tables

**`users`** — analyst accounts

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| username | TEXT UNIQUE | Case-insensitive |
| password | TEXT | Werkzeug pbkdf2 hash |
| created_at | TEXT | UTC, server-stamped |

**`assessments`** — completed risk assessments

| Column | Notes |
|---|---|
| id, created_at, authenticated_as | Server-stamped; immutable after creation |
| date, analyst, cve, vuln_name, system, owner, business_unit, threat_actor, mitre, vpr_score | Analyst-supplied metadata |
| notes | "Source Reports" in the UI — free-text field for advisories and references; exported immediately after VPR Score |
| pre_q1, pre_q2, pre_q3 | Pre-assessment answers ("yes" / "no") |
| score_c, score_a, score_r1, score_v, score_e, score_r2 | CARVER dimension scores (1–5, server-validated) |
| level_c … level_r2 | Human-readable level labels (e.g. "Critical") |
| note_c, note_a, note_r1, note_v, note_e, note_r2 | Per-dimension analyst notes explaining score rationale (optional free text) |
| total_score, risk_tier | Server-computed from scores; `risk_tier` is `LOW`, `MEDIUM`, `EMERGENCY`, or `NOT_AFFECTED` |
| email_html | Sanitized HTML report artifact; populated for both scored and Not Affected assessments |
| not_affected | `1` if the asset was confirmed not affected; `0` otherwise |
| confirmed_by | Person/team that verified the asset is not affected (required when `not_affected = 1`) |
| deleted_at, deleted_by | Soft-delete fields; NULL means the record is active |

**`audit_log`** — immutable record of all data mutations

| Column | Notes |
|---|---|
| id, timestamp | Auto-assigned; UTC server time |
| actor | Authenticated username who performed the action |
| action | `create`, `update`, or `delete` |
| assessment_id | Foreign key to `assessments.id` |
| detail | Vuln name at time of action (context for deleted records) |

---
