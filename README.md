# CARVER Risk Assessment Tool

A web-based vulnerability prioritization tool for small analyst teams. Analysts score vulnerabilities across six dimensions using the CARVER methodology, producing a risk tier (LOW / MEDIUM / EMERGENCY), a shareable email report, and a persistent assessment log.

---

## Table of Contents

1. [Tech Stack](#tech-stack)
2. [CARVER Methodology](#carver-methodology)
3. [Features](#features)
4. [Workflow](#workflow)
5. [API Reference](#api-reference)
6. [User Management](#user-management)
7. [Setup — Development](#setup--development)
8. [Setup — Production](#setup--production)
9. [File Structure](#file-structure)
10. [Security Status](#security-status)

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
| HTML sanitization | nh3 0.3 (Rust-backed) |
| Rate limiting | flask-limiter 4+ (in-memory, per-worker) |
| Frontend | Vanilla JS, no build step |

---

## CARVER Methodology

CARVER is a six-dimension framework for scoring the priority of a vulnerability or threat. Each dimension is scored **1–5**; the six scores are summed for a **total of 6–30**.

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

> **Note:** Total score and risk tier are computed server-side. Client-supplied values are ignored.

---

## Features

### Assessment Form (4-step wizard)

**Step 1 — Metadata**
- Analyst name (required)
- Assessment date (auto-filled to today, read-only)
- CVE identifier (optional)
- Vulnerability / threat name (required)
- Affected system / application (optional)
- Asset owner / team (optional)
- Business unit (optional)
- Threat actor (optional)
- MITRE ATT&CK technique(s) (optional)
- VPR score from scanner (optional)
- Notes / references free-text field (optional)
- Suggested documentation checklist (affected versions, vendor advisory link, internal ticket, detection coverage, regulatory scope)

**Step 2 — Pre-Assessment Questions**

Three yes/no questions that inform CARVER score suggestions:
1. Is the vulnerability actively being exploited in the wild?
2. Is there a public proof-of-concept (PoC) exploit available?
3. Does the vulnerability affect an externally-facing asset?

Answers appear as labeled tags in the final report and CSV export.

**Step 3 — CARVER Matrix**

- Five-option selector per dimension (Negligible/Minor/Moderate/Significant/Severe, labeled and scored 1–5)
- Live score display per dimension
- Auto-suggestion of V and A scores based on pre-assessment answers, with a warning banner; suggestions are overridable
- Running total not shown until report generation (prevents anchoring)

**Step 4 — Risk Report**

- Total score with color-coded risk bar and pip indicator
- Risk tier badge (LOW / MEDIUM / EMERGENCY)
- Full metadata summary
- Pre-assessment indicator tags
- CARVER matrix score table with level labels
- Recommended action text per tier
- **Email report** — table-based HTML formatted for Outlook and Gmail paste; generated client-side, sanitized server-side before storage

### Report Output

| Format | How |
|---|---|
| Email (Outlook / Gmail) | Click **Copy for Outlook** — rich HTML copied to clipboard; paste directly into email body |
| HTML file | Click **Download .html** — downloads the sanitized report as a standalone file |
| Print / PDF | Browser print dialog via **Print / Save PDF** button |

### Assessment Log

- Shared across all analysts (any logged-in user sees all entries)
- Columns: server timestamp (UTC), authenticated login, analyst name (self-reported), vulnerability + CVE, affected system, score, risk tier, actions
- Per-row **Report** button — downloads the stored HTML report for that assessment
- Per-row **Remove** button — soft-deletes the assessment (marks it deleted; only the analyst who created the record may remove it; returns 403 otherwise)
- **Export CSV** — downloads all active assessments as a structured CSV with full CARVER dimension scores, level labels, pre-assessment answers, and metadata
- Every create, update, and delete is recorded in the `audit_log` table; view it with `python manage.py audit`
- Bulk deletion is an admin-only operation via `python manage.py clear-assessments` (hard-delete, requires interactive confirmation)

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
Step 1: Fill metadata (vuln name, CVE, system, etc.)
         ↓
Step 2: Answer 3 pre-assessment yes/no questions
         ↓
Step 3: Score each CARVER dimension (1–5)
         ↓
Step 4: Review risk report
         ├── Copy / download email report
         ├── Print to PDF
         └── Click "Log Assessment" → POST /api/assessments
                   ↓
              Record appears in Assessment Log
              (shared with all analysts)
```

Analysts can navigate back from any step to adjust scores before logging. Clicking **Log Assessment** is the only action that writes to the database.

---

## API Reference

All endpoints require HTTP Basic Auth. The server stamps `authenticated_as` and `created_at` — clients cannot set or overwrite these fields.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the single-page application |
| `GET` | `/logout` | Returns 401 to flush browser credential cache |
| `GET` | `/api/me` | Returns `{"username": "<authenticated_login>"}` |
| `POST` | `/api/assessments` | Create a new assessment record |
| `PUT` | `/api/assessments/<id>` | Update analyst fields (403 if not the creator) |
| `GET` | `/api/assessments` | List all assessments (summary fields only) |
| `DELETE` | `/api/assessments/<id>` | Soft-delete an assessment (403 if not the creator) |
| `GET` | `/api/assessments/export` | Download all assessments as CSV |
| `GET` | `/api/assessments/<id>/report` | Download stored HTML report for one assessment |

All state-mutating requests (POST, PUT, DELETE) must include the header `X-Requested-With: XMLHttpRequest`. Requests missing this header are rejected with 403. The frontend sends it automatically.

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
  "levels":        { "C": "Severe", "A": "Open", "R1": "Prolonged", "V": "Critical", "E": "Catastrophic", "R2": "Known" },
  "email_html":    "<html>...</html>"
}
```

> `total_score` and `risk_tier` in the payload are **ignored** — the server computes them from `scores`. Each score must be an integer 1–5 or the request is rejected with 400.

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
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialise the database (first run only)
python manage.py init-db

# 4. Create the first analyst account
python manage.py add-user analyst1

# 5. Run with gunicorn (mirrors production)
gunicorn -w 2 -b 127.0.0.1:5000 app:app
# Or for quick dev iteration:
flask --app app run --port 5000
```

> **SECRET_KEY**: For local dev a random key is generated automatically on each start. For production, set the `CARVER_SECRET_KEY` environment variable (see Setup — Production step 4).

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
echo "CARVER_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
# (Not yet wired into app.py — see Security Status below)

# 5. Configure nginx
sudo cp nginx.conf /etc/nginx/sites-available/carver
# Edit /etc/nginx/sites-available/carver — replace 'your.domain'
sudo ln -s /etc/nginx/sites-available/carver /etc/nginx/sites-enabled/carver
sudo nginx -t

# 6. Obtain TLS certificate
sudo certbot --nginx -d your.domain

# 7. Create a systemd service (example)
sudo tee /etc/systemd/system/carver.service > /dev/null <<EOF
[Unit]
Description=CARVER Risk Assessment Tool
After=network.target

[Service]
User=carver
WorkingDirectory=/opt/carver-tool-server
ExecStart=/opt/carver-tool-server/.venv/bin/gunicorn -w 2 -b 127.0.0.1:5000 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now carver
```

---

## File Structure

```
carver-tool-server/
├── app.py              # Flask application — routes, auth, DB helpers, sanitizers
├── manage.py           # CLI — user management and DB initialisation
├── requirements.txt    # Python dependencies
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
| date, analyst, cve, vuln_name, system, owner, business_unit, threat_actor, mitre, vpr_score, notes | Analyst-supplied metadata |
| pre_q1, pre_q2, pre_q3 | Pre-assessment answers ("yes" / "no") |
| score_c, score_a, score_r1, score_v, score_e, score_r2 | CARVER dimension scores (1–5, server-validated) |
| level_c … level_r2 | Human-readable level labels (e.g. "Severe") |
| total_score, risk_tier | Server-computed from scores |
| email_html | Sanitized HTML report artifact |
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

## Security Status

### Implemented

| Severity | Item | Status |
|---|---|---|
| Critical | Server-side score validation and tier recomputation | ✅ Done |
| Critical | HTML sanitization (nh3) on all stored reports | ✅ Done |
| Critical | Strict CSP on report download endpoint | ✅ Done |
| Critical | Security response headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS-ready) | ✅ Done |
| High | Rate limiting — `flask-limiter` (60 req/min per IP per worker) + nginx `limit_req` (30 req/min) | ✅ Done |
| High | Deletion ownership — `DELETE /<id>` restricted to record creator; returns 403 otherwise | ✅ Done |
| High | Bulk delete removed from API — `DELETE /api/assessments` endpoint removed; use `manage.py clear-assessments` | ✅ Done |
| High | Audit trail — `audit_log` table records every create/update/delete with actor and vuln name; `manage.py audit` views it | ✅ Done |
| High | Soft deletes — deleted assessments are marked with `deleted_at`/`deleted_by`; never physically removed by the API | ✅ Done |
| Medium | CSRF mitigation — POST/PUT/DELETE require `X-Requested-With: XMLHttpRequest`; missing header → 403 | ✅ Done |
| Medium | Flask `SECRET_KEY` — loaded from `CARVER_SECRET_KEY` env var; falls back to per-process random key | ✅ Done |
| Medium | Authenticated username shown in UI header — populated via `GET /api/me` on page load | ✅ Done |
| Medium | PUT ownership — `PUT /api/assessments/<id>` restricted to record creator; returns 403 otherwise | ✅ Done |
| Low | `.gitignore` (venv, data/, *.csv, .env) | ✅ Done |
| Low | SQLite file permissions (600) | ✅ Done |
| Low | Stale backup files removed | ✅ Done |
| Low | `init_db()` moved from module level to `manage.py init-db` | ✅ Done |
| Low | `/logout` endpoint + Sign out button | ✅ Done |

### Outstanding

| Severity | Item |
|---|---|
| High | HTTPS/TLS — `nginx.conf` template created; production cert required |
