---

# README – Veritas Pilot Test Web App

## Overview

This repository contains the **Veritas – Pilot Test** web application.
It is a Flask-based interface for running **bias detection analyses** using an OpenAI model.

Key features:

* 🔒 Secure login with optional access password
* 📊 Bias analysis reports with unique Report IDs
* 📑 Upload support for PDF, DOCX, TXT, MD, CSV
* 📝 PDF download of structured reports
* 📮 User feedback form with optional SendGrid email relay
* 🔐 Security hardening (secure cookies, HTTPS enforcement, rate limiting)
* 🧾 Audit logs for authentication, analyses, feedback, and errors
* ⚡ Configurable via environment variables (`config.py`)

---

## Requirements

### Python version

* Python 3.10 – 3.12 recommended

### Core dependencies

Installed from `requirements.txt`:

```
flask==3.0.3
werkzeug==3.0.4
openai==1.40.3
httpx==0.27.0
pypdf==4.2.0
python-docx==1.1.2
reportlab==4.2.2
python-dotenv==1.0.1   # optional, for .env support
```

### Install

```bash
pip install -r requirements.txt
```

---

## Configuration

All runtime configuration is managed through **environment variables**, read by `config.py`.

### Required

* `OPENAI_API_KEY` → Your OpenAI API key (used for /chat analysis).

### Optional

* `APP_PASSWORD` → Password required to log in.
* `BRAND_ADMIN_PASSWORD` → Admin unlock key for branding controls.
* `VERITAS_TZ` → Time zone for pilot start (default: `America/Denver`).
* `PILOT_START_AT` → Optional datetime (e.g., `2025-09-15 08:00`) to lock access until pilot start.

### Security

* `SESSION_COOKIE_SECURE=true` (default) → secure cookies only over HTTPS.
* `SESSION_COOKIE_HTTPONLY=true` (default).
* `SESSION_COOKIE_SAMESITE=Lax` (default).
* `ENFORCE_HTTPS=true` → redirect all HTTP requests to HTTPS (expects proxy headers).

### Uploads

* `MAX_UPLOAD_MB=8` → maximum upload size (MB).

### Rate limiting

* `RATE_LIMIT_WINDOW_SEC=60` → time window in seconds (default: 60).
* `RATE_LIMIT_LOGIN=10` → max login attempts per IP per window.
* `RATE_LIMIT_CHAT=10` → max chat requests per IP per window.
* `RATE_LIMIT_EXTRACT=10` → max extract requests per IP per window.

### SendGrid (optional)

* `SENDGRID_API_KEY` → If provided, feedback emails will also be relayed.
* `SENDGRID_TO`, `SENDGRID_FROM`, `SENDGRID_SUBJECT` → Email details.

### Log retention (days)

* `AUTH_LOG_TTL_DAYS=365`
* `ANALYSES_LOG_TTL_DAYS=365`
* `FEEDBACK_LOG_TTL_DAYS=365`
* `ERRORS_LOG_TTL_DAYS=365`

---

## Running the app

### Local

```bash
export OPENAI_API_KEY="sk-xxxx"
export APP_PASSWORD="veritas-demo"
python main.py
```

App runs at: [http://127.0.0.1:8000](http://127.0.0.1:8000)

### With HTTPS proxy (recommended for production)

* Run Flask with `ENFORCE_HTTPS=true`.
* Use a reverse proxy (e.g., NGINX, Traefik, Caddy) to terminate TLS and set the header:

  ```
  X-Forwarded-Proto: https
  ```

---

## Usage

1. **Login** → Visit the app and enter the access password if set.
2. **Analysis** → Paste or upload text/documents and click **Analyze**.

   * Each analysis generates a public Report ID (`VER-...`) and internal ID (`AX-...`).
3. **Download** → Save results as PDF.
4. **Feedback** → Submit feedback with rating + email.

---

## Logging & Security

### CSV logs

Stored in `data/`:

* `auth_events.csv` → login/logout attempts with hashed password prefix for failures.
* `analyses.csv` → records of each analysis (conversation + response).
* `feedback.csv` → feedback submissions.
* `errors.csv` → timestamped error events with unique error IDs + request IDs.

### Rate limiting

* `/login`, `/chat`, `/extract` protected at **10 requests/minute per IP** (configurable).

### Security measures

* Session cookies set `Secure`, `HttpOnly`, and `SameSite=Lax` by default.
* HTTPS enforced (if `ENFORCE_HTTPS=true`).
* CORS disabled by default.

---

## Development Notes

* **Frontend**: The interface is inline HTML + JavaScript (served by Flask).
* **Admin unlock**: 5 quick clicks on the title prompt for the admin key → enables branding controls.
* **Error handling**: User sees a generic `"network error"`.
  Developers can trace details in `errors.csv` (timestamp, IDs, truncated stack info).

---

## Recommended workflow

* Install deps → `pip install -r requirements.txt`
* Run dev server → `python main.py`
* Test locally at `http://127.0.0.1:8000`
* Deploy behind HTTPS proxy with `ENFORCE_HTTPS=true`
* Rotate logs periodically (pruning runs at startup based on `*_LOG_TTL_DAYS`).

---

## License

This project is internal to **AXIS AI Excellence & Strategic Intelligence Solutions, LLC**.
All rights reserved.

---