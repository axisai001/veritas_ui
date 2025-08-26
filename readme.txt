---

# README – Veritas Pilot Test (Streamlit Version)

## Overview

This repository contains the **Veritas – Pilot Test** application.
It is a **Streamlit-based interface** for running **bias detection analyses** using an OpenAI model.

Key features:

* 🔒 Secure login with optional access password
* 📊 Bias analysis reports with unique Report IDs
* 📑 Upload support for PDF, DOCX, TXT, MD, CSV
* 📝 PDF download of structured reports
* 📮 User feedback form with optional SendGrid email relay
* 🔐 Security hardening (session-based auth, rate limiting per session, minimal error surfaces)
* 🧾 Audit logs for authentication, analyses, feedback, and errors
* ⚡ Configurable via environment variables (`config.py`)
* 🖼 Branding controls (tagline + logo) for admins

---

## Requirements

### Python version

* Python **3.10 – 3.12** recommended

### Core dependencies

Installed from `requirements.txt`:

```
streamlit==1.38.0
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

* `OPENAI_API_KEY` → Your OpenAI API key (used for analysis).

### Optional

* `APP_PASSWORD` → Password required to log in.
* `BRAND_ADMIN_PASSWORD` → Admin unlock key for branding controls.
* `VERITAS_TZ` → Time zone for pilot start (default: `America/Denver`).
* `PILOT_START_AT` → Optional datetime (e.g., `2025-09-15 08:00`) to lock access until pilot start.

### Uploads

* `MAX_UPLOAD_MB=8` → maximum upload size (MB).

### Rate limiting (per session)

* `RATE_LIMIT_WINDOW_SEC=60` → time window in seconds (default: 60).
* `RATE_LIMIT_LOGIN=10` → max login attempts per session per window.
* `RATE_LIMIT_CHAT=10` → max chat requests per session per window.
* `RATE_LIMIT_EXTRACT=10` → max extract requests per session per window.

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
streamlit run streamlit_app.py
```

App runs at: [http://localhost:8501](http://localhost:8501)

---

## Usage

1. **Login** → Enter the access password if set.
2. **Analysis** → Paste or upload text/documents and click **Analyze**.

   * Each analysis generates a public Report ID (`VER-...`) and internal ID (`AX-...`).
3. **Download** → Save results as PDF.
4. **Feedback** → Submit feedback with rating + email.

---

## Logging & Security

### CSV logs

Stored in `data/`:

* `auth_events.csv` → login/logout attempts.
* `analyses.csv` → records of each analysis (conversation + response).
* `feedback.csv` → feedback submissions.
* `errors.csv` → timestamped error events with unique IDs.

### Rate limiting

* `/login`, `/chat`, `/extract`, `/feedback` are limited to **10 requests/minute per session** (configurable).

### Security measures

* Session cookies replaced by **Streamlit session state** (per-browser tab).
* HTTPS should be enforced at the proxy layer (Streamlit Cloud, Render, etc.).
* CORS not applicable (Streamlit runs front + back together).
* Error messages show only `"network error"` to users; full details are logged in `errors.csv`.

---

## Development Notes

* **UI**: Built with Streamlit (`st.form`, `st.text_area`, `st.file_uploader`, etc.).
* **Admin unlock**: Enter `BRAND_ADMIN_PASSWORD` in the sidebar → enables branding controls.
* **Error handling**: Only `"network error"` is displayed to users. Developers trace details in `errors.csv`.
* **PDF reports**: Generated with ReportLab.

---

## Recommended workflow

* Install deps → `pip install -r requirements.txt`
* Run dev server → `streamlit run streamlit_app.py`
* Test locally at `http://localhost:8501`
* Deploy behind HTTPS proxy (Streamlit Cloud, Render, etc.)

---

## License

This project is internal to **AXIS AI Excellence & Strategic Intelligence Solutions, LLC**.
All rights reserved.

---
