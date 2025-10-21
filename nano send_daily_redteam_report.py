#!/usr/bin/env python3
# send_daily_redteam_report.py
import os
import sqlite3
import csv
import io
import json
from datetime import datetime, timedelta, timezone
import httpx

# --- Config (env vars preferred) ---
DB_PATH = os.environ.get("VERITAS_DB_PATH", "data/veritas.db")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
REDTEAM_TO = os.environ.get("REDTEAM_REPORT_TO", "")      # e.g. ops@axislabs.ai
REDTEAM_FROM = os.environ.get("REDTEAM_REPORT_FROM", "")  # e.g. veritas@axislabs.ai
SUBJECT = os.environ.get("REDTEAM_REPORT_SUBJECT", "Daily Red Team Report")
LOOKBACK_DAYS = int(os.environ.get("REDTEAM_LOOKBACK_DAYS", "1"))  # last N days

def fetch_redteam_rows(db_path: str, lookback_days: int):
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    cutoff_iso = cutoff.isoformat()
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    # be safe if column missing
    try:
        cur.execute("PRAGMA table_info(analyses)")
        cols = [r[1] for r in cur.fetchall()]
        if "redteam_flag" not in cols:
            con.close()
            return []
    except Exception:
        con.close()
        return []

    q = """
    SELECT id, timestamp_utc, public_report_id, internal_report_id,
           login_id, remote_addr, conversation_json
    FROM analyses
    WHERE redteam_flag=1 AND timestamp_utc >= ?
    ORDER BY id DESC
    """
    cur.execute(q, (cutoff_iso,))
    rows = cur.fetchall()
    con.close()
    return rows

def build_csv_bytes(rows):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow([
        "id","timestamp_utc","public_report_id","internal_report_id",
        "login_id","remote_addr","user_input","assistant_reply"
    ])
    for (id_, ts, pub, internal, login, remote, conv_json) in rows:
        try:
            conv = json.loads(conv_json or "{}")
            user_input = conv.get("user_prompt","")
            assistant_reply = conv.get("assistant_reply","")
        except Exception:
            user_input = ""
            assistant_reply = conv_json or ""
        w.writerow([id_, ts, pub, internal, login, remote, user_input, assistant_reply])
    return out.getvalue().encode("utf-8")

def send_via_sendgrid(api_key, to_email, from_email, subject, plain_text,
                      html_text=None, attachment_bytes=None, attachment_name="redteam_report.csv"):
    if not api_key:
        raise RuntimeError("Missing SENDGRID_API_KEY")
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email, "name": "Veritas"},
        "subject": subject,
        "content": [{"type": "text/plain", "value": plain_text}],
    }
    if html_text:
        payload["content"].append({"type": "text/html", "value": html_text})
    if attachment_bytes:
        import base64
        payload["attachments"] = [{
            "content": base64.b64encode(attachment_bytes).decode("ascii"),
            "filename": attachment_name,
            "type": "text/csv",
            "disposition": "attachment",
        }]

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=30) as client:
        r = client.post("https://api.sendgrid.com/v3/mail/send", headers=headers, json=payload)
    return r.status_code, r.text

def main():
    rows = fetch_redteam_rows(DB_PATH, LOOKBACK_DAYS)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not rows:
        body = f"No Red Team tests found in the last {LOOKBACK_DAYS} day(s) as of {ts} UTC."
        print(body)
        # You can still email a "no data" digest if you want:
        if SENDGRID_API_KEY and REDTEAM_TO and REDTEAM_FROM:
            send_via_sendgrid(SENDGRID_API_KEY, REDTEAM_TO, REDTEAM_FROM, SUBJECT + " (empty)", body)
        return

    csv_bytes = build_csv_bytes(rows)
    plain = f"Attached is the Red Team report for the last {LOOKBACK_DAYS} day(s).\nRows: {len(rows)}\nTime: {ts} UTC"
    html = f"<p>Attached is the Red Team report for the last {LOOKBACK_DAYS} day(s).</p><p><b>Rows:</b> {len(rows)}<br><b>Time:</b> {ts} UTC</p>"

    if not (SENDGRID_API_KEY and REDTEAM_TO and REDTEAM_FROM):
        print("Missing sendgrid config; writing redteam_report.csv locally.")
        with open("redteam_report.csv", "wb") as f:
            f.write(csv_bytes)
        return

    status, text = send_via_sendgrid(SENDGRID_API_KEY, REDTEAM_TO, REDTEAM_FROM, SUBJECT,
                                     plain, html, csv_bytes, "redteam_report.csv")
    print("SendGrid status:", status)
    if status not in (200, 202):
        print("Response:", text)

if __name__ == "__main__":
    main()
