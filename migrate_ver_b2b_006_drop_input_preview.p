import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH") or str(BASE_DIR / "data" / "veritas.db")

def colnames(cur, table: str):
    cur.execute(f"PRAGMA table_info({table})")
    return [r[1] for r in cur.fetchall()]

def main():
    print("DB_PATH =", DB_PATH)
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()

    # Safety: ensure analyses exists
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyses'")
    if not cur.fetchone():
        raise SystemExit("ERROR: analyses table not found. Aborting.")

    cols = colnames(cur, "analyses")
    print("analyses columns:", cols)

    if "input_preview" not in cols:
        print("OK: input_preview not present. Nothing to do.")
        con.close()
        return

    # Fail if target already exists (avoid accidental overwrite)
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyses_new'")
    if cur.fetchone():
        raise SystemExit("ERROR: analyses_new already exists. Remove it manually or restore DB backup.")

    # BEGIN IMMEDIATE = grabs write lock right away (prevents partial writes during migration)
    cur.execute("BEGIN IMMEDIATE;")

    # Create new table WITHOUT input_preview.
    # Keep everything else identical to your current schema.
    cur.execute("""
        CREATE TABLE analyses_new (
            id INTEGER PRIMARY KEY,
            timestamp_utc TEXT,
            analysis_id TEXT,
            session_id TEXT,
            login_id TEXT,
            model TEXT,
            elapsed_seconds REAL,
            input_chars INTEGER,
            input_sha256 TEXT
        )
    """)

    # Copy allowed fields only (drops input_preview)
    cur.execute("""
        INSERT INTO analyses_new (
            id, timestamp_utc, analysis_id, session_id, login_id, model,
            elapsed_seconds, input_chars, input_sha256
        )
        SELECT
            id, timestamp_utc, analysis_id, session_id, login_id, model,
            elapsed_seconds, input_chars, input_sha256
        FROM analyses
    """)

    # Swap tables
    cur.execute("DROP TABLE analyses;")
    cur.execute("ALTER TABLE analyses_new RENAME TO analyses;")

    con.commit()

    # Verify
    cols2 = colnames(cur, "analyses")
    print("NEW analyses columns:", cols2)
    if "input_preview" in cols2:
        raise SystemExit("ERROR: input_preview still present after migration.")
    print("SUCCESS: input_preview removed.")

    con.close()

if __name__ == "__main__":
    main()
