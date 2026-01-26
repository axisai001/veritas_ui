# tenant_store.py — B2B Tenant Key Store (VER-B2B-001 / VER-B2B-002)

from datetime import datetime, timezone
from typing import Dict, Optional
from pathlib import Path
import os
import sqlite3
import uuid

# -------------------------------------------------
# Database path (single source of truth)
# -------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Allows override via environment / Streamlit secrets
DB_PATH = os.environ.get("DB_PATH") or str(DATA_DIR / "veritas.db")

# -------------------------------------------------
# Assumes these exist below in this file:
# - generate_api_key()
# - hash_api_key()
# - _now()  -> returns UTC ISO string
# -------------------------------------------------


def init_tenant_tables() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # -----------------------------
    # TENANTS (canonical registry)
    # -----------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id TEXT PRIMARY KEY,
            tier TEXT NOT NULL,
            monthly_analysis_limit INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL
        )
    """)

    # -----------------------------
    # TENANT KEYS (hashed, rotatable)
    # -----------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_keys (
            key_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            created_utc TEXT NOT NULL,
            revoked_utc TEXT,
            rotated_from_key_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
        )
    """)

    # -----------------------------
    # TENANT USAGE (monthly metering)
    # -----------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_usage (
            tenant_id TEXT NOT NULL,
            period_yyyymm TEXT NOT NULL,
            analysis_count INTEGER NOT NULL DEFAULT 0,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            PRIMARY KEY (tenant_id, period_yyyymm),
            FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
        )
    """)

    con.commit()
    con.close()


def admin_create_tenant(tenant_id: str, tier: str, monthly_limit: int) -> str:
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_id = f"tk_{uuid.uuid4().hex[:12]}"

    ts = _now()

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute(
        """INSERT INTO tenants VALUES (?,?,?,?,?,?)""",
        (tenant_id, tier, int(monthly_limit), "active", ts, ts)
    )

    cur.execute(
        """INSERT INTO tenant_keys VALUES (?,?,?,?,?,?,?)""",
        (key_id, tenant_id, key_hash, "active", ts, None, None)
    )

    con.commit()
    con.close()

    return raw_key  # DISPLAY ONCE ONLY


def verify_tenant_key(raw_key: str) -> Optional[Dict]:
    key_hash = hash_api_key(raw_key)

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        SELECT
            t.tenant_id, t.tier, t.monthly_analysis_limit, t.status,
            k.key_id, k.status
        FROM tenant_keys k
        JOIN tenants t ON t.tenant_id = k.tenant_id
        WHERE k.key_hash = ?
    """, (key_hash,))

    row = cur.fetchone()
    con.close()

    if not row:
        return None

    tenant_status = row[3]
    key_status = row[5]

    if tenant_status != "active" or key_status != "active":
        return None

    return {
        "tenant_id": row[0],
        "tier": row[1],
        "monthly_analysis_limit": row[2],
        "key_id": row[4],
    }


def suspend_tenant(tenant_id: str) -> None:
    ts = _now()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "UPDATE tenants SET status='suspended', updated_utc=? WHERE tenant_id=?",
        (ts, tenant_id)
    )
    con.commit()
    con.close()


def rotate_key(tenant_id: str, old_key_id: str) -> str:
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    new_key_id = f"tk_{uuid.uuid4().hex[:12]}"
    ts = _now()

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute(
        "UPDATE tenant_keys SET status='revoked', revoked_utc=? WHERE key_id=?",
        (ts, old_key_id)
    )

    cur.execute(
        """INSERT INTO tenant_keys VALUES (?,?,?,?,?,?,?)""",
        (new_key_id, tenant_id, key_hash, "active", ts, None, old_key_id)
    )

    con.commit()
    con.close()

    return raw_key


# =============================================================================
# TENANT USAGE (MONTHLY METERING) — Step 3
# =============================================================================
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def current_period_yyyymm() -> str:
    # e.g., "202601"
    return datetime.now(timezone.utc).strftime("%Y%m")

def ensure_usage_row(tenant_id: str, period_yyyymm: str) -> None:
    ts = _utc_now_iso()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO tenant_usage (tenant_id, period_yyyymm, analysis_count, created_utc, updated_utc)
        VALUES (?, ?, 0, ?, ?)
        ON CONFLICT(tenant_id, period_yyyymm) DO NOTHING
        """,
        (tenant_id, period_yyyymm, ts, ts),
    )
    con.commit()
    con.close()

def get_usage(tenant_id: str, period_yyyymm: str) -> int:
    ensure_usage_row(tenant_id, period_yyyymm)
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT analysis_count
        FROM tenant_usage
        WHERE tenant_id=? AND period_yyyymm=?
        """,
        (tenant_id, period_yyyymm),
    )
    row = cur.fetchone()
    con.close()
    return int(row[0]) if row else 0

def increment_usage(tenant_id: str, period_yyyymm: str) -> None:
    ensure_usage_row(tenant_id, period_yyyymm)
    ts = _utc_now_iso()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        UPDATE tenant_usage
        SET analysis_count = analysis_count + 1,
            updated_utc = ?
        WHERE tenant_id=? AND period_yyyymm=?
        """,
        (ts, tenant_id, period_yyyymm),
    )
    con.commit()
    con.close()

def admin_get_tenant(tenant_id: str) -> Optional[Dict]:
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT tenant_id, tier, monthly_analysis_limit, status, created_utc, updated_utc
        FROM tenants
        WHERE tenant_id=?
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return {
        "tenant_id": row[0],
        "tier": row[1],
        "monthly_analysis_limit": int(row[2]),
        "status": row[3],
        "created_utc": row[4],
        "updated_utc": row[5],
    }

def admin_list_tenants(limit: int = 500) -> list:
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT tenant_id, tier, monthly_analysis_limit, status, created_utc, updated_utc
        FROM tenants
        ORDER BY created_utc DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    rows = cur.fetchall()
    con.close()
    return rows

def admin_list_tenant_keys(tenant_id: str, limit: int = 50) -> list:
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT key_id, status, created_utc, revoked_utc, rotated_from_key_id
        FROM tenant_keys
        WHERE tenant_id=?
        ORDER BY created_utc DESC
        LIMIT ?
        """,
        (tenant_id, int(limit)),
    )
    rows = cur.fetchall()
    con.close()
    return rows

def admin_get_usage(tenant_id: str, period_yyyymm: str) -> int:
    # Uses your existing get_usage() (which also ensures the row exists)
    return int(get_usage(tenant_id, period_yyyymm))

def admin_usage_snapshot(period_yyyymm: str, limit: int = 500) -> list:
    """
    Returns per-tenant usage for a given month.
    Includes tenants even if usage row doesn't exist yet by LEFT JOIN.
    """
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT
            t.tenant_id,
            t.tier,
            t.monthly_analysis_limit,
            t.status,
            COALESCE(u.analysis_count, 0) as analysis_count
        FROM tenants t
        LEFT JOIN tenant_usage u
          ON u.tenant_id = t.tenant_id
         AND u.period_yyyymm = ?
        ORDER BY t.created_utc DESC
        LIMIT ?
        """,
        (period_yyyymm, int(limit)),
    )
    rows = cur.fetchall()
    con.close()
    return rows
