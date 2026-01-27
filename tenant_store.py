# tenant_store.py — B2B Tenant Key Store (VER-B2B-001 / VER-B2B-002)
# Updated: YEARLY metering (period_yyyy) instead of monthly (period_yyyy)

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple
from pathlib import Path
import os
import sqlite3
import uuid
import secrets
import hashlib

# -------------------------------------------------
# Database path (single source of truth)
# -------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = os.environ.get("DB_PATH") or str(DATA_DIR / "veritas.db")

# -------------------------------------------------
# Tenant key security
# -------------------------------------------------
TENANT_KEY_SALT = (os.environ.get("TENANT_KEY_SALT") or "").strip()
if not TENANT_KEY_SALT:
    raise RuntimeError("TENANT_KEY_SALT must be set in Streamlit secrets or environment")

def generate_api_key() -> str:
    return f"vx_{secrets.token_urlsafe(32)}"

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256((TENANT_KEY_SALT + raw_key).encode("utf-8", errors="ignore")).hexdigest()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# =============================================================================
# DB SCHEMA
# =============================================================================
def init_tenant_tables() -> None:
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")

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

    # -------------------------------------------------
    # MIGRATION: monthly tenant_usage -> yearly tenant_usage
    # -------------------------------------------------
    def _table_exists(name: str) -> bool:
        cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (name,))
        return cur.fetchone() is not None

    def _columns(name: str) -> set[str]:
        cur.execute(f"PRAGMA table_info({name})")
        return {r[1] for r in cur.fetchall()}

    if _table_exists("tenant_usage"):
        cols = _columns("tenant_usage")
        # Old schema had period_yyyymm; new schema uses period_yyyy
        if "period_yyyymm" in cols and "period_yyyy" not in cols:
            # Rename old table
            cur.execute("ALTER TABLE tenant_usage RENAME TO tenant_usage_old")

            # Create new yearly table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenant_usage (
                    tenant_id TEXT NOT NULL,
                    period_yyyy TEXT NOT NULL,
                    analysis_count INTEGER NOT NULL DEFAULT 0,
                    created_utc TEXT NOT NULL,
                    updated_utc TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, period_yyyy),
                    FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
                )
            """)

            # Roll up monthly -> yearly (take YYYY from YYYYMM)
            cur.execute("""
                INSERT INTO tenant_usage (tenant_id, period_yyyy, analysis_count, created_utc, updated_utc)
                SELECT
                    tenant_id,
                    SUBSTR(period_yyyymm, 1, 4) AS period_yyyy,
                    SUM(COALESCE(analysis_count, 0)) AS analysis_count,
                    MIN(created_utc) AS created_utc,
                    MAX(updated_utc) AS updated_utc
                FROM tenant_usage_old
                GROUP BY tenant_id, SUBSTR(period_yyyymm, 1, 4)
            """)

            # Drop old
            cur.execute("DROP TABLE tenant_usage_old")

    # -----------------------------
    # TENANT USAGE (YEARLY metering)
    # -----------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_usage (
            tenant_id TEXT NOT NULL,
            period_yyyy TEXT NOT NULL,
            analysis_count INTEGER NOT NULL DEFAULT 0,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            PRIMARY KEY (tenant_id, period_yyyy),
            FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
        )
    """)

    con.commit()
    con.close()

# =============================================================================
# TENANT MANAGEMENT (Admin)
# =============================================================================
def admin_create_tenant(tenant_id: str, tier: str, monthly_limit: int) -> str:
    """
    Creates a tenant + issues a new vx_ key (returned ONCE).
    Note: annual_analysis_limit is treated as the entitlement number; if you want annual naming later,
    do that via a migration ticket to rename the column.
    """
    tenant_id = (tenant_id or "").strip()
    if not tenant_id:
        raise ValueError("tenant_id required")

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_id = f"tk_{uuid.uuid4().hex[:12]}"

    ts = _now()

    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")

    # Insert tenant (will raise IntegrityError if tenant_id already exists)
    cur.execute(
        """INSERT INTO tenants (tenant_id, tier, annual_analysis_limit, status, created_utc, updated_utc)
           VALUES (?,?,?,?,?,?)""",
        (tenant_id, tier, int(monthly_limit), "active", ts, ts),
    )

    # Insert initial key
    cur.execute(
        """INSERT INTO tenant_keys (key_id, tenant_id, key_hash, status, created_utc, revoked_utc, rotated_from_key_id)
           VALUES (?,?,?,?,?,?,?)""",
        (key_id, tenant_id, key_hash, "active", ts, None, None),
    )

    con.commit()
    con.close()

    return raw_key  # DISPLAY ONCE ONLY

def verify_tenant_key(raw_key: str) -> Optional[Dict]:
    raw_key = (raw_key or "").strip()
    if not raw_key:
        return None
    if not raw_key.startswith("vx_"):
        return None

    key_hash = hash_api_key(raw_key)

    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()

    cur.execute("""
        SELECT
            t.tenant_id,
            t.tier,
            t.annual_analysis_limit,
            t.status,
            k.key_id,
            k.status
        FROM tenant_keys k
        JOIN tenants t ON t.tenant_id = k.tenant_id
        WHERE k.key_hash = ?
        LIMIT 1
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
        "annual_analysis_limit": int(row[2]),
        "key_id": row[4],
    }

def suspend_tenant(tenant_id: str) -> None:
    tenant_id = (tenant_id or "").strip()
    ts = _now()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        "UPDATE tenants SET status='suspended', updated_utc=? WHERE tenant_id=?",
        (ts, tenant_id),
    )
    con.commit()
    con.close()

def rotate_key(tenant_id: str, old_key_id: str) -> str:
    tenant_id = (tenant_id or "").strip()
    old_key_id = (old_key_id or "").strip()
    if not tenant_id or not old_key_id:
        raise ValueError("tenant_id and old_key_id required")

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    new_key_id = f"tk_{uuid.uuid4().hex[:12]}"
    ts = _now()

    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")

    # Revoke old key (audit trail preserved)
    cur.execute(
        "UPDATE tenant_keys SET status='revoked', revoked_utc=? WHERE key_id=? AND tenant_id=?",
        (ts, old_key_id, tenant_id),
    )

    # Insert new active key linked to old key id
    cur.execute(
        """INSERT INTO tenant_keys (key_id, tenant_id, key_hash, status, created_utc, revoked_utc, rotated_from_key_id)
           VALUES (?,?,?,?,?,?,?)""",
        (new_key_id, tenant_id, key_hash, "active", ts, None, old_key_id),
    )

    con.commit()
    con.close()

    return raw_key  # DISPLAY ONCE ONLY

# =============================================================================
# TENANT USAGE (YEARLY METERING)
# =============================================================================
def current_period_yyyy() -> str:
    # e.g., "2026"
    return datetime.now(timezone.utc).strftime("%Y")

def ensure_usage_row(tenant_id: str, period_yyyy: str) -> None:
    ts = _utc_now_iso()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO tenant_usage (tenant_id, period_yyyy, analysis_count, created_utc, updated_utc)
        VALUES (?, ?, 0, ?, ?)
        ON CONFLICT(tenant_id, period_yyyy) DO NOTHING
        """,
        (tenant_id, period_yyyy, ts, ts),
    )
    con.commit()
    con.close()

def get_usage(tenant_id: str, period_yyyy: str) -> int:
    ensure_usage_row(tenant_id, period_yyyy)
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT analysis_count
        FROM tenant_usage
        WHERE tenant_id=? AND period_yyyy=?
        """,
        (tenant_id, period_yyyy),
    )
    row = cur.fetchone()
    con.close()
    return int(row[0]) if row else 0

def increment_usage(tenant_id: str, period_yyyy: str) -> None:
    ensure_usage_row(tenant_id, period_yyyy)
    ts = _utc_now_iso()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        UPDATE tenant_usage
        SET analysis_count = analysis_count + 1,
            updated_utc = ?
        WHERE tenant_id=? AND period_yyyy=?
        """,
        (ts, tenant_id, period_yyyy),
    )
    con.commit()
    con.close()

# =============================================================================
# ADMIN REPORTING HELPERS
# =============================================================================
def admin_get_tenant(tenant_id: str) -> Optional[Dict]:
    tenant_id = (tenant_id or "").strip()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT tenant_id, tier, annual_analysis_limit, status, created_utc, updated_utc
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
        "annual_analysis_limit": int(row[2]),
        "status": row[3],
        "created_utc": row[4],
        "updated_utc": row[5],
    }

def admin_list_tenants(limit: int = 500) -> List[Tuple]:
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT tenant_id, tier, annual_analysis_limit, status, created_utc, updated_utc
        FROM tenants
        ORDER BY created_utc DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    rows = cur.fetchall()
    con.close()
    return rows

def admin_list_tenant_keys(tenant_id: str, limit: int = 50) -> List[Tuple]:
    tenant_id = (tenant_id or "").strip()
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

def admin_get_usage(tenant_id: str, period_yyyy: str) -> int:
    return int(get_usage(tenant_id, period_yyyy))

def admin_usage_snapshot(period_yyyy: str, limit: int = 500) -> List[Tuple]:
    """
    Returns per-tenant usage for a given year.
    Includes tenants even if usage row doesn't exist yet by LEFT JOIN.
    """
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT
            t.tenant_id,
            t.tier,
            t.annual_analysis_limit,
            t.status,
            COALESCE(u.analysis_count, 0) as analysis_count
        FROM tenants t
        LEFT JOIN tenant_usage u
          ON u.tenant_id = t.tenant_id
         AND u.period_yyyy = ?
        ORDER BY t.created_utc DESC
        LIMIT ?
        """,
        (period_yyyy, int(limit)),
    )
    rows = cur.fetchall()
    con.close()
    return rows

