# tenant_store.py — B2B Tenant Key Store (VER-B2B-001 / VER-B2B-002)
# Metering: YEARLY usage (period_yyyy). Entitlement column remains: monthly_analysis_limit (canonical).

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple, Set
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


def _table_exists(cur: sqlite3.Cursor, name: str) -> bool:
    cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (name,))
    return cur.fetchone() is not None


def _columns(cur: sqlite3.Cursor, name: str) -> Set[str]:
    cur.execute(f"PRAGMA table_info({name})")
    return {r[1] for r in cur.fetchall()}


# =============================================================================
# DB SCHEMA + MIGRATIONS
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

    # MIGRATION: If someone previously created annual_analysis_limit column, rename to monthly_analysis_limit.
    # SQLite supports RENAME COLUMN in modern versions; if this fails, fallback is to rebuild table (not done here).
    if _table_exists(cur, "tenants"):
        cols = _columns(cur, "tenants")
        if "annual_analysis_limit" in cols and "monthly_analysis_limit" not in cols:
            try:
                cur.execute("ALTER TABLE tenants RENAME COLUMN annual_analysis_limit TO monthly_analysis_limit")
            except Exception:
                # If your SQLite is too old for RENAME COLUMN, you must delete the DB or do a rebuild migration.
                # We fail closed with a clear message rather than silently corrupting data.
                con.close()
                raise RuntimeError(
                    "DB migration needed: tenants has annual_analysis_limit but no monthly_analysis_limit, "
                    "and SQLite cannot RENAME COLUMN. Delete veritas.db or run a rebuild migration."
                )

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
    # Old schema: tenant_usage(tenant_id, period_yyyymm, analysis_count, created_utc, updated_utc)
    # New schema: tenant_usage(tenant_id, period_yyyy,  analysis_count, created_utc, updated_utc)
    # -------------------------------------------------
    if _table_exists(cur, "tenant_usage"):
        cols = _columns(cur, "tenant_usage")
        if "period_yyyymm" in cols and "period_yyyy" not in cols:
            cur.execute("ALTER TABLE tenant_usage RENAME TO tenant_usage_old")

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

            # Roll up YYYYMM -> YYYY
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
    Entitlement column is monthly_analysis_limit (canonical), regardless of metering period length.
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

    cur.execute(
        """
        INSERT INTO tenants (tenant_id, tier, monthly_analysis_limit, status, created_utc, updated_utc)
        VALUES (?,?,?,?,?,?)
        """,
        (tenant_id, tier, int(monthly_limit), "active", ts, ts),
    )

    cur.execute(
        """
        INSERT INTO tenant_keys (key_id, tenant_id, key_hash, status, created_utc, revoked_utc, rotated_from_key_id)
        VALUES (?,?,?,?,?,?,?)
        """,
        (key_id, tenant_id, key_hash, "active", ts, None, None),
    )

    con.commit()
    con.close()
    return raw_key  # DISPLAY ONCE ONLY


def verify_tenant_key(raw_key: str) -> Optional[Dict]:
    raw_key = (raw_key or "").strip()
    if not raw_key or not raw_key.startswith("vx_"):
        return None

    key_hash = hash_api_key(raw_key)

    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()

    cur.execute(
        """
        SELECT
            t.tenant_id,
            t.tier,
            t.monthly_analysis_limit,
            t.status,
            k.key_id,
            k.status
        FROM tenant_keys k
        JOIN tenants t ON t.tenant_id = k.tenant_id
        WHERE k.key_hash = ?
        LIMIT 1
        """,
        (key_hash,),
    )

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
        "monthly_analysis_limit": int(row[2]),
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

    cur.execute(
        "UPDATE tenant_keys SET status='revoked', revoked_utc=? WHERE key_id=? AND tenant_id=?",
        (ts, old_key_id, tenant_id),
    )

    cur.execute(
        """
        INSERT INTO tenant_keys (key_id, tenant_id, key_hash, status, created_utc, revoked_utc, rotated_from_key_id)
        VALUES (?,?,?,?,?,?,?)
        """,
        (new_key_id, tenant_id, key_hash, "active", ts, None, old_key_id),
    )

    con.commit()
    con.close()
    return raw_key  # DISPLAY ONCE ONLY


# =============================================================================
# TENANT USAGE (YEARLY METERING)
# =============================================================================
def current_period_yyyy() -> str:
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


def admin_list_tenants(limit: int = 500) -> List[Tuple]:
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
            t.monthly_analysis_limit,
            t.status,
            COALESCE(u.analysis_count, 0) AS analysis_count
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
