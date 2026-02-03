# tenant_store.py — B2B Tenant Key Store (VER-B2B-001 / VER-B2B-002)
# Metering: YEARLY usage (period_yyyy).
# Storage: entitlement column remains monthly_analysis_limit (legacy DB name).
# Canonical API key exposed to app: annual_analysis_limit.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple, Set
from pathlib import Path
import os
import sqlite3
import uuid
import secrets
import hashlib
import time  # <-- ADDED (VER-B2B-008)

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


def _entitlement(limit_val: int) -> Dict[str, int]:
    """
    Canonical entitlement is annual_analysis_limit (because metering is yearly).
    DB storage uses monthly_analysis_limit as a legacy column name.
    We return BOTH keys for compatibility during migration.
    """
    v = int(limit_val or 0)
    return {
        "annual_analysis_limit": v,
        "monthly_analysis_limit": v,  # legacy / compat
    }


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
    if _table_exists(cur, "tenants"):
        cols = _columns(cur, "tenants")
        if "annual_analysis_limit" in cols and "monthly_analysis_limit" not in cols:
            try:
                cur.execute("ALTER TABLE tenants RENAME COLUMN annual_analysis_limit TO monthly_analysis_limit")
            except Exception:
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

    # -----------------------------
    # TENANT WARNINGS (VER-B2B-005)
    # One-time warning flags per period
    # -----------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_warnings (
            tenant_id TEXT NOT NULL,
            period_yyyy TEXT NOT NULL,
            warned_95 INTEGER NOT NULL DEFAULT 0,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            PRIMARY KEY (tenant_id, period_yyyy),
            FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
        )
    """)

    # =============================================================================
    # VER-B2B-008 — Per-tenant rate limiting (server-side, shared, audited)
    # =============================================================================

    # Shared counter by (tenant_id, rule, window_start_epoch)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_rate_counters (
            tenant_id TEXT NOT NULL,
            rule TEXT NOT NULL,
            window_start_epoch INTEGER NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            created_utc TEXT NOT NULL,
            updated_utc TEXT NOT NULL,
            PRIMARY KEY (tenant_id, rule, window_start_epoch),
            FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
        )
    """)

    # Audit log (append-only)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_rate_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_utc TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            rule TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            limit_val INTEGER NOT NULL,
            window_sec INTEGER NOT NULL,
            window_start_epoch INTEGER NOT NULL,
            count_before INTEGER NOT NULL,
            count_after INTEGER NOT NULL,
            key_id TEXT,
            route TEXT,
            ip TEXT
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
    DB column is monthly_analysis_limit (legacy name).
    Semantically, this limit is treated as ANNUAL because metering is period_yyyy.
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

    # Fail loud & clear if tenant_id already exists (common testing gotcha).
    cur.execute("SELECT 1 FROM tenants WHERE tenant_id=? LIMIT 1", (tenant_id,))
    if cur.fetchone():
        con.close()
        raise sqlite3.IntegrityError("UNIQUE constraint failed: tenants.tenant_id")

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
    """
    Back-compat: returns tenant context or None (no reason).
    Prefer verify_tenant_key_detailed for API middleware decisions.
    """
    tenant, reason = verify_tenant_key_detailed(raw_key)
    return tenant if reason == "ok" else None


def verify_tenant_key_detailed(raw_key: str) -> Tuple[Optional[Dict], str]:
    """
    Returns (tenant_dict_or_none, reason)

    reason values:
      - "missing"      -> no key provided
      - "bad_format"   -> not vx_
      - "not_found"    -> key hash not found
      - "inactive"     -> tenant suspended OR key revoked
      - "ok"           -> active + returns tenant context
    """
    raw_key = (raw_key or "").strip()
    if not raw_key:
        return None, "missing"
    if not raw_key.startswith("vx_"):
        return None, "bad_format"

    key_hash = hash_api_key(raw_key)

    con = sqlite3.connect(DB_PATH, timeout=30)
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT
                t.tenant_id,
                t.tier,
                t.monthly_analysis_limit,
                t.status AS tenant_status,
                k.key_id,
                k.status AS key_status
            FROM tenant_keys k
            JOIN tenants t ON t.tenant_id = k.tenant_id
            WHERE k.key_hash = ?
            LIMIT 1
            """,
            (key_hash,),
        )
        row = cur.fetchone()
    finally:
        con.close()

    if not row:
        return None, "not_found"

    tenant_status = row[3]
    key_status = row[5]
    if tenant_status != "active" or key_status != "active":
        return None, "inactive"

    ent = _entitlement(int(row[2]))
    return {
        "tenant_id": row[0],
        "tier": row[1],
        **ent,
        "key_id": row[4],
    }, "ok"


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
    """
    Consume 1 analysis for (tenant_id, year).
    NOTE: This does not re-check quota. Quota is enforced BEFORE calling this.
    """
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
# VER-B2B-005 — 95% WARNING (FIRE ONCE PER TENANT/PERIOD)
# =============================================================================
def _ensure_warning_row(tenant_id: str, period_yyyy: str) -> None:
    ts = _utc_now_iso()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO tenant_warnings (tenant_id, period_yyyy, warned_95, created_utc, updated_utc)
        VALUES (?, ?, 0, ?, ?)
        ON CONFLICT(tenant_id, period_yyyy) DO NOTHING
        """,
        (tenant_id, period_yyyy, ts, ts),
    )
    con.commit()
    con.close()


def has_warned_95(tenant_id: str, period_yyyy: str) -> bool:
    _ensure_warning_row(tenant_id, period_yyyy)
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        "SELECT warned_95 FROM tenant_warnings WHERE tenant_id=? AND period_yyyy=?",
        (tenant_id, period_yyyy),
    )
    row = cur.fetchone()
    con.close()
    return bool(row and int(row[0]) == 1)


def mark_warned_95(tenant_id: str, period_yyyy: str) -> None:
    _ensure_warning_row(tenant_id, period_yyyy)
    ts = _utc_now_iso()
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        UPDATE tenant_warnings
        SET warned_95=1, updated_utc=?
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

    ent = _entitlement(int(row[2]))
    return {
        "tenant_id": row[0],
        "tier": row[1],
        **ent,
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
            t.monthly_analysis_limit AS annual_analysis_limit,
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


# =============================================================================
# Compatibility aliases (so older tests/scripts don't break)
# =============================================================================
def list_tenants(limit: int = 500) -> List[Tuple]:
    return admin_list_tenants(limit=limit)


# =============================================================================
# VER-B2B-008 — Per-tenant rate limiting (shared across processes, audited)
# =============================================================================
def _window_start_epoch(now_epoch: int, window_sec: int) -> int:
    # Fixed window start (e.g., every 60s bucket, every 1s bucket)
    if window_sec <= 0:
        return now_epoch
    return now_epoch - (now_epoch % window_sec)


def rate_limit_check(
    tenant_id: str,
    rule: str,
    limit_val: int,
    window_sec: int,
    *,
    key_id: str = "",
    route: str = "",
    ip: str = "",
    consume: int = 1,
) -> Tuple[bool, int, int, int]:
    """
    Atomic per-tenant rate limiter (fixed-window), shared across processes via SQLite.

    Returns: (allowed, remaining, count_after, reset_epoch)

    Fail-closed behavior:
      - If DB operation fails for any reason, we deny (allowed=False).
    """
    tenant_id = (tenant_id or "").strip()
    rule = (rule or "").strip()
    limit_val = int(limit_val or 0)
    window_sec = int(window_sec or 0)
    consume = int(consume or 1)

    if not tenant_id or not rule or limit_val <= 0 or window_sec <= 0 or consume <= 0:
        # Misconfigured limiter => fail-closed (deny)
        return (False, 0, 0, int(time.time()) + max(window_sec, 1))

    now_epoch = int(time.time())
    win_start = _window_start_epoch(now_epoch, window_sec)
    reset_epoch = win_start + window_sec

    ts = _utc_now_iso()

    con = sqlite3.connect(DB_PATH, timeout=30)
    try:
        cur = con.cursor()
        cur.execute("PRAGMA foreign_keys = ON;")

        # IMMEDIATE gives us a write lock early (race-safe across processes)
        cur.execute("BEGIN IMMEDIATE")

        # Ensure row exists
        cur.execute(
            """
            INSERT INTO tenant_rate_counters (tenant_id, rule, window_start_epoch, count, created_utc, updated_utc)
            VALUES (?, ?, ?, 0, ?, ?)
            ON CONFLICT(tenant_id, rule, window_start_epoch) DO NOTHING
            """,
            (tenant_id, rule, win_start, ts, ts),
        )

        cur.execute(
            """
            SELECT count
            FROM tenant_rate_counters
            WHERE tenant_id=? AND rule=? AND window_start_epoch=?
            """,
            (tenant_id, rule, win_start),
        )
        row = cur.fetchone()
        count_before = int(row[0]) if row else 0

        projected = count_before + consume
        allowed = 1 if projected <= limit_val else 0

        if allowed:
            cur.execute(
                """
                UPDATE tenant_rate_counters
                SET count = count + ?,
                    updated_utc = ?
                WHERE tenant_id=? AND rule=? AND window_start_epoch=?
                """,
                (consume, ts, tenant_id, rule, win_start),
            )

        # Re-read after update (authoritative)
        cur.execute(
            """
            SELECT count
            FROM tenant_rate_counters
            WHERE tenant_id=? AND rule=? AND window_start_epoch=?
            """,
            (tenant_id, rule, win_start),
        )
        row2 = cur.fetchone()
        count_after = int(row2[0]) if row2 else count_before

        remaining = max(0, int(limit_val - count_after))

        # Audit event (always log: allow/deny)
        cur.execute(
            """
            INSERT INTO tenant_rate_events
              (created_utc, tenant_id, rule, allowed, limit_val, window_sec, window_start_epoch,
               count_before, count_after, key_id, route, ip)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ts,
                tenant_id,
                rule,
                int(bool(allowed)),
                int(limit_val),
                int(window_sec),
                int(win_start),
                int(count_before),
                int(count_after),
                (key_id or "")[:64] if key_id else None,
                (route or "")[:120] if route else None,
                (ip or "")[:64] if ip else None,
            ),
        )

        con.commit()
        return (bool(allowed), remaining, count_after, reset_epoch)

    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        # Fail-closed
        return (False, 0, 0, reset_epoch)
    finally:
        con.close()


def rate_limit_check_or_raise(
    tenant_id: str,
    rule: str,
    limit_val: int,
    window_sec: int,
    *,
    key_id: str = "",
    route: str = "",
    ip: str = "",
    consume: int = 1,
) -> Dict[str, int]:
    """
    Convenience wrapper: raises RuntimeError on deny (fail-closed).
    Returns dict of metadata when allowed (for API response headers / logs).
    """
    allowed, remaining, count_after, reset_epoch = rate_limit_check(
        tenant_id=tenant_id,
        rule=rule,
        limit_val=limit_val,
        window_sec=window_sec,
        key_id=key_id,
        route=route,
        ip=ip,
        consume=consume,
    )
    if not allowed:
        raise RuntimeError(f"Rate limit exceeded for {rule}")

    return {
        "remaining": int(remaining),
        "count": int(count_after),
        "reset_epoch": int(reset_epoch),
        "limit": int(limit_val),
        "window_sec": int(window_sec),
    }


def admin_recent_rate_events(limit: int = 500) -> List[Tuple]:
    """
    Returns most recent rate-limit events for audit review.
    """
    con = sqlite3.connect(DB_PATH, timeout=30)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, created_utc, tenant_id, rule, allowed, limit_val, window_sec,
               window_start_epoch, count_before, count_after, key_id, route, ip
        FROM tenant_rate_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    rows = cur.fetchall()
    con.close()
    return rows
