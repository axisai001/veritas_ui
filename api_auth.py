# api_auth.py — B2B API Authentication (VER-B2B-003)
# Fail-closed authentication & entitlement checks.
# No Streamlit dependency.
#
# IMPORTANT:
# - This module ENFORCES quota by ATOMICALLY CONSUMING 1 unit of usage on each successful auth.
# - Perioding is YEARLY via period_yyyy (per tenant_store.current_period_yyyy()).
# - Entitlement column remains monthly_analysis_limit (canonical), even though metering is yearly.

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import sqlite3

import tenant_store
from tenant_store import (
    verify_tenant_key_detailed,
    current_period_yyyy,
)

# -----------------------------
# Exceptions (framework-agnostic)
# -----------------------------
class Unauthorized(Exception):
    """401"""
    pass


class Forbidden(Exception):
    """403"""
    pass


class TooManyRequests(Exception):
    """429"""
    pass


# -----------------------------
# Tenant context (returned on success)
# -----------------------------
@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    tier: str
    # Name kept for backward compatibility with your existing code,
    # but this value is actually "per-period limit" using monthly_analysis_limit canonical.
    annual_analysis_limit: int
    key_id: str
    period_yyyy: str
    used_this_period: int


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _consume_usage_atomic(tenant_id: str, period_yyyy: str, limit: int) -> int:
    """
    Atomically increments tenant_usage.analysis_count by 1 IF under limit.
    Returns the usage count AFTER the attempted consume.
    Raises TooManyRequests if already at/over limit.
    """
    if limit <= 0:
        raise Forbidden("Tenant entitlement misconfigured")

    now = _utc_iso()

    # Single source of truth DB path comes from tenant_store.DB_PATH
    db_path = tenant_store.DB_PATH

    con = sqlite3.connect(db_path, timeout=10)
    try:
        cur = con.cursor()

        # Acquire a write lock early so concurrent requests can't both pass quota.
        cur.execute("BEGIN IMMEDIATE")

        # Ensure row exists
        cur.execute(
            """
            INSERT OR IGNORE INTO tenant_usage
            (tenant_id, period_yyyy, analysis_count, created_utc, updated_utc)
            VALUES (?, ?, 0, ?, ?)
            """,
            (tenant_id, period_yyyy, now, now),
        )

        # Increment ONLY if under limit
        cur.execute(
            """
            UPDATE tenant_usage
            SET analysis_count = analysis_count + 1,
                updated_utc = ?
            WHERE tenant_id = ?
              AND period_yyyy = ?
              AND analysis_count < ?
            """,
            (now, tenant_id, period_yyyy, limit),
        )

        # Read current count (after attempted update)
        cur.execute(
            """
            SELECT analysis_count
            FROM tenant_usage
            WHERE tenant_id = ? AND period_yyyy = ?
            """,
            (tenant_id, period_yyyy),
        )
        row = cur.fetchone()
        used_after = int(row[0]) if row and row[0] is not None else 0

        # If we did NOT increment, we're over quota
        if used_after > limit:
            # Defensive: should never happen due to WHERE clause, but fail-closed.
            raise TooManyRequests(f"Over quota ({used_after}/{limit})")

        if cur.rowcount == 0:
            # UPDATE didn't apply => already at/over limit before this request
            raise TooManyRequests(f"Over quota ({used_after}/{limit})")

        con.commit()
        return used_after

    except TooManyRequests:
        con.rollback()
        raise
    except Forbidden:
        con.rollback()
        raise
    except Exception:
        con.rollback()
        # Fail-closed: do not leak internal details
        raise Unauthorized("Unauthorized")
    finally:
        con.close()


def authenticate_request(api_key: Optional[str]) -> TenantContext:
    raw = (api_key or "").strip()

    # Explicit missing-key check (don’t rely on tenant_store behavior)
    if not raw:
        raise Unauthorized("Missing API key")

    tenant, reason = verify_tenant_key_detailed(raw)

    if reason in ("bad_format", "not_found", "missing"):
        raise Unauthorized("Missing or invalid API key")

    if reason == "inactive":
        raise Forbidden("Tenant or API key is inactive")

    if reason != "ok":
        # Future-proof: any unknown reason -> fail-closed
        raise Unauthorized("Invalid API key")

    if not tenant:
        # Defensive fail-closed
        raise Unauthorized("Invalid API key")

    tenant_id = tenant.get("tenant_id") or ""
    tier = tenant.get("tier") or ""
    key_id = tenant.get("key_id") or ""

    # Canonical entitlement in DB schema
    limit = int(tenant.get("monthly_analysis_limit") or 0)
    if limit <= 0:
        raise Forbidden("Tenant entitlement misconfigured")

    period = current_period_yyyy()

    # IMPORTANT: consume 1 unit of usage *here* so each /analyze call is metered
    used_after = _consume_usage_atomic(tenant_id, period, limit)

    return TenantContext(
        tenant_id=tenant_id,
        tier=tier,
        annual_analysis_limit=limit,  # backward compatible field name
        key_id=key_id,
        period_yyyy=period,
        used_this_period=used_after,
    )
