# tenant_store.py — B2B Tenant Key Store (VER-B2B-001)

import os
import hmac
import uuid
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict

DB_PATH = os.environ.get("DB_PATH", "./data/veritas.db")
TENANT_KEY_SALT = os.environ.get("TENANT_KEY_SALT", "")

if not TENANT_KEY_SALT:
    raise RuntimeError("TENANT_KEY_SALT is required")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def generate_api_key() -> str:
    return f"vx_{secrets.token_urlsafe(32)}"

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256((TENANT_KEY_SALT + raw_key).encode()).hexdigest()

def init_tenant_tables() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id TEXT PRIMARY KEY,
            tier TEXT,
            monthly_analysis_limit INTEGER,
            status TEXT,
            created_utc TEXT,
            updated_utc TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenant_keys (
            key_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            key_hash TEXT,
            status TEXT,
            created_utc TEXT,
            revoked_utc TEXT,
            rotated_from_key_id TEXT
        )
    """)

    con.commit()
    con.close()

def admin_create_tenant(
    tenant_id: str,
    tier: str,
    monthly_limit: int
) -> str:
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_id = f"tk_{uuid.uuid4().hex[:12]}"

    ts = _now()

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute(
        """INSERT INTO tenants VALUES (?,?,?,?,?,?)""",
        (tenant_id, tier, monthly_limit, "active", ts, ts)
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
