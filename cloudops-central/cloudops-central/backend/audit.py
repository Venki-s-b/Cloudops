"""
CloudOps Central — Audit Log
Records every significant action (login, user create/delete, account onboard/remove, config change).
"""

import sqlite3
import json
import os
import logging
from datetime import datetime, timezone

log = logging.getLogger("cloudops.audit")
DB_PATH = os.path.join(os.path.dirname(__file__), "cloudops.db")


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_audit_table():
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                actor      TEXT NOT NULL,
                action     TEXT NOT NULL,
                resource   TEXT,
                detail     TEXT,
                ip         TEXT,
                status     TEXT DEFAULT 'success'
            )
        """)
        conn.commit()


init_audit_table()


def audit(actor: str, action: str, resource: str = None, detail: dict = None, ip: str = None, status: str = "success"):
    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, resource, detail, ip, status) VALUES (?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    actor,
                    action,
                    resource,
                    json.dumps(detail) if detail else None,
                    ip,
                    status,
                )
            )
            conn.commit()
    except Exception as e:
        log.error("Audit write failed: %s", e)


def get_audit_log(limit: int = 200, actor: str = None, action: str = None) -> list:
    query = "SELECT * FROM audit_log"
    params = []
    filters = []
    if actor:
        filters.append("actor=?")
        params.append(actor)
    if action:
        filters.append("action LIKE ?")
        params.append(f"%{action}%")
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with _db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]
