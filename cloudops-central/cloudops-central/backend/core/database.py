"""
Database layer — SQLite for dev, PostgreSQL for production.
Switch by setting DATABASE_URL=postgresql://user:pass@host/db
"""
import sqlite3
import json
import os
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

log = logging.getLogger("cloudops.db")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cloudops.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db_session() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_id   TEXT PRIMARY KEY,
                provider     TEXT NOT NULL DEFAULT 'aws',
                data         TEXT NOT NULL,
                onboarded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                data     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                actor      TEXT NOT NULL,
                action     TEXT NOT NULL,
                resource   TEXT,
                detail     TEXT,
                ip         TEXT,
                status     TEXT DEFAULT 'success'
            );
            CREATE TABLE IF NOT EXISTS smtp_config (
                id   INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS otp_tokens (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                purpose    TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used       INTEGER DEFAULT 0
            );
        """)


init_db()


# ── Generic key-value store backed by a table ─────────────────────────────────

class _TableStore:
    """Dict-like interface over a SQLite table with (pk TEXT, data TEXT) columns."""

    def __init__(self, table: str, pk_col: str = "account_id", extra_cols: dict | None = None):
        self._table = table
        self._pk = pk_col
        self._extra = extra_cols or {}

    def _load_all(self) -> dict:
        with db_session() as conn:
            rows = conn.execute(f"SELECT {self._pk}, data FROM {self._table}").fetchall()
        return {r[self._pk]: json.loads(r["data"]) for r in rows}

    def __getitem__(self, key):
        with db_session() as conn:
            row = conn.execute(
                f"SELECT data FROM {self._table} WHERE {self._pk}=?", (key,)
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["data"])

    def __setitem__(self, key, value):
        data_json = json.dumps(value)
        ts = datetime.now(timezone.utc).isoformat()
        extra_keys = ", ".join(self._extra.keys())
        extra_placeholders = ", ".join("?" for _ in self._extra)
        extra_vals = list(self._extra.values())
        provider = value.get("provider", "aws") if isinstance(value, dict) else "aws"

        with db_session() as conn:
            if self._table == "accounts":
                conn.execute(
                    "INSERT INTO accounts (account_id, provider, data, onboarded_at) VALUES (?,?,?,?) "
                    "ON CONFLICT(account_id) DO UPDATE SET data=excluded.data, provider=excluded.provider",
                    (key, provider, data_json, ts),
                )
            else:
                conn.execute(
                    f"INSERT INTO {self._table} ({self._pk}, data) VALUES (?,?) "
                    f"ON CONFLICT({self._pk}) DO UPDATE SET data=excluded.data",
                    (key, data_json),
                )

    def __delitem__(self, key):
        with db_session() as conn:
            conn.execute(f"DELETE FROM {self._table} WHERE {self._pk}=?", (key,))

    def __contains__(self, key):
        with db_session() as conn:
            row = conn.execute(
                f"SELECT 1 FROM {self._table} WHERE {self._pk}=?", (key,)
            ).fetchone()
        return row is not None

    def __len__(self):
        with db_session() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM {self._table}").fetchone()[0]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):   return self._load_all().keys()
    def values(self): return self._load_all().values()
    def items(self):  return self._load_all().items()


ACCOUNTS_DB = _TableStore("accounts", "account_id")
USERS_DB    = _TableStore("users",    "username")
