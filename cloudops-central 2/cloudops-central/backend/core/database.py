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
from typing import Any, Iterator

log = logging.getLogger("cloudops.db")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cloudops.db")

# Whitelist of allowed table/column names — prevents SQL injection via f-string interpolation
_ALLOWED_TABLES  = {"accounts", "users"}
_ALLOWED_PK_COLS = {"account_id", "username"}


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")    # better read concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")   # wait up to 5s on lock
    return conn


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
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
            CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts);
            CREATE INDEX IF NOT EXISTS idx_otp_user     ON otp_tokens(username, purpose);
        """)


init_db()


class _TableStore:
    """
    Dict-like interface over a SQLite table with (pk TEXT, data TEXT) columns.
    Table and column names are validated against a whitelist before use in
    f-string SQL to prevent injection.
    """

    def __init__(self, table: str, pk_col: str = "account_id") -> None:
        if table not in _ALLOWED_TABLES:
            raise ValueError(f"Table '{table}' is not in the allowed list: {_ALLOWED_TABLES}")
        if pk_col not in _ALLOWED_PK_COLS:
            raise ValueError(f"PK column '{pk_col}' is not in the allowed list: {_ALLOWED_PK_COLS}")
        self._table = table
        self._pk = pk_col

    def _load_all(self) -> dict:
        with db_session() as conn:
            rows = conn.execute(
                f"SELECT {self._pk}, data FROM {self._table}"  # noqa: S608 — whitelisted
            ).fetchall()
        return {r[self._pk]: json.loads(r["data"]) for r in rows}

    def __getitem__(self, key: str) -> dict:
        with db_session() as conn:
            row = conn.execute(
                f"SELECT data FROM {self._table} WHERE {self._pk}=?",  # noqa: S608
                (key,),
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["data"])

    def __setitem__(self, key: str, value: Any) -> None:
        data_json = json.dumps(value)
        ts = datetime.now(timezone.utc).isoformat()
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
                    f"INSERT INTO {self._table} ({self._pk}, data) VALUES (?,?) "  # noqa: S608
                    f"ON CONFLICT({self._pk}) DO UPDATE SET data=excluded.data",
                    (key, data_json),
                )

    def __delitem__(self, key: str) -> None:
        with db_session() as conn:
            conn.execute(
                f"DELETE FROM {self._table} WHERE {self._pk}=?",  # noqa: S608
                (key,),
            )

    def __contains__(self, key: object) -> bool:
        with db_session() as conn:
            row = conn.execute(
                f"SELECT 1 FROM {self._table} WHERE {self._pk}=?",  # noqa: S608
                (key,),
            ).fetchone()
        return row is not None

    def __len__(self) -> int:
        with db_session() as conn:
            return conn.execute(
                f"SELECT COUNT(*) FROM {self._table}"  # noqa: S608
            ).fetchone()[0]

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):   return self._load_all().keys()
    def values(self): return self._load_all().values()
    def items(self):  return self._load_all().items()


ACCOUNTS_DB = _TableStore("accounts", "account_id")
USERS_DB    = _TableStore("users",    "username")
