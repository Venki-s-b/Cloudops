"""
CloudOps Central — FastAPI Backend (FIXED)

Bugs fixed:
  1. /accounts used a rogue APIRouter with a broken EC2-based implementation
     that ignored ONBOARDED_ACCOUNTS_DB entirely and returned dummy EC2 data.
     Fixed: replaced with a proper @app.get("/accounts") that reads the real DB.

  2. get_cloudwatch_client() silently swallowed ALL exceptions and returned
     dummy data instead of surfacing the real AWS error.
     Fixed: exceptions now propagate with the real error message.

  3. fetch_service_metrics() called get_metric_statistics() with Dimensions=[]
     which returns NO datapoints for EC2/RDS (AWS requires instance/cluster IDs).
     Fixed: fetches real resource IDs first, then queries per-resource metrics.

  4. fetch_account_health() used str.__contains__ which is not callable —
     `"foo".lower().__contains__("bar")` is a bound method, not a bool.
     Fixed: replaced with `"bar" in "foo".lower()`.

Install:
    pip install fastapi uvicorn boto3 python-jose[cryptography] passlib[bcrypt] python-multipart

Run:
    uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Union
from datetime import datetime, timedelta, timezone
import boto3
import logging
from jose import JWTError, jwt
from passlib.context import CryptContext
import json
import sqlite3
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from email_service import (
    get_smtp_config, save_smtp_config,
    create_otp, verify_otp,
    send_welcome_email, send_password_reset_email, send_alert_notification
)
from audit import audit, get_audit_log

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cloudops")

# ─── CONFIG ───────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_use_secrets_manager")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

# ─── RESPONSE CACHE (TTL = 90 seconds per account) ─────────
# Prevents hammering AWS on every 30s frontend poll.
_ACCOUNT_CACHE: dict = {}   # { account_id: {"ts": float, "health": ..., "resources": ...} }
_CACHE_TTL_SECONDS = 90

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="CloudOps Central API",
    description="AWS CloudWatch monitoring backend",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8001,http://127.0.0.1:8001,http://localhost:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ─── AUTH ──────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Persists in memory while server is running.
# Swap for DynamoDB/RDS in production.
#############################DATABASE SETTIGN ####################################
DB_PATH = os.path.join(os.path.dirname(__file__), "cloudops.db")
 
def _db():
    """Get a SQLite connection with row_factory so rows act like dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
 
def _init_db():
    """Create tables on first run — safe to call every startup."""
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_id   TEXT PRIMARY KEY,
                data         TEXT NOT NULL,
                onboarded_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                data     TEXT NOT NULL
            )
        """)
        conn.commit()
 
_init_db()   # runs once at startup
 
class _AccountsDB:
    """
    Drop-in replacement for the old dict.
    Supports:  db[key]  db[key]=val  del db[key]  key in db
               db.get(key)  db.keys()  db.values()  db.items()
    """
    def _load_all(self):
        with _db() as conn:
            rows = conn.execute("SELECT account_id, data FROM accounts").fetchall()
        return {r["account_id"]: json.loads(r["data"]) for r in rows}
 
    def __getitem__(self, key):
        with _db() as conn:
            row = conn.execute("SELECT data FROM accounts WHERE account_id=?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["data"])
 
    def __setitem__(self, key, value):
        data_json = json.dumps(value)
        ts = datetime.now(timezone.utc).isoformat()
        with _db() as conn:
            conn.execute(
                "INSERT INTO accounts (account_id, data, onboarded_at) VALUES (?,?,?) "
                "ON CONFLICT(account_id) DO UPDATE SET data=excluded.data",
                (key, data_json, ts)
            )
            conn.commit()
 
    def __delitem__(self, key):
        with _db() as conn:
            conn.execute("DELETE FROM accounts WHERE account_id=?", (key,))
            conn.commit()
 
    def __contains__(self, key):
        with _db() as conn:
            row = conn.execute("SELECT 1 FROM accounts WHERE account_id=?", (key,)).fetchone()
        return row is not None
 
    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default
 
    def keys(self):
        return self._load_all().keys()
 
    def values(self):
        return self._load_all().values()
 
    def items(self):
        return self._load_all().items()
 
    def __len__(self):
        with _db() as conn:
            return conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
 
class _UsersDB:
    """
    SQLite-backed user store — survives server restarts.
    Bootstrapped with the default admin/viewer users on first run.
    """
    def _load_all(self):
        with _db() as conn:
            rows = conn.execute("SELECT username, data FROM users").fetchall()
        return {r["username"]: json.loads(r["data"]) for r in rows}

    def __getitem__(self, key):
        with _db() as conn:
            row = conn.execute("SELECT data FROM users WHERE username=?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["data"])

    def __setitem__(self, key, value):
        with _db() as conn:
            conn.execute(
                "INSERT INTO users (username, data) VALUES (?,?) "
                "ON CONFLICT(username) DO UPDATE SET data=excluded.data",
                (key, json.dumps(value))
            )
            conn.commit()

    def __delitem__(self, key):
        with _db() as conn:
            conn.execute("DELETE FROM users WHERE username=?", (key,))
            conn.commit()

    def __contains__(self, key):
        with _db() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE username=?", (key,)).fetchone()
        return row is not None

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):   return self._load_all().keys()
    def values(self): return self._load_all().values()
    def items(self):  return self._load_all().items()


USERS_DB = _UsersDB()

# Seed default users on first run (skipped if they already exist)
def _seed_default_users():
    _default_users = [
        {
            "username": "admin",
            "name": "Rucha Chormunge",
            "email": "admin@company.com",
            "hashed_password": pwd_context.hash("admin123"),
            "role": "admin",
            "accounts": "all",
        },
        {
            "username": "viewer",
            "name": "Priya Nair",
            "email": "priya@company.com",
            "hashed_password": pwd_context.hash("view123"),
            "role": "viewer",
            "accounts": "all",
        },
    ]
    for u in _default_users:
        if u["username"] not in USERS_DB:
            USERS_DB[u["username"]] = u

_seed_default_users()

ONBOARDED_ACCOUNTS_DB = _AccountsDB()

# ─── PYDANTIC MODELS ───────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    name: str


class OnboardRequest(BaseModel):
    account_id: str
    name: str
    region: str
    env: str
    owner: str
    role_arn: str
    external_id: Optional[str] = None
    services: List[str]
    extra_regions: List[str] = []
    cpu_threshold: float = 75.0
    mem_threshold: float = 80.0
    alert_email: Optional[str] = None
    description: Optional[str] = None

class CreateAlarmRequest(BaseModel):
    alarm_name: str
    metric_name: str
    namespace: str = "AWS/EC2"
    threshold: float
    comparison: str = "GreaterThanThreshold"
    period: int = 300
    evaluation_periods: int = 2
    statistic: str = "Average"
    dimensions: list = []
    alarm_description: str = ""
    treat_missing: str = "notBreaching"


class CreateUserRequest(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str
    role: str
    accounts: Union[str, List[str]] = "all"
    send_welcome: bool = True


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class SmtpConfigRequest(BaseModel):
    host: str
    port: int = 587
    username: str
    password: str
    from_email: EmailStr
    from_name: str = "CloudOps Central"
    use_tls: bool = False
    start_tls: bool = True
    enabled: bool = True


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


# ─── AUTH HELPERS ──────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc
    user = USERS_DB.get(username)
    if not user:
        raise exc
    return user


def require_admin(current_user=Depends(get_current_user)) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ─── AWS SESSION HELPERS ───────────────────────────────────
def get_aws_session(
    role_arn: str,
    external_id: Optional[str] = None,
    region: str = "ap-south-1",
) -> boto3.Session:
    """
    Assumes a cross-account IAM role via STS and returns a boto3 Session.
    The machine running FastAPI must have sts:AssumeRole permission on the target role.
    """
    sts = boto3.client("sts")
    kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": "CloudOpsCentralSession",
        "DurationSeconds": 3600,
    }
    if external_id:
        kwargs["ExternalId"] = external_id

    log.info(f"Assuming role: {role_arn}")
    resp = sts.assume_role(**kwargs)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def get_cloudwatch_client(account_id: str, region: Optional[str] = None):
    """
    BUG FIX #2: previously swallowed all exceptions silently.
    Now raises HTTPException with the real AWS error message.
    """
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id} not found in ONBOARDED_ACCOUNTS_DB. "
                   f"Did you onboard it via POST /admin/accounts/onboard?",
        )

    target_region = region or acc["region"]
    # Let the real exception surface so you can debug it
    session = get_aws_session(acc["role_arn"], acc.get("external_id"), target_region)
    return session.client("cloudwatch", region_name=target_region)


def get_session_for_account(account_id: str, region: Optional[str] = None) -> boto3.Session:
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not onboarded")
    target_region = region or acc["region"]
    return get_aws_session(acc["role_arn"], acc.get("external_id"), target_region)


# ══════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.post("/auth/token", response_model=Token)
@limiter.limit("10/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = USERS_DB.get(form_data.username)
    ip = get_remote_address(request)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        audit(form_data.username, "LOGIN_FAILED", ip=ip, status="failure")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    audit(user["username"], "LOGIN", ip=ip)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "username": user["username"],
        "name": user["name"],
    }


@app.get("/auth/me")
async def get_me(current_user=Depends(get_current_user)):
    return {k: v for k, v in current_user.items() if k != "hashed_password"}


@app.put("/auth/profile")
async def update_profile(payload: UpdateProfileRequest, current_user=Depends(get_current_user)):
    user = dict(current_user)
    if payload.new_password:
        if not payload.current_password or not verify_password(payload.current_password, user["hashed_password"]):
            raise HTTPException(400, "Current password is incorrect")
        if len(payload.new_password) < 8:
            raise HTTPException(400, "New password must be at least 8 characters")
        user["hashed_password"] = pwd_context.hash(payload.new_password)
    if payload.name:
        user["name"] = payload.name
    if payload.email:
        user["email"] = payload.email
    USERS_DB[user["username"]] = user
    audit(user["username"], "PROFILE_UPDATE")
    return {"message": "Profile updated successfully"}


@app.post("/auth/password-reset/request")
@limiter.limit("5/minute")
async def request_password_reset(request: Request, payload: PasswordResetRequest):
    # Find user by email
    target = next((u for u in USERS_DB.values() if u.get("email") == payload.email), None)
    # Always return 200 to prevent email enumeration
    if target:
        token = create_otp(target["username"], "password_reset", ttl_minutes=30)
        reset_link = f"http://localhost:8001/reset-password?token={token}"
        import asyncio
        asyncio.create_task(send_password_reset_email(target["email"], target["name"], reset_link))
        audit(target["username"], "PASSWORD_RESET_REQUEST")
    return {"message": "If that email exists, a reset link has been sent."}


@app.post("/auth/password-reset/confirm")
async def confirm_password_reset(payload: PasswordResetConfirm):
    username = verify_otp(payload.token, "password_reset")
    if not username:
        raise HTTPException(400, "Invalid or expired reset token")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(404, "User not found")
    user["hashed_password"] = pwd_context.hash(payload.new_password)
    USERS_DB[username] = user
    audit(username, "PASSWORD_RESET_COMPLETE")
    return {"message": "Password reset successfully"}


# ══════════════════════════════════════════════════════════
# ACCOUNTS ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.get("/accounts")
async def list_accounts(
    region: Optional[str] = None,
    current_user=Depends(get_current_user),
):
    """
    FIX: parallelised with ThreadPoolExecutor (was sequential, causing 10-20s latency).
    FIX: per-account 90-second TTL cache — avoids hammering AWS on every 30s frontend poll.
    FIX: optional ?region=ap-south-2 query param — filters accounts by AWS region.
    """
    acc_items = [
        (acc_id, acc) for acc_id, acc in ONBOARDED_ACCOUNTS_DB.items()
        if (current_user["accounts"] == "all" or acc_id in current_user["accounts"])
        and (region is None or acc.get("region") == region or region in acc.get("extra_regions", []))
    ]

    # Capture the requested region in the closure so fetch_one can use it.
    # When no region filter is given we default to each account's primary region.
    requested_region = region  # may be None

    def fetch_one(acc_id_acc):
        acc_id, acc = acc_id_acc

        # Determine which region to actually query for health/resources.
        # If the caller requested a specific region (e.g. ap-south-2) we use
        # that; otherwise fall back to the account's stored primary region.
        target_region = requested_region if requested_region else acc["region"]

        # Cache key is scoped to (account, region) so switching the global
        # region dropdown never serves stale data from a different region.
        cache_key = f"{acc_id}:{target_region}"
        now = time.time()
        cached = _ACCOUNT_CACHE.get(cache_key)
        if cached and (now - cached["ts"]) < _CACHE_TTL_SECONDS:
            return cached["payload"]

        try:
            # Pass target_region so CloudWatch queries the right region endpoint.
            cw = get_cloudwatch_client(acc_id, target_region)
            health = fetch_account_health(cw, acc)
        except Exception as e:
            log.warning(f"Could not fetch health for {acc_id} in {target_region}: {e}")
            health = {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}

        try:
            # Pass target_region so EC2/RDS/Lambda clients hit the right region.
            session = get_session_for_account(acc_id, target_region)
            # Build a temporary acc dict with target_region as primary so
            # fetch_account_resources only scans the selected region.
            scoped_acc = dict(acc)
            scoped_acc["region"] = target_region
            scoped_acc["extra_regions"] = []
            resources = fetch_account_resources(session, scoped_acc)
        except Exception as e:
            log.warning(f"Could not fetch resources for {acc_id} in {target_region}: {e}")
            resources = {}

        payload = {
            "id": acc_id,
            "name": acc["name"],
            # Return the region actually queried so the card tag & dropdown
            # reflect the selected region, not always the primary region.
            "region": target_region,
            "primary_region": acc["region"],
            "extra_regions": acc.get("extra_regions", []),
            "env": acc["env"],
            "owner": acc["owner"],
            "services": acc["services"],
            "status": health["status"],
            "alerts": health["alerts"],
            "metrics": health["metrics"],
            "resources": resources,
            "consoleUrl": (
                f"https://{target_region}.console.aws.amazon.com"
                f"/console/home?region={target_region}"
            ),
        }
        _ACCOUNT_CACHE[cache_key] = {"ts": now, "payload": payload}
        return payload

    if not acc_items:
        return {"accounts": [], "total": 0}

    result = []
    with ThreadPoolExecutor(max_workers=min(len(acc_items), 10)) as ex:
        futures = {ex.submit(fetch_one, item): item[0] for item in acc_items}
        for f in as_completed(futures):
            try:
                result.append(f.result())
            except Exception as e:
                log.warning(f"fetch_one failed for {futures[f]}: {e}")

    return {"accounts": result, "total": len(result)}


@app.get("/accounts/{account_id}")
async def get_account(account_id: str, current_user=Depends(get_current_user)):
    """Detailed account info with per-service live metrics."""
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(status_code=404, detail="Account not found")

    cw = get_cloudwatch_client(account_id)
    session = get_session_for_account(account_id)

    service_data = []
    for svc_name in acc["services"]:
        metrics = fetch_service_metrics(cw, session, svc_name, acc["region"])
        service_data.append({"name": svc_name, "region": acc["region"], **metrics})

    alarms = fetch_active_alarms(cw, region=acc["region"])

    return {
        "id": account_id,
        "name": acc["name"],
        "region": acc["region"],
        "env": acc["env"],
        "owner": acc["owner"],
        "serviceData": service_data,
        "activeAlerts": alarms,
        "consoleUrl": (
            f"https://{acc['region']}.console.aws.amazon.com"
            f"/console/home?region={acc['region']}"
        ),
    }


# ══════════════════════════════════════════════════════════
# METRICS ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.get("/accounts/{account_id}/metrics/{service}")
async def get_service_metrics(
    account_id: str,
    service: str,
    time_range: str = "6h",
    region: Optional[str] = None,
    current_user=Depends(get_current_user),
):
    cw = get_cloudwatch_client(account_id, region)
    session = get_session_for_account(account_id, region)

    end_time = datetime.now(timezone.utc)
    range_map = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
    period_map = {"1h": 60, "6h": 300, "24h": 3600, "7d": 86400}

    seconds = range_map.get(time_range, 21600)
    period = period_map.get(time_range, 300)
    start_time = end_time - timedelta(seconds=seconds)

    charts = build_metric_queries(service, start_time, end_time, period, cw, session)
    return {"service": service, "timeRange": time_range, "charts": charts}


@app.get("/accounts/{account_id}/alarms")
async def get_alarms(account_id: str, current_user=Depends(get_current_user)):
    cw = get_cloudwatch_client(account_id)
    alarms = fetch_active_alarms(cw, region=acc.get("region", "—"))
    return {"accountId": account_id, "alarms": alarms, "total": len(alarms)}


@app.get("/accounts/{account_id}/alarms/list")
async def list_all_alarms(account_id: str, current_user=Depends(get_current_user)):
    """List ALL alarms (any state) for an account."""
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    try:
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        cw = session.client("cloudwatch", region_name=acc["region"])
        response = cw.describe_alarms(MaxRecords=50)
        alarms = []
        for a in response.get("MetricAlarms", []):
            alarms.append({
                "name":       a["AlarmName"],
                "metric":     a["MetricName"],
                "namespace":  a.get("Namespace", ""),
                "threshold":  a.get("Threshold", 0),
                "comparison": a.get("ComparisonOperator", ""),
                "state":      a.get("StateValue", "UNKNOWN"),
                "description":a.get("AlarmDescription", ""),
                "updated":    a["StateUpdatedTimestamp"].strftime("%Y-%m-%d %H:%M UTC") if "StateUpdatedTimestamp" in a else "—",
            })
        return {"accountId": account_id, "alarms": alarms, "total": len(alarms)}
    except Exception as e:
        raise HTTPException(400, f"Failed to list alarms: {str(e)}")


@app.post("/accounts/{account_id}/alarms/create", status_code=201)
async def create_alarm(account_id: str, payload: CreateAlarmRequest, admin=Depends(require_admin)):
    """Create a CloudWatch metric alarm in the target account."""
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    try:
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        cw = session.client("cloudwatch", region_name=acc["region"])
        cw.put_metric_alarm(
            AlarmName=payload.alarm_name,
            AlarmDescription=payload.alarm_description or f"CloudOps: {payload.metric_name} threshold alarm",
            MetricName=payload.metric_name,
            Namespace=payload.namespace,
            Statistic=payload.statistic,
            Dimensions=payload.dimensions,
            Period=payload.period,
            EvaluationPeriods=payload.evaluation_periods,
            Threshold=payload.threshold,
            ComparisonOperator=payload.comparison,
            TreatMissingData=payload.treat_missing,
            ActionsEnabled=False,
        )
        return {"message": f"Alarm '{payload.alarm_name}' created successfully", "accountId": account_id}
    except Exception as e:
        raise HTTPException(400, f"Failed to create alarm: {str(e)}")


@app.delete("/accounts/{account_id}/alarms/{alarm_name}")
async def delete_alarm(account_id: str, alarm_name: str, admin=Depends(require_admin)):
    """Delete a CloudWatch alarm."""
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    try:
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        cw = session.client("cloudwatch", region_name=acc["region"])
        cw.delete_alarms(AlarmNames=[alarm_name])
        return {"message": f"Alarm '{alarm_name}' deleted"}
    except Exception as e:
        raise HTTPException(400, f"Failed to delete alarm: {str(e)}")

@app.get("/alarms")
async def get_all_alarms(current_user=Depends(get_current_user)):
    """
    Aggregate alarms across all onboarded accounts.
    Returns both CloudWatch ALARM-state alarms AND threshold breaches
    detected by checking live metrics against each account's stored thresholds.
    This is what the frontend polls every 30 s to drive donut coloring.
    """
    all_alarms = []
    for acc_id, acc in ONBOARDED_ACCOUNTS_DB.items():
        try:
            cw = get_cloudwatch_client(acc_id)
            region = acc.get("region", "—")
            # 1. Real CloudWatch alarms already in ALARM state
            alarms = fetch_active_alarms(cw, region=region)
            for a in alarms:
                a["accountName"] = acc["name"]
                a["accountId"]   = acc_id
            all_alarms.extend(alarms)

            # 2. Threshold-breach check using the account's stored thresholds
            stored_thresh = acc.get("thresholds", {})
            cpu_thresh  = float(stored_thresh.get("cpu",    75.0))
            mem_thresh  = float(stored_thresh.get("memory", 80.0))
            now = datetime.now(timezone.utc)

            def _latest(namespace, metric_name, dimensions, stat="Average"):
                """Fetch single latest datapoint, return float or None."""
                try:
                    resp = cw.get_metric_statistics(
                        Namespace=namespace,
                        MetricName=metric_name,
                        Dimensions=dimensions,
                        StartTime=now - timedelta(minutes=15),
                        EndTime=now,
                        Period=300,
                        Statistics=[stat],
                    )
                    dps = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
                    return round(dps[-1].get(stat, 0), 2) if dps else None
                except Exception:
                    return None

            # EC2 CPU check (aggregate across all instances via SEARCH expression)
            try:
                ec2_cpu_resp = cw.get_metric_data(
                    MetricDataQueries=[{
                        "Id": "cpu_all",
                        "Expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', 'Average', 300)",
                        "ReturnData": True,
                    }],
                    StartTime=now - timedelta(minutes=15),
                    EndTime=now,
                )
                for series in ec2_cpu_resp.get("MetricDataResults", []):
                    if not series.get("Values"):
                        continue
                    latest_cpu = round(series["Values"][-1], 2)
                    # Extract InstanceId from the label or Id field
                    inst_id = series.get("Label", series.get("Id", "unknown"))
                    warn_thresh = cpu_thresh * 0.75
                    if latest_cpu > cpu_thresh:
                        sev = "critical"
                    elif latest_cpu > warn_thresh:
                        sev = "warning"
                    else:
                        continue  # healthy, skip
                    all_alarms.append({
                        "accountId":    acc_id,
                        "accountName":  acc["name"],
                        "name":         f"EC2 CPU High: {inst_id}",
                        "service":      "EC2",
                        "region":       region,
                        "sev":          sev,
                        "metric":       "CPUUtilization",
                        "metricLabel":  f"CPUUtilization > {cpu_thresh}%",
                        "threshold":    cpu_thresh,
                        "currentValue": latest_cpu,
                        "unit":         "%",
                        "stateReason":  f"CPU at {latest_cpu}% exceeds threshold {cpu_thresh}%",
                        "time":         now.strftime("%H:%M UTC"),
                        "timeISO":      now.isoformat(),
                    })
            except Exception as e:
                log.warning(f"EC2 threshold check failed for {acc_id}: {e}")

            # RDS CPU check
            try:
                rds = boto3.Session(
                    **{k: v for k, v in {
                        "aws_access_key_id":     None,
                        "aws_secret_access_key": None,
                        "aws_session_token":     None,
                    }.items() if v}
                )  # placeholder — use get_aws_session properly
                session = get_aws_session(acc["role_arn"], acc.get("external_id"), region)
                rds_client = session.client("rds", region_name=region)
                dbs = rds_client.describe_db_instances().get("DBInstances", [])
                for db in dbs:
                    db_id = db["DBInstanceIdentifier"]
                    val = _latest("AWS/RDS", "CPUUtilization",
                                  [{"Name": "DBInstanceIdentifier", "Value": db_id}])
                    if val is None:
                        continue
                    warn_thresh = mem_thresh * 0.75
                    if val > mem_thresh:
                        sev = "critical"
                    elif val > warn_thresh:
                        sev = "warning"
                    else:
                        continue
                    all_alarms.append({
                        "accountId":    acc_id,
                        "accountName":  acc["name"],
                        "name":         f"RDS CPU High: {db_id}",
                        "service":      "RDS",
                        "region":       region,
                        "sev":          sev,
                        "metric":       "CPUUtilization",
                        "metricLabel":  f"CPUUtilization > {mem_thresh}%",
                        "threshold":    mem_thresh,
                        "currentValue": val,
                        "unit":         "%",
                        "stateReason":  f"RDS CPU at {val}% exceeds threshold {mem_thresh}%",
                        "time":         now.strftime("%H:%M UTC"),
                        "timeISO":      now.isoformat(),
                    })
            except Exception as e:
                log.warning(f"RDS threshold check failed for {acc_id}: {e}")

        except Exception as e:
            log.warning(f"Could not fetch alarms for {acc_id}: {e}")

    # Deduplicate: prefer CloudWatch native alarms; drop threshold-synthetic ones
    # that duplicate an already-present CW alarm for the same account+metric
    seen = set()
    deduped = []
    for a in all_alarms:
        key = (a.get("accountId"), a.get("metric"), a.get("name"))
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    return {"alarms": deduped, "total": len(deduped)}


# ══════════════════════════════════════════════════════════
# COST EXPLORER
# ══════════════════════════════════════════════════════════

@app.get("/accounts/{account_id}/costs")
async def get_costs(account_id: str, current_user=Depends(get_current_user)):
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(status_code=404, detail="Account not found")

    try:
        # Cost Explorer is always us-east-1
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), "us-east-1")
        ce = session.client("ce", region_name="us-east-1")

        end = datetime.now(timezone.utc).date()
        start = (end.replace(day=1) - timedelta(days=150)).replace(day=1)

        response = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        monthly = [
            {
                "month": r["TimePeriod"]["Start"][:7],
                "cost": float(r["Total"]["UnblendedCost"]["Amount"]),
                "unit": r["Total"]["UnblendedCost"]["Unit"],
            }
            for r in response["ResultsByTime"]
        ]
        return {"accountId": account_id, "monthly": monthly}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cost Explorer error: {str(e)}")


# ══════════════════════════════════════════════════════════
# ONBOARDING (ADMIN ONLY)
# ══════════════════════════════════════════════════════════

@app.post("/admin/accounts/onboard", status_code=201)
async def onboard_account(payload: OnboardRequest, admin=Depends(require_admin), request: Request = None):
     # Allow re-onboarding same account (updates region/role/services)

    # Validate the role ARN actually works before saving
    try:
        session = get_aws_session(payload.role_arn, payload.external_id, payload.region)
        cw = session.client("cloudwatch")
        cw.describe_alarms(MaxRecords=1)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"IAM role validation failed: {str(e)}. "
                   f"Check your role ARN and trust policy.",
        )

    ONBOARDED_ACCOUNTS_DB[payload.account_id] = {
        "name": payload.name,
        "region": payload.region,
        "env": payload.env,
        "owner": payload.owner,
        "role_arn": payload.role_arn,
        "external_id": payload.external_id,
        "services": payload.services,
        "extra_regions": [r for r in payload.extra_regions if r != payload.region],
        "thresholds": {"cpu": payload.cpu_threshold, "memory": payload.mem_threshold},
        "alert_email": payload.alert_email,
        "description": payload.description,
        "onboarded_by": admin["username"],
        "onboarded_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }
    # Invalidate all region-scoped cache entries for this account
    for k in list(_ACCOUNT_CACHE.keys()):
        if k == payload.account_id or k.startswith(f"{payload.account_id}:"):
            _ACCOUNT_CACHE.pop(k, None)
    audit(admin["username"], "ACCOUNT_ONBOARD", resource=payload.account_id, detail={"name": payload.name, "region": payload.region})
    log.info(f"Onboarded account {payload.account_id} ({payload.name})")
    return {
        "message": f"Account {payload.name} ({payload.account_id}) onboarded successfully",
        "accountId": payload.account_id,
    }


@app.patch("/admin/accounts/{account_id}/regions")
async def update_account_regions(
    account_id: str,
    body: dict,
    admin=Depends(require_admin),
):
    """
    Add extra regions to an existing onboarded account so fetch_account_resources
    scans those regions too. No need to re-onboard.

    Body: { "extra_regions": ["ap-south-2", "ap-southeast-1"] }
    """
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    extra = body.get("extra_regions", [])
    if not isinstance(extra, list):
        raise HTTPException(400, "extra_regions must be a list")
    acc["extra_regions"] = extra
    ONBOARDED_ACCOUNTS_DB[account_id] = acc
    for k in list(_ACCOUNT_CACHE.keys()):
        if k == account_id or k.startswith(f"{account_id}:"):
            _ACCOUNT_CACHE.pop(k, None)   # bust all region-scoped cache so next fetch picks up new regions
    log.info(f"Updated extra_regions for {account_id}: {extra}")
    return {
        "message": f"Extra regions updated for {acc['name']}",
        "accountId": account_id,
        "primary_region": acc["region"],
        "extra_regions": extra,
    }


@app.delete("/admin/accounts/{account_id}")
async def remove_account(account_id: str, admin=Depends(require_admin)):
    if account_id not in ONBOARDED_ACCOUNTS_DB:
        raise HTTPException(status_code=404, detail="Account not found")
    del ONBOARDED_ACCOUNTS_DB[account_id]
    for k in list(_ACCOUNT_CACHE.keys()):
        if k == account_id or k.startswith(f"{account_id}:"):
            _ACCOUNT_CACHE.pop(k, None)
    audit(admin["username"], "ACCOUNT_REMOVE", resource=account_id)


@app.get("/admin/accounts")
async def admin_list_accounts(admin=Depends(require_admin)):
    return {
        "accounts": [
            {k: v for k, v in {**{"id": acc_id}, **acc}.items() if k != "role_arn"}
            for acc_id, acc in ONBOARDED_ACCOUNTS_DB.items()
        ]
    }


# ══════════════════════════════════════════════════════════
# USER MANAGEMENT (ADMIN ONLY)
# ══════════════════════════════════════════════════════════

@app.get("/admin/users")
async def list_users(admin=Depends(require_admin)):
    return {
        "users": [
            {k: v for k, v in u.items() if k != "hashed_password"}
            for u in USERS_DB.values()
        ]
    }


@app.post("/admin/users", status_code=201)
async def create_user(payload: CreateUserRequest, admin=Depends(require_admin)):
    if payload.username in USERS_DB:
        raise HTTPException(status_code=409, detail="Username already exists")
    if payload.role not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'viewer'")

    USERS_DB[payload.username] = {
        "username": payload.username,
        "name": payload.name,
        "email": payload.email,
        "hashed_password": pwd_context.hash(payload.password),
        "role": payload.role,
        "accounts": payload.accounts,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": admin["username"],
    }
    audit(admin["username"], "USER_CREATE", resource=payload.username, detail={"role": payload.role})
    if payload.send_welcome:
        import asyncio
        asyncio.create_task(send_welcome_email(payload.email, payload.name, payload.username, payload.password))
    return {"message": f"User {payload.username} created"}


@app.patch("/admin/users/{username}")
async def update_user(username: str, body: dict, admin=Depends(require_admin)):
    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(404, "User not found")
    allowed = {"name", "email", "role", "accounts"}
    for k, v in body.items():
        if k in allowed:
            user[k] = v
    if "password" in body and body["password"]:
        user["hashed_password"] = pwd_context.hash(body["password"])
    USERS_DB[username] = user
    audit(admin["username"], "USER_UPDATE", resource=username, detail={k: v for k, v in body.items() if k != "password"})
    return {"message": f"User {username} updated"}


@app.delete("/admin/users/{username}")
async def delete_user(username: str, admin=Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if username not in USERS_DB:
        raise HTTPException(status_code=404, detail="User not found")
    del USERS_DB[username]
    audit(admin["username"], "USER_DELETE", resource=username)
    return {"message": f"User {username} deleted"}


# ══════════════════════════════════════════════════════════
# SMTP CONFIGURATION (ADMIN ONLY)
# ══════════════════════════════════════════════════════════

@app.get("/admin/smtp")
async def get_smtp(admin=Depends(require_admin)):
    cfg = get_smtp_config()
    if cfg:
        cfg.pop("password", None)  # never return password
    return {"config": cfg}


@app.post("/admin/smtp")
async def set_smtp(payload: SmtpConfigRequest, admin=Depends(require_admin)):
    save_smtp_config(payload.model_dump())
    audit(admin["username"], "SMTP_CONFIG_UPDATE")
    return {"message": "SMTP configuration saved"}


@app.post("/admin/smtp/test")
async def test_smtp(admin=Depends(require_admin)):
    from email_service import send_email
    user = USERS_DB.get(admin["username"])
    ok = await send_email(
        user.get("email", ""),
        "CloudOps Central — SMTP Test",
        "<p style='color:#10d97a;font-family:monospace;'>✅ SMTP is working correctly.</p>"
    )
    if not ok:
        raise HTTPException(400, "SMTP test failed — check your configuration and server logs")
    return {"message": "Test email sent successfully"}


# ══════════════════════════════════════════════════════════
# AUDIT LOG (ADMIN ONLY)
# ══════════════════════════════════════════════════════════

@app.get("/admin/audit")
async def list_audit_log(
    limit: int = 200,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    admin=Depends(require_admin),
):
    logs = get_audit_log(limit=limit, actor=actor, action=action)
    return {"logs": logs, "total": len(logs)}


# ══════════════════════════════════════════════════════════
# CLOUDWATCH HELPERS  (all bugs fixed)
# ══════════════════════════════════════════════════════════

def fetch_account_health(cw_client, acc: dict) -> dict:
    """
    BUG FIX #4: `str.__contains__` is a method object — calling it as a bool
    always evaluated to True. Fixed with `"word" in string` syntax.
    """
    try:
        response = cw_client.describe_alarms(StateValue="ALARM", MaxRecords=100)
        alarms = response.get("MetricAlarms", [])
        alert_count = len(alarms)

        if alert_count == 0:
            health_status = "healthy"
        elif any("critical" in a.get("AlarmName", "").lower() for a in alarms):  # FIXED
            health_status = "critical"
        else:
            health_status = "warning"

        # Fetch aggregate CPU — needs at least one EC2 instance dimension
        # so we use get_metric_data with a search expression instead
        cpu_avg = _get_aggregate_ec2_cpu(cw_client)

        return {
            "status": health_status,
            "alerts": alert_count,
            "metrics": {
                "cpu": f"{cpu_avg:.1f}%" if cpu_avg is not None else "—",
                "alerts": alert_count,
            },
        }
    except Exception as e:
        log.warning(f"fetch_account_health error: {e}")
        return {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}


def _get_aggregate_ec2_cpu(cw_client) -> Optional[float]:
    """
    Uses get_metric_data with a SEARCH expression — the only correct way to
    aggregate CPUUtilization across ALL instances without knowing instance IDs.
    """
    try:
        now = datetime.now(timezone.utc)
        resp = cw_client.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "cpu_avg",
                    "Expression": "AVG(SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', 'Average', 300))",
                    "Label": "AverageCPU",
                    "ReturnData": True,
                }
            ],
            StartTime=now - timedelta(minutes=30),
            EndTime=now,
        )
        values = resp["MetricDataResults"][0].get("Values", [])
        return round(sum(values) / len(values), 1) if values else None
    except Exception as e:
        log.warning(f"_get_aggregate_ec2_cpu error: {e}")
        return None


def fetch_account_resources(session: boto3.Session, acc: dict) -> dict:
    """
    Fetch real resource details for each service across ALL regions the account
    has resources in. The primary region is always scanned; additionally any
    regions listed in acc.get("extra_regions", []) are also scanned.
    Each resource is tagged with its actual region/AZ so the frontend can
    filter correctly when the user selects a region from the dropdown.
    """
    primary_region = acc["region"]
    extra_regions  = acc.get("extra_regions", [])
    all_regions    = list(dict.fromkeys([primary_region] + extra_regions))  # deduplicated, order preserved

    resources: dict = {}

    for svc in acc.get("services", []):
        svc_rows = []
        for region in all_regions:
            try:
                if svc == "EC2":
                    ec2 = session.client("ec2", region_name=region)
                    resp = ec2.describe_instances(
                        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "pending"]}]
                    )
                    for res in resp.get("Reservations", []):
                        for inst in res.get("Instances", []):
                            name_tag = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                            svc_rows.append({
                                "id": inst["InstanceId"],
                                "type": inst.get("InstanceType", "—"),
                                "az": inst.get("Placement", {}).get("AvailabilityZone", region),
                                "region": region,
                                "state": inst.get("State", {}).get("Name", "unknown"),
                                "cpu": "—",
                                "mem": "—",
                                "uptime": "—",
                                "label": name_tag,
                                "consoleUrl": (
                                    f"https://{region}.console.aws.amazon.com/ec2/home"
                                    f"?region={region}#Instances:instanceId={inst['InstanceId']}"
                                ),
                            })

                elif svc == "RDS":
                    rds = session.client("rds", region_name=region)
                    resp = rds.describe_db_instances()
                    for db in resp.get("DBInstances", []):
                        svc_rows.append({
                            "id": db["DBInstanceIdentifier"],
                            "type": db.get("DBInstanceClass", "—"),
                            "az": db.get("AvailabilityZone", region),
                            "region": region,
                            "state": db.get("DBInstanceStatus", "unknown"),
                            "cpu": "—",
                            "mem": "—",
                            "uptime": "—",
                        })

                elif svc == "Lambda":
                    lm = session.client("lambda", region_name=region)
                    resp = lm.list_functions()
                    for fn in resp.get("Functions", []):
                        svc_rows.append({
                            "id": fn["FunctionName"],
                            "type": fn.get("Runtime", "—"),
                            "az": region,
                            "region": region,
                            "state": "active",
                            "cpu": "—",
                            "mem": str(fn.get("MemorySize", "—")) + " MB",
                            "uptime": "—",
                        })

                elif svc == "ELB":
                    elbv2 = session.client("elbv2", region_name=region)
                    resp = elbv2.describe_load_balancers()
                    for lb in resp.get("LoadBalancers", []):
                        azs = "/".join(a["ZoneName"] for a in lb.get("AvailabilityZones", []))
                        svc_rows.append({
                            "id": lb["LoadBalancerName"],
                            "type": lb.get("Type", "application").upper() + " LB",
                            "az": azs or region,
                            "region": region,
                            "state": lb.get("State", {}).get("Code", "active"),
                            "cpu": "—",
                            "mem": "—",
                            "uptime": "—",
                        })

                elif svc == "S3":
                    # S3 is global — only query once from primary region
                    if region == primary_region:
                        s3 = session.client("s3", region_name="us-east-1")
                        resp = s3.list_buckets()
                        for b in resp.get("Buckets", []):
                            svc_rows.append({
                                "id": b["Name"],
                                "type": "Standard",
                                "az": "global",
                                "region": "global",
                                "state": "active",
                                "cpu": "—",
                                "mem": "—",
                                "uptime": "—",
                            })

            except Exception as e:
                log.warning(f"fetch_account_resources [{svc}][{region}] error: {e}")

        resources[svc] = svc_rows

    return resources


def _get_ec2_instance_ids(session: boto3.Session, region: str) -> List[str]:
    """Fetch running EC2 instance IDs — needed to build CloudWatch dimensions."""
    try:
        ec2 = session.client("ec2", region_name=region)
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
        ids = []
        for res in resp["Reservations"]:
            for inst in res["Instances"]:
                ids.append(inst["InstanceId"])
        return ids
    except Exception as e:
        log.warning(f"_get_ec2_instance_ids error: {e}")
        return []


def _get_rds_identifiers(session: boto3.Session, region: str) -> List[str]:
    """Fetch RDS DB instance identifiers."""
    try:
        rds = session.client("rds", region_name=region)
        resp = rds.describe_db_instances()
        return [db["DBInstanceIdentifier"] for db in resp.get("DBInstances", [])]
    except Exception as e:
        log.warning(f"_get_rds_identifiers error: {e}")
        return []


def _get_lambda_function_names(session: boto3.Session, region: str) -> List[str]:
    """Fetch Lambda function names."""
    try:
        lm = session.client("lambda", region_name=region)
        resp = lm.list_functions()
        return [f["FunctionName"] for f in resp.get("Functions", [])]
    except Exception as e:
        log.warning(f"_get_lambda_function_names error: {e}")
        return []


def _get_elb_names(session: boto3.Session, region: str) -> List[dict]:
    """Fetch ALB ARNs and names."""
    try:
        elbv2 = session.client("elbv2", region_name=region)
        resp = elbv2.describe_load_balancers()
        return [
            {"arn": lb["LoadBalancerArn"], "name": lb["LoadBalancerName"]}
            for lb in resp.get("LoadBalancers", [])
        ]
    except Exception as e:
        log.warning(f"_get_elb_names error: {e}")
        return []


def fetch_service_metrics(cw_client, session: boto3.Session, service: str, region: str) -> dict:
    """
    FIX: replaced serial get_metric_statistics loop with a single batched
    get_metric_data call per service — dramatically reduces latency.
    Previously: N instances × M metrics = N*M sequential AWS calls.
    Now: 1 batched call per service.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=30)
    period = 1800

    def _batch_avg(namespace, metric_name, dim_key, ids, stat="Average"):
        """One batched CloudWatch call for up to 10 resource IDs; returns average."""
        if not ids:
            return None
        ids = ids[:10]
        queries = [
            {
                "Id": f"m{i}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": namespace,
                        "MetricName": metric_name,
                        "Dimensions": [{"Name": dim_key, "Value": rid}],
                    },
                    "Period": period,
                    "Stat": stat,
                },
                "ReturnData": True,
            }
            for i, rid in enumerate(ids)
        ]
        try:
            resp = cw_client.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start,
                EndTime=now,
                ScanBy="TimestampDescending",
            )
            vals = []
            for r in resp.get("MetricDataResults", []):
                values = r.get("Values", [])
                if values:
                    vals.append(values[0])   # most recent datapoint
            return round(sum(vals) / len(vals), 1) if vals else None
        except Exception as e:
            log.warning(f"_batch_avg {namespace}/{metric_name} error: {e}")
            return None

    if service == "EC2":
        instance_ids = _get_ec2_instance_ids(session, region)
        count = len(instance_ids)
        cpu = _batch_avg("AWS/EC2", "CPUUtilization", "InstanceId", instance_ids)
        return {
            "cpu": f"{cpu}%" if cpu is not None else "—",
            "mem": "—",
            "alerts": 0,
            "status": "ok",
            "sub": f"{count} instance{'s' if count != 1 else ''}",
            "icon": "🖥️",
            "color": "#38b6ff",
            "resources": instance_ids,
        }

    elif service == "RDS":
        db_ids = _get_rds_identifiers(session, region)
        count = len(db_ids)
        cpu = _batch_avg("AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", db_ids)
        mem_bytes = _batch_avg("AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", db_ids)
        mem_str = f"{round(mem_bytes / 1024**3, 1)} GB free" if mem_bytes else "—"
        return {
            "cpu": f"{cpu}%" if cpu is not None else "—",
            "mem": mem_str,
            "alerts": 0,
            "status": "ok",
            "sub": f"{count} cluster{'s' if count != 1 else ''}",
            "icon": "🗄️",
            "color": "#a78bfa",
            "resources": db_ids,
        }

    elif service == "Lambda":
        fn_names = _get_lambda_function_names(session, region)
        count = len(fn_names)
        invoc  = _batch_avg("AWS/Lambda", "Invocations", "FunctionName", fn_names, "Sum")
        errors = _batch_avg("AWS/Lambda", "Errors",      "FunctionName", fn_names, "Sum")
        return {
            "cpu": "—",
            "mem": "—",
            "alerts": 1 if (errors and errors > 0) else 0,
            "status": "alert" if (errors and errors > 0) else "ok",
            "sub": f"{count} function{'s' if count != 1 else ''} · {int(invoc or 0)} inv",
            "icon": "λ",
            "color": "#fb923c",
            "resources": fn_names,
        }

    elif service == "ELB":
        lbs = _get_elb_names(session, region)
        count = len(lbs)
        lb_dim_vals = [lb["arn"].split("loadbalancer/")[-1] for lb in lbs]
        total_req  = _batch_avg("AWS/ApplicationELB", "RequestCount",           "LoadBalancer", lb_dim_vals, "Sum") or 0
        total_5xx  = _batch_avg("AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", lb_dim_vals, "Sum") or 0
        return {
            "cpu": "—",
            "mem": "—",
            "alerts": 1 if total_5xx > 10 else 0,
            "status": "alert" if total_5xx > 10 else "ok",
            "sub": f"{count} load balancer{'s' if count != 1 else ''} · {int(total_req)} req",
            "icon": "⚖️",
            "color": "#f0c040",
            "resources": [lb["name"] for lb in lbs],
        }

    elif service == "S3":
        try:
            s3 = session.client("s3")
            buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            return {
                "cpu": "—", "mem": "—", "alerts": 0, "status": "ok",
                "sub": f"{len(buckets)} bucket{'s' if len(buckets) != 1 else ''}",
                "icon": "🪣", "color": "#00e5a0", "resources": buckets,
            }
        except Exception as e:
            log.warning(f"S3 list error: {e}")

    return {
        "cpu": "—", "mem": "—", "alerts": 0, "status": "ok",
        "sub": service, "icon": "☁️", "color": "#6b8299", "resources": [],
    }


def fetch_active_alarms(cw_client, region: str = "—") -> list:
    """
    Returns all CloudWatch alarms currently in ALARM state.
    Enriched with currentValue (latest datapoint), threshold, timeISO,
    and real region so the frontend can drive donut coloring correctly.
    """
    try:
        response = cw_client.describe_alarms(StateValue="ALARM", MaxRecords=50)
        results = []
        now = datetime.now(timezone.utc)
        for a in response.get("MetricAlarms", []):
            # Determine severity: prefer explicit flag in alarm name, else
            # use threshold percentage heuristic (>= 90% of threshold = critical)
            alarm_name_lower = a.get("AlarmName", "").lower()
            sev = "critical" if "critical" in alarm_name_lower else "warning"

            # Fetch the most recent datapoint so we can show the actual value
            current_value = None
            try:
                dp_resp = cw_client.get_metric_statistics(
                    Namespace=a.get("Namespace", "AWS/EC2"),
                    MetricName=a.get("MetricName", "CPUUtilization"),
                    Dimensions=a.get("Dimensions", []),
                    StartTime=now - timedelta(minutes=15),
                    EndTime=now,
                    Period=300,
                    Statistics=[a.get("Statistic", "Average")],
                )
                dps = sorted(dp_resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
                if dps:
                    stat_key = a.get("Statistic", "Average")
                    current_value = round(dps[-1].get(stat_key, 0), 2)
                    # Upgrade to critical if value is >= 90% above threshold
                    threshold = a.get("Threshold", 0)
                    if threshold and current_value and current_value >= threshold * 0.9:
                        sev = "critical"
            except Exception:
                pass  # best-effort; leave current_value as None

            ts = a.get("StateUpdatedTimestamp")
            results.append({
                "name":         a["AlarmName"],
                "service":      a.get("Namespace", "").split("/")[-1],
                "region":       region,
                "sev":          sev,
                "metric":       a.get("MetricName", "?"),
                "metricLabel":  (
                    f"{a.get('MetricName','?')} "
                    f"{a.get('ComparisonOperator','>')} "
                    f"{a.get('Threshold', 0)}"
                ),
                "threshold":    a.get("Threshold"),
                "currentValue": current_value,
                "unit":         a.get("Unit", ""),
                "stateReason":  a.get("StateReason", ""),
                "time":         ts.strftime("%H:%M UTC") if ts else "—",
                "timeISO":      ts.isoformat() if ts else None,
            })
        return results
    except Exception as e:
        log.warning(f"fetch_active_alarms error: {e}")
        return []


def build_metric_queries(
    service: str,
    start: datetime,
    end: datetime,
    period: int,
    cw,
    session: boto3.Session,
) -> list:
    """
    BUG FIX #3 (charts): same Dimensions=[] problem fixed here too.
    We resolve real resource IDs first, then fan out metric calls.
    Returns Chart.js-ready {id, title, unit, labels, data, latest}.
    """
    acc_region = session.region_name

    # Build service-specific metric definitions with real dimensions
    metric_defs = _resolve_metric_defs(service, session, acc_region)

    charts = []
    for metric_name, namespace, dimensions, stat, label, unit in metric_defs:
        try:
            resp = cw.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start,
                EndTime=end,
                Period=period,
                Statistics=[stat],
            )
            datapoints = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
            charts.append({
                "id": metric_name,
                "title": label,
                "unit": unit,
                "labels": [dp["Timestamp"].strftime("%H:%M") for dp in datapoints],
                "data": [round(dp[stat], 4) for dp in datapoints],
                "latest": round(datapoints[-1][stat], 2) if datapoints else 0,
            })
        except Exception as e:
            log.warning(f"build_metric_queries {namespace}/{metric_name} error: {e}")
            charts.append({
                "id": metric_name,
                "title": label,
                "unit": unit,
                "labels": [],
                "data": [],
                "latest": 0,
                "error": str(e),
            })

    return charts


def _resolve_metric_defs(
    service: str,
    session: boto3.Session,
    region: str,
) -> list:
    """
    Returns metric definition tuples with real AWS dimensions.
    Falls back to [] dimensions only for Lambda/S3 which support it.
    """
    if service == "EC2":
        ids = _get_ec2_instance_ids(session, region)
        # Use first instance for the chart (most meaningful for drilldown)
        dim = [{"Name": "InstanceId", "Value": ids[0]}] if ids else []
        return [
            ("CPUUtilization",    "AWS/EC2", dim, "Average", "CPU Utilization",  "%"),
            ("NetworkIn",         "AWS/EC2", dim, "Average", "Network In",        "B"),
            ("NetworkOut",        "AWS/EC2", dim, "Average", "Network Out",       "B"),
            ("DiskReadOps",       "AWS/EC2", dim, "Average", "Disk Read Ops",     "ops"),
            ("StatusCheckFailed", "AWS/EC2", dim, "Sum",     "Status Check Fail", ""),
        ]

    elif service == "RDS":
        ids = _get_rds_identifiers(session, region)
        dim = [{"Name": "DBInstanceIdentifier", "Value": ids[0]}] if ids else []
        return [
            ("CPUUtilization",    "AWS/RDS", dim, "Average", "CPU Utilization",  "%"),
            ("FreeableMemory",    "AWS/RDS", dim, "Average", "Freeable Memory",  "B"),
            ("DatabaseConnections","AWS/RDS",dim, "Average", "DB Connections",   ""),
            ("ReadLatency",       "AWS/RDS", dim, "Average", "Read Latency",     "s"),
            ("WriteLatency",      "AWS/RDS", dim, "Average", "Write Latency",    "s"),
            ("FreeStorageSpace",  "AWS/RDS", dim, "Average", "Free Storage",     "B"),
        ]

    elif service == "Lambda":
        # Lambda supports Dimensions=[] for account-wide aggregation
        return [
            ("Invocations", "AWS/Lambda", [], "Sum",     "Invocations",  ""),
            ("Errors",      "AWS/Lambda", [], "Sum",     "Errors",       ""),
            ("Duration",    "AWS/Lambda", [], "Average", "Avg Duration", "ms"),
            ("Throttles",   "AWS/Lambda", [], "Sum",     "Throttles",    ""),
            ("ConcurrentExecutions", "AWS/Lambda", [], "Maximum", "Concurrency", ""),
        ]

    elif service == "ELB":
        lbs = _get_elb_names(session, region)
        if lbs:
            lb_dim_val = lbs[0]["arn"].split("loadbalancer/")[-1]
            dim = [{"Name": "LoadBalancer", "Value": lb_dim_val}]
        else:
            dim = []
        return [
            ("RequestCount",             "AWS/ApplicationELB", dim, "Sum",     "Request Count",    ""),
            ("HTTPCode_ELB_5XX_Count",   "AWS/ApplicationELB", dim, "Sum",     "5XX Errors",       ""),
            ("TargetResponseTime",        "AWS/ApplicationELB", dim, "Average", "Response Time",    "s"),
            ("ActiveConnectionCount",     "AWS/ApplicationELB", dim, "Average", "Active Connections",""),
            ("HTTPCode_Target_2XX_Count", "AWS/ApplicationELB", dim, "Sum",     "2XX Responses",    ""),
        ]

    elif service == "S3":
        # S3 metrics require StorageType dimension; bucket-level requires BucketName too
        return [
            ("BucketSizeBytes", "AWS/S3",
             [{"Name": "StorageType", "Value": "StandardStorage"}],
             "Average", "Bucket Size", "B"),
            ("NumberOfObjects", "AWS/S3",
             [{"Name": "StorageType", "Value": "AllStorageTypes"}],
             "Average", "Object Count", ""),
        ]

    return []

# ══════════════════════════════════════════════════════════
# PASTE THIS BLOCK INTO main_fixed.py
# Find the line:  # ─── HEALTH CHECK ─────
# Paste this entire block ABOVE it
# ══════════════════════════════════════════════════════════

@app.get("/accounts/{account_id}/metrics/EC2/per-instance")
async def get_ec2_per_instance_metrics(
    account_id: str,
    time_range: str = "6h",
    current_user=Depends(get_current_user)
):
    """
    Returns CPU, NetworkIn, NetworkOut per EC2 instance as multi-series.
    Frontend uses this to draw one line per instance instead of one aggregated line.
    """
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")

    hours = {"1h":1,"3h":3,"6h":6,"12h":12,"24h":24,"7d":168}.get(time_range, 6)
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    period     = 300 if hours <= 6 else 900 if hours <= 24 else 3600

    try:
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        ec2 = session.client("ec2", region_name=acc["region"])
        cw  = session.client("cloudwatch", region_name=acc["region"])

        # Get all running instances + their Name tags
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", [])

        instances = []
        for r in reservations:
            for inst in r.get("Instances", []):
                iid      = inst["InstanceId"]
                itype    = inst.get("InstanceType", "unknown")
                name_tag = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), None)
                label    = f"{name_tag} ({iid})" if name_tag else f"{iid} ({itype})"
                instances.append({"id": iid, "type": itype, "label": label})

        if not instances:
            return {"instances": [], "metrics": {}, "message": "No running EC2 instances found"}

        METRICS_TO_FETCH = [
            ("CPUUtilization", "%"),
            ("NetworkIn",      "B"),
            ("NetworkOut",     "B"),
        ]

        result_metrics = {}

        for metric_name, unit in METRICS_TO_FETCH:
            # One batched get_metric_data call for all instances
            queries = []
            for idx, inst in enumerate(instances):
                queries.append({
                    "Id": f"m{idx}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace":  "AWS/EC2",
                            "MetricName": metric_name,
                            "Dimensions": [{"Name": "InstanceId", "Value": inst["id"]}],
                        },
                        "Period": period,
                        "Stat":   "Average",
                    },
                    "ReturnData": True,
                })

            resp = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start_time,
                EndTime=end_time,
                ScanBy="TimestampAscending",
            )

            all_results = {r["Id"]: r for r in resp.get("MetricDataResults", [])}
            longest = max(all_results.values(), key=lambda r: len(r.get("Timestamps", [])), default=None)
            if not longest or not longest.get("Timestamps"):
                result_metrics[metric_name] = {"unit": unit, "labels": [], "series": []}
                continue

            labels = [ts.strftime("%H:%M") for ts in longest["Timestamps"]]
            ts_map = {ts: i for i, ts in enumerate(longest["Timestamps"])}

            series = []
            for idx, inst in enumerate(instances):
                r    = all_results.get(f"m{idx}", {})
                data = [None] * len(labels)
                for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
                    if ts in ts_map:
                        data[ts_map[ts]] = round(val, 4)
                series.append({
                    "instance_id": inst["id"],
                    "name":        inst["label"],
                    "data":        data,
                    "latest":      next((v for v in reversed(data) if v is not None), 0),
                })

            result_metrics[metric_name] = {
                "unit":   unit,
                "labels": labels,
                "series": series,
            }

        return {
            "accountId":       account_id,
            "timeRange":       time_range,
            "instances":       [i["id"] for i in instances],
            "instanceDetails": instances,
            "metrics":         result_metrics,
        }

    except Exception as e:
        raise HTTPException(400, f"Per-instance metrics error: {str(e)}")
# ─── HEALTH CHECK ──────────────────────────────────────────
@app.get("/accounts/{account_id}/resources")
async def get_account_resources_by_region(
    account_id: str,
    region: Optional[str] = None,
    current_user=Depends(get_current_user),
):
    """
    Returns flat list of all instances for a specific region.
    Used by the per-card region dropdown on the overview page.
    """
    acc = ONBOARDED_ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")

    target_region = region or acc["region"]
    all_regions = list(dict.fromkeys([acc["region"]] + acc.get("extra_regions", [])))
    if target_region not in all_regions:
        raise HTTPException(400, f"Region {target_region} is not configured for this account")

    try:
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), target_region)
        # Build a temporary single-region acc dict for fetch_account_resources
        temp_acc = dict(acc)
        temp_acc["region"] = target_region
        temp_acc["extra_regions"] = []
        resources_by_svc = fetch_account_resources(session, temp_acc)
        # Flatten all services into one list
        flat = []
        for svc, rows in resources_by_svc.items():
            for r in rows:
                flat.append({**r, "service": svc})
        return {"accountId": account_id, "region": target_region, "resources": flat, "total": len(flat)}
    except Exception as e:
        raise HTTPException(500, f"Failed to fetch resources: {str(e)}") 
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "onboarded_accounts": len(ONBOARDED_ACCOUNTS_DB),
    }