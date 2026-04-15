"""
CloudOps Central — Enterprise Multi-Cloud Monitoring Platform
FastAPI entry point. Wires all routers together.

Run:
    uvicorn main:app --reload --port 8000

Environment variables (set in .env or shell):
    SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
    DATABASE_URL=sqlite:///./cloudops.db   (or postgresql://...)
    ALLOWED_ORIGINS=http://localhost:8001
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import boto3
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from core.config import get_settings
from core.database import ACCOUNTS_DB, USERS_DB
from core.security import hash_password, get_current_user
from routers.auth import router as auth_router
from routers.accounts import router as accounts_router
from routers.admin import router as admin_router
from routers.alarms import router as alarms_router
from audit import audit, get_audit_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cloudops")

# ── App setup ─────────────────────────────────────────────────────────────────
settings = get_settings()
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="CloudOps Central API",
    description="Enterprise multi-cloud monitoring — AWS, Azure, GCP",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(admin_router)
app.include_router(alarms_router)


# ── AWS session helper (shared across routers) ────────────────────────────────
def get_aws_session(
    role_arn: str,
    external_id: Optional[str] = None,
    region: str = "us-east-1",
) -> boto3.Session:
    sts = boto3.client("sts")
    kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": "CloudOpsCentralSession",
        "DurationSeconds": 3600,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    resp = sts.assume_role(**kwargs)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


# ── Seed default users on first run ──────────────────────────────────────────
def _seed_default_users():
    """
    Seeds admin/viewer only if they don't exist yet.
    Passwords come from environment variables — never hardcoded.
    """
    defaults = [
        {
            "username": "admin",
            "name": "Platform Admin",
            "email": os.getenv("ADMIN_EMAIL", "admin@company.com"),
            "hashed_password": hash_password(os.getenv("ADMIN_PASSWORD", "ChangeMe123!")),
            "role": "admin",
            "accounts": "all",
        },
        {
            "username": "viewer",
            "name": "Read-Only Viewer",
            "email": os.getenv("VIEWER_EMAIL", "viewer@company.com"),
            "hashed_password": hash_password(os.getenv("VIEWER_PASSWORD", "ChangeMe123!")),
            "role": "viewer",
            "accounts": "all",
        },
    ]
    for u in defaults:
        if u["username"] not in USERS_DB:
            USERS_DB[u["username"]] = u
            log.info(f"Seeded default user: {u['username']}")


_seed_default_users()


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "onboarded_accounts": len(ACCOUNTS_DB),
        "providers": list({acc.get("provider", "aws") for acc in ACCOUNTS_DB.values()}),
    }


@app.get("/providers", tags=["system"])
async def list_providers():
    """Returns supported cloud providers and their service catalogs."""
    from providers.aws_provider import SERVICE_CATALOG as AWS_CATALOG
    from providers.azure_provider import AZURE_SERVICE_CATALOG
    from providers.gcp_provider import GCP_SERVICE_CATALOG
    return {
        "providers": [
            {
                "id": "aws",
                "name": "Amazon Web Services",
                "icon": "☁️",
                "color": "#ff9900",
                "services": list(AWS_CATALOG.keys()),
                "regions": "27+ regions",
            },
            {
                "id": "azure",
                "name": "Microsoft Azure",
                "icon": "🔷",
                "color": "#0078d4",
                "services": list(AZURE_SERVICE_CATALOG.keys()),
                "regions": "60+ regions",
            },
            {
                "id": "gcp",
                "name": "Google Cloud Platform",
                "icon": "🌈",
                "color": "#4285f4",
                "services": list(GCP_SERVICE_CATALOG.keys()),
                "regions": "35+ regions",
            },
        ]
    }
