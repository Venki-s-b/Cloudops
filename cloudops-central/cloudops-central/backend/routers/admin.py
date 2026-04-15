"""
Admin router — account onboarding, user management, SMTP config, audit log.
All endpoints require admin role.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr

from audit import audit, get_audit_log
from core.database import ACCOUNTS_DB, USERS_DB
from core.security import get_current_user, hash_password, require_admin
from email_service import (
    get_smtp_config, save_smtp_config,
    send_welcome_email,
)
from routers.accounts import cache_bust

log = logging.getLogger("cloudops.admin")
router = APIRouter(prefix="/admin", tags=["admin"])


# ── Pydantic models ───────────────────────────────────────────────────────────

class OnboardRequest(BaseModel):
    # Common
    account_id: str
    name: str
    region: str
    env: str
    owner: str
    services: List[str]
    extra_regions: List[str] = []
    cpu_threshold: float = 75.0
    mem_threshold: float = 80.0
    alert_email: Optional[str] = None
    description: Optional[str] = None
    provider: str = "aws"          # aws | azure | gcp

    # AWS
    role_arn: Optional[str] = None
    external_id: Optional[str] = None

    # Azure
    subscription_id: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    # GCP
    project_id: Optional[str] = None
    service_account_key: Optional[str] = None  # JSON string or file path
    billing_table: Optional[str] = None


class CreateUserRequest(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str
    role: str
    accounts: Union[str, List[str]] = "all"
    send_welcome: bool = True


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


# ── Account onboarding ────────────────────────────────────────────────────────

@router.post("/accounts/onboard", status_code=201)
async def onboard_account(
    payload: OnboardRequest,
    admin: dict = Depends(require_admin),
    request: Request = None,
):
    # Validate connectivity before saving
    _validate_provider(payload)

    record = {
        "name": payload.name,
        "provider": payload.provider,
        "region": payload.region,
        "env": payload.env,
        "owner": payload.owner,
        "services": payload.services,
        "extra_regions": [r for r in payload.extra_regions if r != payload.region],
        "thresholds": {"cpu": payload.cpu_threshold, "memory": payload.mem_threshold},
        "alert_email": payload.alert_email,
        "description": payload.description,
        "onboarded_by": admin["username"],
        "onboarded_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }

    # Provider-specific credentials
    if payload.provider == "aws":
        record["role_arn"] = payload.role_arn
        record["external_id"] = payload.external_id
    elif payload.provider == "azure":
        record["subscription_id"] = payload.subscription_id
        record["tenant_id"] = payload.tenant_id
        record["client_id"] = payload.client_id
        record["client_secret"] = payload.client_secret
    elif payload.provider == "gcp":
        record["project_id"] = payload.project_id
        record["service_account_key"] = payload.service_account_key
        record["billing_table"] = payload.billing_table

    ACCOUNTS_DB[payload.account_id] = record
    cache_bust(payload.account_id)
    audit(
        admin["username"], "ACCOUNT_ONBOARD",
        resource=payload.account_id,
        detail={"name": payload.name, "provider": payload.provider, "region": payload.region},
    )
    return {
        "message": f"Account {payload.name} ({payload.account_id}) onboarded successfully",
        "accountId": payload.account_id,
        "provider": payload.provider,
    }


def _validate_provider(payload: OnboardRequest):
    """Quick connectivity check before saving credentials."""
    try:
        if payload.provider == "aws":
            if not payload.role_arn:
                raise HTTPException(400, "role_arn is required for AWS accounts")
            import boto3
            sts = boto3.client("sts")
            kwargs = {"RoleArn": payload.role_arn, "RoleSessionName": "CloudOpsValidation"}
            if payload.external_id:
                kwargs["ExternalId"] = payload.external_id
            sts.assume_role(**kwargs)

        elif payload.provider == "azure":
            if not all([payload.subscription_id, payload.tenant_id, payload.client_id, payload.client_secret]):
                raise HTTPException(400, "subscription_id, tenant_id, client_id, client_secret required for Azure")
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient
            cred = ClientSecretCredential(payload.tenant_id, payload.client_id, payload.client_secret)
            ResourceManagementClient(cred, payload.subscription_id).resource_groups.list().__next__()

        elif payload.provider == "gcp":
            if not payload.project_id:
                raise HTTPException(400, "project_id is required for GCP accounts")
            # Light validation — just check credentials load
            from providers.gcp_provider import get_gcp_credentials
            get_gcp_credentials({"service_account_key": payload.service_account_key})

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Provider validation failed: {str(e)}")


@router.patch("/accounts/{account_id}/regions")
async def update_account_regions(
    account_id: str,
    body: dict,
    admin: dict = Depends(require_admin),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    extra = body.get("extra_regions", [])
    if not isinstance(extra, list):
        raise HTTPException(400, "extra_regions must be a list")
    acc["extra_regions"] = extra
    ACCOUNTS_DB[account_id] = acc
    cache_bust(account_id)
    return {"message": f"Extra regions updated", "accountId": account_id, "extra_regions": extra}


@router.delete("/accounts/{account_id}")
async def remove_account(account_id: str, admin: dict = Depends(require_admin)):
    if account_id not in ACCOUNTS_DB:
        raise HTTPException(404, "Account not found")
    del ACCOUNTS_DB[account_id]
    cache_bust(account_id)
    audit(admin["username"], "ACCOUNT_REMOVE", resource=account_id)
    return {"message": f"Account {account_id} removed"}


@router.get("/accounts")
async def admin_list_accounts(admin: dict = Depends(require_admin)):
    safe_fields = {"id", "name", "provider", "region", "env", "owner", "services", "status", "onboarded_at"}
    return {
        "accounts": [
            {k: v for k, v in {**{"id": acc_id}, **acc}.items() if k in safe_fields}
            for acc_id, acc in ACCOUNTS_DB.items()
        ]
    }


# ── User management ───────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)):
    return {
        "users": [
            {k: v for k, v in u.items() if k != "hashed_password"}
            for u in USERS_DB.values()
        ]
    }


@router.post("/users", status_code=201)
async def create_user(payload: CreateUserRequest, admin: dict = Depends(require_admin)):
    if payload.username in USERS_DB:
        raise HTTPException(409, "Username already exists")
    if payload.role not in ("admin", "viewer"):
        raise HTTPException(400, "Role must be 'admin' or 'viewer'")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    USERS_DB[payload.username] = {
        "username": payload.username,
        "name": payload.name,
        "email": str(payload.email),
        "hashed_password": hash_password(payload.password),
        "role": payload.role,
        "accounts": payload.accounts,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": admin["username"],
    }
    audit(admin["username"], "USER_CREATE", resource=payload.username, detail={"role": payload.role})
    if payload.send_welcome:
        asyncio.create_task(
            send_welcome_email(str(payload.email), payload.name, payload.username, payload.password)
        )
    return {"message": f"User {payload.username} created"}


@router.patch("/users/{username}")
async def update_user(username: str, body: dict, admin: dict = Depends(require_admin)):
    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(404, "User not found")
    for k in ("name", "email", "role", "accounts"):
        if k in body:
            user[k] = body[k]
    if body.get("password"):
        if len(body["password"]) < 8:
            raise HTTPException(400, "Password must be at least 8 characters")
        user["hashed_password"] = hash_password(body["password"])
    USERS_DB[username] = user
    audit(admin["username"], "USER_UPDATE", resource=username)
    return {"message": f"User {username} updated"}


@router.delete("/users/{username}")
async def delete_user(username: str, admin: dict = Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(400, "Cannot delete your own account")
    if username not in USERS_DB:
        raise HTTPException(404, "User not found")
    del USERS_DB[username]
    audit(admin["username"], "USER_DELETE", resource=username)
    return {"message": f"User {username} deleted"}


# ── SMTP ──────────────────────────────────────────────────────────────────────

@router.get("/smtp")
async def get_smtp(admin: dict = Depends(require_admin)):
    cfg = get_smtp_config()
    if cfg:
        cfg.pop("password", None)
    return {"config": cfg}


@router.post("/smtp")
async def set_smtp(payload: SmtpConfigRequest, admin: dict = Depends(require_admin)):
    save_smtp_config(payload.model_dump())
    audit(admin["username"], "SMTP_CONFIG_UPDATE")
    return {"message": "SMTP configuration saved"}


@router.post("/smtp/test")
async def test_smtp(admin: dict = Depends(require_admin)):
    from email_service import send_email
    user = USERS_DB.get(admin["username"])
    ok = await send_email(
        user.get("email", ""),
        "CloudOps Central — SMTP Test",
        "<p style='color:#10d97a;font-family:monospace;'>✅ SMTP is working correctly.</p>",
    )
    if not ok:
        raise HTTPException(400, "SMTP test failed — check your configuration")
    return {"message": "Test email sent successfully"}


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit")
async def list_audit_log(
    limit: int = 200,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    admin: dict = Depends(require_admin),
):
    logs = get_audit_log(limit=limit, actor=actor, action=action)
    return {"logs": logs, "total": len(logs)}
