"""
Admin router — account onboarding, user management, SMTP config, audit log.
All endpoints require admin role.
"""
import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, field_validator

from audit import audit, get_audit_log
from core.database import ACCOUNTS_DB, USERS_DB
from core.security import get_current_user, hash_password, require_admin, validate_password_strength
from email_service import get_smtp_config, save_smtp_config, send_welcome_email
from routers.accounts import cache_bust

log = logging.getLogger("cloudops.admin")
router = APIRouter(prefix="/admin", tags=["admin"])

_VALID_PROVIDERS = {"aws", "azure", "gcp"}
_VALID_ENVS = {"PROD", "STAGING", "DEV", "DR"}
_VALID_ROLES = {"admin", "viewer"}
_ACCOUNT_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{3,64}$")

# Sensitive credential fields that must never be returned in list responses
_SENSITIVE_ACCOUNT_FIELDS = {
    "role_arn", "external_id", "client_secret",
    "service_account_key", "client_id", "tenant_id",
}


# ── Pydantic models ───────────────────────────────────────────────────────────

class OnboardRequest(BaseModel):
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
    provider: str = "aws"

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
    service_account_key: Optional[str] = None
    billing_table: Optional[str] = None

    @field_validator("account_id")
    @classmethod
    def validate_account_id(cls, v: str) -> str:
        if not _ACCOUNT_ID_RE.match(v):
            raise ValueError("account_id must be 3-64 alphanumeric/hyphen/underscore characters")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        if v not in _VALID_PROVIDERS:
            raise ValueError(f"provider must be one of: {_VALID_PROVIDERS}")
        return v

    @field_validator("env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        if v not in _VALID_ENVS:
            raise ValueError(f"env must be one of: {_VALID_ENVS}")
        return v

    @field_validator("cpu_threshold", "mem_threshold")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        if not (0.0 < v <= 100.0):
            raise ValueError("Threshold must be between 0 and 100")
        return v

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one service must be selected")
        return v


class CreateUserRequest(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str
    role: str
    accounts: Union[str, List[str]] = "all"
    send_welcome: bool = True

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]{3,32}$", v):
            raise ValueError("username must be 3-32 alphanumeric/hyphen/underscore characters")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in _VALID_ROLES:
            raise ValueError(f"role must be one of: {_VALID_ROLES}")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        try:
            validate_password_strength(v)
        except ValueError as e:
            raise ValueError(str(e))
        return v


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


class UpdateRegionsRequest(BaseModel):
    extra_regions: List[str]


class UpdateUserRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    accounts: Optional[Union[str, List[str]]] = None
    password: Optional[str] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _VALID_ROLES:
            raise ValueError(f"role must be one of: {_VALID_ROLES}")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            try:
                validate_password_strength(v)
            except ValueError as e:
                raise ValueError(str(e))
        return v


# ── Account onboarding ────────────────────────────────────────────────────────

@router.post("/accounts/onboard", status_code=201)
async def onboard_account(
    payload: OnboardRequest,
    admin: dict = Depends(require_admin),
):
    _validate_provider_connectivity(payload)

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
    log.info("Account onboarded: %s (%s) by %s", payload.name, payload.account_id, admin["username"])
    return {
        "message": f"Account {payload.name} ({payload.account_id}) onboarded successfully",
        "accountId": payload.account_id,
        "provider": payload.provider,
    }


def _validate_provider_connectivity(payload: OnboardRequest) -> None:
    try:
        if payload.provider == "aws":
            if not payload.role_arn:
                raise HTTPException(400, "role_arn is required for AWS accounts")
            import boto3
            sts = boto3.client("sts")
            kwargs: dict = {"RoleArn": payload.role_arn, "RoleSessionName": "CloudOpsValidation"}
            if payload.external_id:
                kwargs["ExternalId"] = payload.external_id
            sts.assume_role(**kwargs)

        elif payload.provider == "azure":
            missing = [
                f for f in ["subscription_id", "tenant_id", "client_id", "client_secret"]
                if not getattr(payload, f)
            ]
            if missing:
                raise HTTPException(400, f"Missing required Azure fields: {missing}")
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient
            cred = ClientSecretCredential(
                payload.tenant_id, payload.client_id, payload.client_secret
            )
            next(iter(ResourceManagementClient(cred, payload.subscription_id).resource_groups.list()), None)

        elif payload.provider == "gcp":
            if not payload.project_id:
                raise HTTPException(400, "project_id is required for GCP accounts")
            from providers.gcp_provider import get_gcp_credentials
            get_gcp_credentials({"service_account_key": payload.service_account_key})

    except HTTPException:
        raise
    except Exception as exc:
        log.warning("Provider validation failed for %s: %s", payload.provider, exc)
        raise HTTPException(400, f"Provider validation failed: {exc}") from exc


@router.patch("/accounts/{account_id}/regions")
async def update_account_regions(
    account_id: str,
    body: UpdateRegionsRequest,
    admin: dict = Depends(require_admin),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    acc["extra_regions"] = body.extra_regions
    ACCOUNTS_DB[account_id] = acc
    cache_bust(account_id)
    return {"message": "Extra regions updated", "accountId": account_id, "extra_regions": body.extra_regions}


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
    """Returns account list with all sensitive credential fields stripped."""
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
        # Send welcome email without the plaintext password — user must use reset flow
        asyncio.create_task(
            send_welcome_email(str(payload.email), payload.name, payload.username, "")
        )
    return {"message": f"User {payload.username} created"}


@router.patch("/users/{username}")
async def update_user(
    username: str,
    body: UpdateUserRequest,
    admin: dict = Depends(require_admin),
):
    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(404, "User not found")

    if body.name is not None:
        user["name"] = body.name
    if body.email is not None:
        user["email"] = str(body.email)
    if body.role is not None:
        user["role"] = body.role
    if body.accounts is not None:
        user["accounts"] = body.accounts
    if body.password:
        user["hashed_password"] = hash_password(body.password)

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
        cfg.pop("password", None)   # never return the SMTP password
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
    if not user or not user.get("email"):
        raise HTTPException(400, "Admin account has no email address configured")
    ok = await send_email(
        user["email"],
        "CloudOps Central — SMTP Test",
        "<p style='color:#10d97a;font-family:monospace;'>✅ SMTP is working correctly.</p>",
    )
    if not ok:
        raise HTTPException(400, "SMTP test failed — check your configuration and server logs")
    return {"message": "Test email sent successfully"}


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit")
async def list_audit_log(
    limit: int = 200,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    admin: dict = Depends(require_admin),
):
    if limit < 1 or limit > 1000:
        raise HTTPException(400, "limit must be between 1 and 1000")
    logs = get_audit_log(limit=limit, actor=actor, action=action)
    return {"logs": logs, "total": len(logs)}
