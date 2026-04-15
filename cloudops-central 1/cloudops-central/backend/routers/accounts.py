"""
Accounts router — multi-cloud account management (AWS / Azure / GCP).
GET  /accounts              — list all with live health
GET  /accounts/{id}         — detail with per-service metrics
GET  /accounts/{id}/costs   — cost explorer data
GET  /accounts/{id}/resources — flat resource list by region
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from fastapi import APIRouter, Depends, HTTPException, Request

from core.database import ACCOUNTS_DB
from core.security import get_current_user

log = logging.getLogger("cloudops.accounts")
router = APIRouter(prefix="/accounts", tags=["accounts"])

# Per-account response cache (TTL = 90s)
_CACHE: dict = {}
_CACHE_TTL = 90


def _cache_get(key: str):
    entry = _CACHE.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
        return entry["payload"]
    return None


def _cache_set(key: str, payload):
    _CACHE[key] = {"ts": time.time(), "payload": payload}


def cache_bust(account_id: str):
    for k in list(_CACHE.keys()):
        if k == account_id or k.startswith(f"{account_id}:"):
            _CACHE.pop(k, None)


# ── Provider dispatch ─────────────────────────────────────────────────────────

def _get_health_and_resources(acc_id: str, acc: dict, target_region: str):
    provider = acc.get("provider", "aws")

    if provider == "aws":
        return _aws_health_resources(acc_id, acc, target_region)
    elif provider == "azure":
        return _azure_health_resources(acc_id, acc, target_region)
    elif provider == "gcp":
        return _gcp_health_resources(acc_id, acc, target_region)
    return {"status": "unknown", "alerts": 0, "metrics": {}}, {}


def _aws_health_resources(acc_id, acc, target_region):
    from providers.aws_provider import fetch_health, fetch_resources
    from main import get_aws_session

    health = {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}
    resources = {}
    try:
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), target_region)
        cw = session.client("cloudwatch", region_name=target_region)
        health = fetch_health(cw, acc)
        scoped = dict(acc, region=target_region, extra_regions=[])
        resources = fetch_resources(session, scoped)
    except Exception as e:
        log.warning(f"AWS health/resources [{acc_id}][{target_region}]: {e}")
    return health, resources


def _azure_health_resources(acc_id, acc, target_region):
    from providers.azure_provider import fetch_azure_health, fetch_azure_resources
    health = {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}
    resources = {}
    try:
        health = fetch_azure_health(acc)
        resources = fetch_azure_resources(acc)
    except Exception as e:
        log.warning(f"Azure health/resources [{acc_id}]: {e}")
    return health, resources


def _gcp_health_resources(acc_id, acc, target_region):
    from providers.gcp_provider import fetch_gcp_health, fetch_gcp_resources
    health = {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}
    resources = {}
    try:
        health = fetch_gcp_health(acc)
        resources = fetch_gcp_resources(acc)
    except Exception as e:
        log.warning(f"GCP health/resources [{acc_id}]: {e}")
    return health, resources


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_accounts(
    region: Optional[str] = None,
    provider: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    acc_items = [
        (acc_id, acc)
        for acc_id, acc in ACCOUNTS_DB.items()
        if (current_user["accounts"] == "all" or acc_id in current_user["accounts"])
        and (provider is None or acc.get("provider", "aws") == provider)
        and (
            region is None
            or acc.get("region") == region
            or region in acc.get("extra_regions", [])
        )
    ]

    def fetch_one(item):
        acc_id, acc = item
        target_region = region if region else acc["region"]
        cache_key = f"{acc_id}:{target_region}"
        cached = _cache_get(cache_key)
        if cached:
            return cached

        health, resources = _get_health_and_resources(acc_id, acc, target_region)

        payload = {
            "id": acc_id,
            "name": acc["name"],
            "provider": acc.get("provider", "aws"),
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
            "consoleUrl": _console_url(acc, target_region),
        }
        _cache_set(cache_key, payload)
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


@router.get("/{account_id}")
async def get_account(
    account_id: str,
    current_user: dict = Depends(get_current_user),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")

    provider = acc.get("provider", "aws")
    health, resources = _get_health_and_resources(account_id, acc, acc["region"])

    alarms = _get_alarms(acc, provider)

    return {
        "id": account_id,
        "name": acc["name"],
        "provider": provider,
        "region": acc["region"],
        "env": acc["env"],
        "owner": acc["owner"],
        "services": acc["services"],
        "status": health["status"],
        "alerts": health["alerts"],
        "metrics": health["metrics"],
        "resources": resources,
        "activeAlerts": alarms,
        "consoleUrl": _console_url(acc, acc["region"]),
    }


@router.get("/{account_id}/costs")
async def get_costs(
    account_id: str,
    current_user: dict = Depends(get_current_user),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")

    provider = acc.get("provider", "aws")
    try:
        if provider == "aws":
            from main import get_aws_session
            session = get_aws_session(acc["role_arn"], acc.get("external_id"), "us-east-1")
            ce = session.client("ce", region_name="us-east-1")
            end = datetime.now(timezone.utc).date()
            start = (end.replace(day=1) - timedelta(days=150)).replace(day=1)
            resp = ce.get_cost_and_usage(
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
                for r in resp["ResultsByTime"]
            ]
        elif provider == "azure":
            from providers.azure_provider import fetch_azure_costs
            monthly = fetch_azure_costs(acc)
        elif provider == "gcp":
            from providers.gcp_provider import fetch_gcp_costs
            monthly = fetch_gcp_costs(acc)
        else:
            monthly = []
        return {"accountId": account_id, "provider": provider, "monthly": monthly}
    except Exception as e:
        raise HTTPException(500, f"Cost data error: {str(e)}")


@router.get("/{account_id}/resources")
async def get_resources_by_region(
    account_id: str,
    region: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")

    target_region = region or acc["region"]
    _, resources = _get_health_and_resources(account_id, acc, target_region)

    flat = [
        {**r, "service": svc}
        for svc, rows in resources.items()
        for r in rows
    ]
    return {"accountId": account_id, "region": target_region, "resources": flat, "total": len(flat)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _console_url(acc: dict, region: str) -> str:
    provider = acc.get("provider", "aws")
    if provider == "aws":
        return f"https://{region}.console.aws.amazon.com/console/home?region={region}"
    elif provider == "azure":
        return "https://portal.azure.com"
    elif provider == "gcp":
        return f"https://console.cloud.google.com/home/dashboard?project={acc.get('project_id', '')}"
    return "#"


def _get_alarms(acc: dict, provider: str) -> list:
    try:
        if provider == "aws":
            from main import get_aws_session
            from providers.aws_provider import fetch_active_alarms
            session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
            cw = session.client("cloudwatch", region_name=acc["region"])
            return fetch_active_alarms(cw, region=acc["region"])
        elif provider == "azure":
            from providers.azure_provider import fetch_azure_active_alarms
            return fetch_azure_active_alarms(acc)
        elif provider == "gcp":
            from providers.gcp_provider import fetch_gcp_active_alarms
            return fetch_gcp_active_alarms(acc)
    except Exception as e:
        log.warning(f"_get_alarms error: {e}")
    return []
