"""
Alarms router — cross-cloud alarm aggregation + CloudWatch alarm CRUD.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.database import ACCOUNTS_DB
from core.security import get_current_user, require_admin

log = logging.getLogger("cloudops.alarms")
router = APIRouter(tags=["alarms"])


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


# ── Global alarms across all accounts ────────────────────────────────────────

@router.get("/alarms")
async def get_all_alarms(current_user: dict = Depends(get_current_user)):
    """Aggregate active alarms across all onboarded accounts (all providers)."""
    all_alarms = []

    for acc_id, acc in ACCOUNTS_DB.items():
        if current_user["accounts"] != "all" and acc_id not in current_user["accounts"]:
            continue
        provider = acc.get("provider", "aws")
        try:
            alarms = _fetch_alarms_for_account(acc_id, acc, provider)
            for a in alarms:
                a["accountId"] = acc_id
                a["accountName"] = acc["name"]
                a["provider"] = provider
            all_alarms.extend(alarms)
        except Exception as e:
            log.warning(f"Could not fetch alarms for {acc_id}: {e}")

    # Deduplicate
    seen, deduped = set(), []
    for a in all_alarms:
        key = (a.get("accountId"), a.get("metric"), a.get("name"))
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    return {"alarms": deduped, "total": len(deduped)}


def _fetch_alarms_for_account(acc_id: str, acc: dict, provider: str) -> list:
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
    return []


# ── Per-account alarm endpoints (AWS only) ────────────────────────────────────

@router.get("/accounts/{account_id}/alarms")
async def get_account_alarms(
    account_id: str,
    current_user: dict = Depends(get_current_user),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    alarms = _fetch_alarms_for_account(account_id, acc, acc.get("provider", "aws"))
    return {"accountId": account_id, "alarms": alarms, "total": len(alarms)}


@router.get("/accounts/{account_id}/alarms/list")
async def list_all_alarms(
    account_id: str,
    current_user: dict = Depends(get_current_user),
):
    """List ALL CloudWatch alarms (any state) for an AWS account."""
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    if acc.get("provider", "aws") != "aws":
        raise HTTPException(400, "Alarm listing only supported for AWS accounts")
    try:
        from main import get_aws_session
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        cw = session.client("cloudwatch", region_name=acc["region"])
        response = cw.describe_alarms(MaxRecords=50)
        alarms = [
            {
                "name": a["AlarmName"],
                "metric": a["MetricName"],
                "namespace": a.get("Namespace", ""),
                "threshold": a.get("Threshold", 0),
                "comparison": a.get("ComparisonOperator", ""),
                "state": a.get("StateValue", "UNKNOWN"),
                "description": a.get("AlarmDescription", ""),
                "updated": (
                    a["StateUpdatedTimestamp"].strftime("%Y-%m-%d %H:%M UTC")
                    if "StateUpdatedTimestamp" in a else "—"
                ),
            }
            for a in response.get("MetricAlarms", [])
        ]
        return {"accountId": account_id, "alarms": alarms, "total": len(alarms)}
    except Exception as e:
        raise HTTPException(400, f"Failed to list alarms: {str(e)}")


@router.post("/accounts/{account_id}/alarms/create", status_code=201)
async def create_alarm(
    account_id: str,
    payload: CreateAlarmRequest,
    admin: dict = Depends(require_admin),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    if acc.get("provider", "aws") != "aws":
        raise HTTPException(400, "Alarm creation only supported for AWS accounts")
    try:
        from main import get_aws_session
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        cw = session.client("cloudwatch", region_name=acc["region"])
        cw.put_metric_alarm(
            AlarmName=payload.alarm_name,
            AlarmDescription=payload.alarm_description or f"CloudOps: {payload.metric_name}",
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
        return {"message": f"Alarm '{payload.alarm_name}' created", "accountId": account_id}
    except Exception as e:
        raise HTTPException(400, f"Failed to create alarm: {str(e)}")


@router.delete("/accounts/{account_id}/alarms/{alarm_name}")
async def delete_alarm(
    account_id: str,
    alarm_name: str,
    admin: dict = Depends(require_admin),
):
    acc = ACCOUNTS_DB.get(account_id)
    if not acc:
        raise HTTPException(404, "Account not found")
    try:
        from main import get_aws_session
        session = get_aws_session(acc["role_arn"], acc.get("external_id"), acc["region"])
        cw = session.client("cloudwatch", region_name=acc["region"])
        cw.delete_alarms(AlarmNames=[alarm_name])
        return {"message": f"Alarm '{alarm_name}' deleted"}
    except Exception as e:
        raise HTTPException(400, f"Failed to delete alarm: {str(e)}")
