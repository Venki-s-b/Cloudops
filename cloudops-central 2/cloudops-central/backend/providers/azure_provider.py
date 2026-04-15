"""
Azure Cloud Provider Adapter
Handles VMs, AKS, SQL, Storage, App Services, Functions via Azure Monitor + SDK
Requires: azure-identity, azure-mgmt-compute, azure-mgmt-monitor,
          azure-mgmt-resource, azure-mgmt-storage, azure-mgmt-sql
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger("cloudops.azure")

AZURE_SERVICE_CATALOG = {
    "VirtualMachines": {"icon": "🖥️",  "color": "#0078d4", "namespace": "Microsoft.Compute/virtualMachines"},
    "AKS":             {"icon": "☸️",  "color": "#326ce5", "namespace": "Microsoft.ContainerService/managedClusters"},
    "SQLDatabase":     {"icon": "🗄️",  "color": "#a78bfa", "namespace": "Microsoft.Sql/servers/databases"},
    "StorageAccounts": {"icon": "🪣",  "color": "#00e5a0", "namespace": "Microsoft.Storage/storageAccounts"},
    "AppService":      {"icon": "🌐",  "color": "#f0c040", "namespace": "Microsoft.Web/sites"},
    "Functions":       {"icon": "λ",   "color": "#fb923c", "namespace": "Microsoft.Web/sites"},
    "CosmosDB":        {"icon": "⚡",  "color": "#fb923c", "namespace": "Microsoft.DocumentDB/databaseAccounts"},
    "LoadBalancer":    {"icon": "⚖️",  "color": "#38b6ff", "namespace": "Microsoft.Network/loadBalancers"},
    "VirtualNetwork":  {"icon": "🔗",  "color": "#a78bfa", "namespace": "Microsoft.Network/virtualNetworks"},
    "KeyVault":        {"icon": "🔑",  "color": "#f05050", "namespace": "Microsoft.KeyVault/vaults"},
}

AZURE_REGIONS = [
    "eastus", "eastus2", "westus", "westus2", "westus3",
    "centralus", "northcentralus", "southcentralus", "westcentralus",
    "northeurope", "westeurope", "uksouth", "ukwest",
    "francecentral", "germanywestcentral", "switzerlandnorth",
    "norwayeast", "swedencentral",
    "eastasia", "southeastasia", "japaneast", "japanwest",
    "australiaeast", "australiasoutheast",
    "centralindia", "southindia", "westindia",
    "canadacentral", "canadaeast",
    "brazilsouth", "southafricanorth", "uaenorth",
]


def get_azure_credential(acc: dict):
    """
    Returns an Azure credential object.
    Supports: Service Principal (client_id + client_secret + tenant_id)
              or Managed Identity (when running on Azure).
    """
    try:
        from azure.identity import ClientSecretCredential, ManagedIdentityCredential
        if acc.get("client_id") and acc.get("client_secret") and acc.get("tenant_id"):
            return ClientSecretCredential(
                tenant_id=acc["tenant_id"],
                client_id=acc["client_id"],
                client_secret=acc["client_secret"],
            )
        return ManagedIdentityCredential()
    except ImportError:
        raise RuntimeError(
            "Azure SDK not installed. Run: pip install azure-identity azure-mgmt-compute "
            "azure-mgmt-monitor azure-mgmt-resource azure-mgmt-storage azure-mgmt-sql"
        )


def fetch_azure_resources(acc: dict) -> dict:
    """Fetch all resources for configured Azure services."""
    resources: dict = {}
    subscription_id = acc.get("subscription_id", "")
    if not subscription_id:
        log.warning("Azure account missing subscription_id")
        return resources

    try:
        credential = get_azure_credential(acc)
    except Exception as e:
        log.warning(f"Azure credential error: {e}")
        return resources

    for svc in acc.get("services", []):
        try:
            rows = _fetch_azure_svc(credential, subscription_id, svc, acc.get("region", "eastus"))
            resources[svc] = rows
        except Exception as e:
            log.warning(f"Azure fetch_resources [{svc}]: {e}")
            resources[svc] = []

    return resources


def _fetch_azure_svc(credential, subscription_id: str, svc: str, region: str) -> list:
    rows = []

    if svc == "VirtualMachines":
        try:
            from azure.mgmt.compute import ComputeManagementClient
            client = ComputeManagementClient(credential, subscription_id)
            for vm in client.virtual_machines.list_all():
                state = "unknown"
                try:
                    iv = client.virtual_machines.instance_view(
                        vm.id.split("/")[4], vm.name
                    )
                    statuses = iv.statuses or []
                    power = next(
                        (s.display_status for s in statuses if s.code and s.code.startswith("PowerState/")),
                        "unknown",
                    )
                    state = power.lower().replace("vm ", "")
                except Exception:
                    pass
                rows.append({
                    "id": vm.name,
                    "label": vm.name,
                    "type": vm.hardware_profile.vm_size if vm.hardware_profile else "—",
                    "az": vm.location,
                    "region": vm.location,
                    "state": state,
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "provider": "azure",
                    "consoleUrl": (
                        f"https://portal.azure.com/#resource{vm.id}/overview"
                    ),
                })
        except Exception as e:
            log.warning(f"Azure VMs fetch error: {e}")

    elif svc == "StorageAccounts":
        try:
            from azure.mgmt.storage import StorageManagementClient
            client = StorageManagementClient(credential, subscription_id)
            for sa in client.storage_accounts.list():
                rows.append({
                    "id": sa.name, "label": sa.name,
                    "type": sa.sku.name if sa.sku else "Standard_LRS",
                    "az": sa.location, "region": sa.location,
                    "state": sa.provisioning_state or "Succeeded",
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "provider": "azure",
                })
        except Exception as e:
            log.warning(f"Azure Storage fetch error: {e}")

    elif svc == "SQLDatabase":
        try:
            from azure.mgmt.sql import SqlManagementClient
            client = SqlManagementClient(credential, subscription_id)
            for server in client.servers.list():
                rg = server.id.split("/")[4]
                for db in client.databases.list_by_server(rg, server.name):
                    if db.name == "master":
                        continue
                    rows.append({
                        "id": db.name, "label": db.name,
                        "type": db.sku.name if db.sku else "—",
                        "az": db.location, "region": db.location,
                        "state": db.status or "Online",
                        "cpu": "—", "mem": "—", "uptime": "—",
                        "provider": "azure",
                    })
        except Exception as e:
            log.warning(f"Azure SQL fetch error: {e}")

    elif svc == "AppService":
        try:
            from azure.mgmt.web import WebSiteManagementClient
            client = WebSiteManagementClient(credential, subscription_id)
            for app in client.web_apps.list():
                rows.append({
                    "id": app.name, "label": app.name,
                    "type": app.kind or "app",
                    "az": app.location, "region": app.location,
                    "state": app.state or "Running",
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "provider": "azure",
                })
        except Exception as e:
            log.warning(f"Azure AppService fetch error: {e}")

    return rows


def fetch_azure_health(acc: dict) -> dict:
    """Fetch Azure Monitor alerts and aggregate health."""
    try:
        credential = get_azure_credential(acc)
        subscription_id = acc.get("subscription_id", "")
        from azure.mgmt.monitor import MonitorManagementClient
        monitor = MonitorManagementClient(credential, subscription_id)

        fired = list(monitor.alert_rules.list_by_subscription())
        count = len(fired)
        status = "healthy" if count == 0 else "warning"
        return {
            "status": status, "alerts": count,
            "metrics": {"cpu": "—", "alerts": count},
        }
    except Exception as e:
        log.warning(f"Azure fetch_health error: {e}")
        return {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}


def fetch_azure_active_alarms(acc: dict) -> list:
    """Fetch active Azure Monitor metric alerts."""
    try:
        credential = get_azure_credential(acc)
        subscription_id = acc.get("subscription_id", "")
        from azure.mgmt.monitor import MonitorManagementClient
        monitor = MonitorManagementClient(credential, subscription_id)
        results = []
        now = datetime.now(timezone.utc)
        for alert in monitor.metric_alerts.list_by_subscription():
            results.append({
                "name": alert.name,
                "service": "Azure Monitor",
                "region": acc.get("region", "—"),
                "sev": "warning",
                "metric": alert.name,
                "metricLabel": alert.description or alert.name,
                "threshold": None,
                "currentValue": None,
                "unit": "",
                "stateReason": alert.description or "",
                "time": now.strftime("%H:%M UTC"),
                "timeISO": now.isoformat(),
                "provider": "azure",
            })
        return results
    except Exception as e:
        log.warning(f"Azure fetch_active_alarms error: {e}")
        return []


def fetch_azure_costs(acc: dict) -> list:
    """Fetch Azure cost data via Cost Management API."""
    try:
        credential = get_azure_credential(acc)
        subscription_id = acc.get("subscription_id", "")
        from azure.mgmt.costmanagement import CostManagementClient
        from azure.mgmt.costmanagement.models import (
            QueryDefinition, QueryTimePeriod, QueryDataset,
            QueryAggregation, QueryGrouping, TimeframeType,
        )
        client = CostManagementClient(credential)
        scope = f"/subscriptions/{subscription_id}"
        now = datetime.now(timezone.utc)
        start = (now.replace(day=1) - timedelta(days=150)).replace(day=1)

        query = QueryDefinition(
            type="ActualCost",
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(from_property=start, to=now),
            dataset=QueryDataset(
                granularity="Monthly",
                aggregation={"totalCost": QueryAggregation(name="Cost", function="Sum")},
            ),
        )
        result = client.query.usage(scope, query)
        rows = []
        for row in (result.rows or []):
            rows.append({
                "month": str(row[1])[:7] if len(row) > 1 else "—",
                "cost": float(row[0]) if row else 0.0,
                "unit": "USD",
            })
        return rows
    except Exception as e:
        log.warning(f"Azure fetch_costs error: {e}")
        return []
