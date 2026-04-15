"""
GCP Cloud Provider Adapter
Handles GCE, GKE, Cloud SQL, Cloud Storage, Cloud Functions, Cloud Run
via Google Cloud Python SDK (google-cloud-*)
Requires: google-cloud-monitoring, google-cloud-compute, google-cloud-storage,
          google-cloud-billing, google-auth
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger("cloudops.gcp")

GCP_SERVICE_CATALOG = {
    "ComputeEngine":   {"icon": "🖥️",  "color": "#4285f4", "namespace": "compute.googleapis.com"},
    "GKE":             {"icon": "☸️",  "color": "#326ce5", "namespace": "container.googleapis.com"},
    "CloudSQL":        {"icon": "🗄️",  "color": "#a78bfa", "namespace": "sqladmin.googleapis.com"},
    "CloudStorage":    {"icon": "🪣",  "color": "#00e5a0", "namespace": "storage.googleapis.com"},
    "CloudFunctions":  {"icon": "λ",   "color": "#fb923c", "namespace": "cloudfunctions.googleapis.com"},
    "CloudRun":        {"icon": "🚀",  "color": "#38b6ff", "namespace": "run.googleapis.com"},
    "BigQuery":        {"icon": "📊",  "color": "#f0c040", "namespace": "bigquery.googleapis.com"},
    "Firestore":       {"icon": "🔥",  "color": "#ff6d00", "namespace": "firestore.googleapis.com"},
    "PubSub":          {"icon": "📢",  "color": "#a78bfa", "namespace": "pubsub.googleapis.com"},
    "LoadBalancing":   {"icon": "⚖️",  "color": "#34a853", "namespace": "compute.googleapis.com/loadbalancing"},
}

GCP_REGIONS = [
    "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
    "northamerica-northeast1", "northamerica-northeast2",
    "southamerica-east1", "southamerica-west1",
    "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
    "europe-central2", "europe-north1",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
    "asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
    "australia-southeast1", "australia-southeast2",
    "me-west1", "me-central1", "africa-south1",
]


def get_gcp_credentials(acc: dict):
    """
    Returns GCP credentials.
    Supports: Service Account JSON key file path or JSON content string,
              or Application Default Credentials (ADC) when running on GCP.
    """
    try:
        import google.auth
        from google.oauth2 import service_account
        import json

        sa_key = acc.get("service_account_key")
        if sa_key:
            if sa_key.strip().startswith("{"):
                info = json.loads(sa_key)
            else:
                with open(sa_key) as f:
                    info = json.load(f)
            return service_account.Credentials.from_service_account_info(
                info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        # Fall back to ADC (works on GCE, GKE, Cloud Run, etc.)
        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        return creds
    except ImportError:
        raise RuntimeError(
            "GCP SDK not installed. Run: pip install google-cloud-monitoring "
            "google-cloud-compute google-cloud-storage google-cloud-billing google-auth"
        )


def fetch_gcp_resources(acc: dict) -> dict:
    """Fetch all resources for configured GCP services."""
    resources: dict = {}
    project_id = acc.get("project_id", "")
    if not project_id:
        log.warning("GCP account missing project_id")
        return resources

    try:
        credentials = get_gcp_credentials(acc)
    except Exception as e:
        log.warning(f"GCP credential error: {e}")
        return resources

    for svc in acc.get("services", []):
        try:
            rows = _fetch_gcp_svc(credentials, project_id, svc, acc.get("region", "us-central1"))
            resources[svc] = rows
        except Exception as e:
            log.warning(f"GCP fetch_resources [{svc}]: {e}")
            resources[svc] = []

    return resources


def _fetch_gcp_svc(credentials, project_id: str, svc: str, region: str) -> list:
    rows = []

    if svc == "ComputeEngine":
        try:
            from google.cloud import compute_v1
            client = compute_v1.InstancesClient(credentials=credentials)
            request = compute_v1.AggregatedListInstancesRequest(project=project_id)
            for zone, response in client.aggregated_list(request=request):
                for inst in response.instances or []:
                    rows.append({
                        "id": inst.name, "label": inst.name,
                        "type": inst.machine_type.split("/")[-1] if inst.machine_type else "—",
                        "az": zone.split("/")[-1],
                        "region": zone.split("/")[-1].rsplit("-", 1)[0],
                        "state": inst.status.lower() if inst.status else "unknown",
                        "cpu": "—", "mem": "—", "uptime": "—",
                        "provider": "gcp",
                        "consoleUrl": (
                            f"https://console.cloud.google.com/compute/instancesDetail"
                            f"/zones/{zone.split('/')[-1]}/instances/{inst.name}?project={project_id}"
                        ),
                    })
        except Exception as e:
            log.warning(f"GCP ComputeEngine fetch error: {e}")

    elif svc == "CloudStorage":
        try:
            from google.cloud import storage
            client = storage.Client(credentials=credentials, project=project_id)
            for bucket in client.list_buckets():
                rows.append({
                    "id": bucket.name, "label": bucket.name,
                    "type": bucket.storage_class or "STANDARD",
                    "az": bucket.location or "global",
                    "region": (bucket.location or "global").lower(),
                    "state": "active",
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "provider": "gcp",
                })
        except Exception as e:
            log.warning(f"GCP CloudStorage fetch error: {e}")

    elif svc == "CloudSQL":
        try:
            import googleapiclient.discovery
            service = googleapiclient.discovery.build(
                "sqladmin", "v1", credentials=credentials
            )
            result = service.instances().list(project=project_id).execute()
            for inst in result.get("items", []):
                rows.append({
                    "id": inst["name"], "label": inst["name"],
                    "type": inst.get("databaseVersion", "—"),
                    "az": inst.get("gceZone", region),
                    "region": inst.get("region", region),
                    "state": inst.get("state", "RUNNABLE").lower(),
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "provider": "gcp",
                })
        except Exception as e:
            log.warning(f"GCP CloudSQL fetch error: {e}")

    elif svc == "CloudFunctions":
        try:
            from google.cloud import functions_v1
            client = functions_v1.CloudFunctionsServiceClient(credentials=credentials)
            parent = f"projects/{project_id}/locations/-"
            for fn in client.list_functions(request={"parent": parent}):
                rows.append({
                    "id": fn.name.split("/")[-1],
                    "label": fn.name.split("/")[-1],
                    "type": fn.runtime or "—",
                    "az": fn.name.split("/")[3],
                    "region": fn.name.split("/")[3],
                    "state": fn.status.name.lower() if fn.status else "active",
                    "cpu": "—",
                    "mem": f"{fn.available_memory_mb} MB" if fn.available_memory_mb else "—",
                    "uptime": "—",
                    "provider": "gcp",
                })
        except Exception as e:
            log.warning(f"GCP CloudFunctions fetch error: {e}")

    elif svc == "GKE":
        try:
            from google.cloud import container_v1
            client = container_v1.ClusterManagerClient(credentials=credentials)
            response = client.list_clusters(parent=f"projects/{project_id}/locations/-")
            for cluster in response.clusters:
                rows.append({
                    "id": cluster.name, "label": cluster.name,
                    "type": f"GKE {cluster.current_master_version or ''}",
                    "az": cluster.location,
                    "region": cluster.location,
                    "state": cluster.status.name.lower() if cluster.status else "running",
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "provider": "gcp",
                })
        except Exception as e:
            log.warning(f"GCP GKE fetch error: {e}")

    return rows


def fetch_gcp_health(acc: dict) -> dict:
    """Fetch GCP Cloud Monitoring alert policies and aggregate health."""
    try:
        project_id = acc.get("project_id", "")
        credentials = get_gcp_credentials(acc)
        from google.cloud import monitoring_v3
        client = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        policies = list(client.list_alert_policies(name=f"projects/{project_id}"))
        firing = [p for p in policies if p.enabled and p.conditions]
        count = len(firing)
        return {
            "status": "healthy" if count == 0 else "warning",
            "alerts": count,
            "metrics": {"cpu": "—", "alerts": count},
        }
    except Exception as e:
        log.warning(f"GCP fetch_health error: {e}")
        return {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}


def fetch_gcp_active_alarms(acc: dict) -> list:
    """Fetch active GCP Cloud Monitoring incidents."""
    try:
        project_id = acc.get("project_id", "")
        credentials = get_gcp_credentials(acc)
        from google.cloud import monitoring_v3
        client = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        results = []
        now = datetime.now(timezone.utc)
        for policy in client.list_alert_policies(name=f"projects/{project_id}"):
            if not policy.enabled:
                continue
            results.append({
                "name": policy.display_name,
                "service": "GCP Monitoring",
                "region": acc.get("region", "—"),
                "sev": "warning",
                "metric": policy.display_name,
                "metricLabel": policy.display_name,
                "threshold": None,
                "currentValue": None,
                "unit": "",
                "stateReason": "",
                "time": now.strftime("%H:%M UTC"),
                "timeISO": now.isoformat(),
                "provider": "gcp",
            })
        return results
    except Exception as e:
        log.warning(f"GCP fetch_active_alarms error: {e}")
        return []


def fetch_gcp_costs(acc: dict) -> list:
    """Fetch GCP billing data via Cloud Billing API."""
    try:
        project_id = acc.get("project_id", "")
        credentials = get_gcp_credentials(acc)
        from google.cloud import bigquery
        client = bigquery.Client(credentials=credentials, project=project_id)
        billing_table = acc.get("billing_table", "")
        if not billing_table:
            return []
        query = f"""
            SELECT
                FORMAT_DATE('%Y-%m', usage_start_time) AS month,
                SUM(cost) AS cost,
                currency
            FROM `{billing_table}`
            WHERE usage_start_time >= DATE_SUB(CURRENT_DATE(), INTERVAL 6 MONTH)
            GROUP BY month, currency
            ORDER BY month
        """
        rows = []
        for row in client.query(query).result():
            rows.append({
                "month": row.month,
                "cost": float(row.cost),
                "unit": row.currency or "USD",
            })
        return rows
    except Exception as e:
        log.warning(f"GCP fetch_costs error: {e}")
        return []
