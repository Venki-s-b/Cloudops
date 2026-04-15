"""
AWS Cloud Provider Adapter
Handles EC2, RDS, Lambda, S3, ELB, ECS, CloudFront metrics via CloudWatch + boto3
"""
import boto3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

log = logging.getLogger("cloudops.aws")

AWS_REGIONS = [
    "us-east-1","us-east-2","us-west-1","us-west-2",
    "ap-south-1","ap-south-2","ap-southeast-1","ap-southeast-2",
    "ap-northeast-1","ap-northeast-2","ap-northeast-3","ap-east-1",
    "eu-west-1","eu-west-2","eu-west-3","eu-central-1","eu-central-2",
    "eu-north-1","eu-south-1","eu-south-2",
    "ca-central-1","ca-west-1","sa-east-1",
    "me-south-1","me-central-1","il-central-1","af-south-1",
]

SERVICE_CATALOG = {
    "EC2":        {"icon": "🖥️",  "color": "#38b6ff", "namespace": "AWS/EC2"},
    "RDS":        {"icon": "🗄️",  "color": "#a78bfa", "namespace": "AWS/RDS"},
    "Lambda":     {"icon": "λ",   "color": "#fb923c", "namespace": "AWS/Lambda"},
    "S3":         {"icon": "🪣",  "color": "#00e5a0", "namespace": "AWS/S3"},
    "ELB":        {"icon": "⚖️",  "color": "#f0c040", "namespace": "AWS/ApplicationELB"},
    "ECS":        {"icon": "📦",  "color": "#38b6ff", "namespace": "AWS/ECS"},
    "CloudFront": {"icon": "🌐",  "color": "#a78bfa", "namespace": "AWS/CloudFront"},
    "DynamoDB":   {"icon": "⚡",  "color": "#fb923c", "namespace": "AWS/DynamoDB"},
    "ElastiCache":{"icon": "🔄",  "color": "#00e5a0", "namespace": "AWS/ElastiCache"},
    "SNS":        {"icon": "📢",  "color": "#f0c040", "namespace": "AWS/SNS"},
    "SQS":        {"icon": "📬",  "color": "#38b6ff", "namespace": "AWS/SQS"},
    "API Gateway":{"icon": "🔌",  "color": "#a78bfa", "namespace": "AWS/ApiGateway"},
}


def get_session(role_arn: str, external_id: Optional[str], region: str) -> boto3.Session:
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


def fetch_resources(session: boto3.Session, acc: dict) -> dict:
    primary = acc["region"]
    regions = list(dict.fromkeys([primary] + acc.get("extra_regions", [])))
    resources: dict = {}

    for svc in acc.get("services", []):
        rows = []
        for region in regions:
            try:
                rows.extend(_fetch_svc_resources(session, svc, region, primary))
            except Exception as e:
                log.warning(f"AWS fetch_resources [{svc}][{region}]: {e}")
        resources[svc] = rows
    return resources


def _fetch_svc_resources(session, svc, region, primary_region):
    rows = []
    if svc == "EC2":
        ec2 = session.client("ec2", region_name=region)
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "pending"]}]
        )
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                rows.append({
                    "id": inst["InstanceId"], "label": name,
                    "type": inst.get("InstanceType", "—"),
                    "az": inst.get("Placement", {}).get("AvailabilityZone", region),
                    "region": region, "state": inst.get("State", {}).get("Name", "unknown"),
                    "cpu": "—", "mem": "—", "uptime": "—",
                    "consoleUrl": f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#Instances:instanceId={inst['InstanceId']}",
                })

    elif svc == "RDS":
        rds = session.client("rds", region_name=region)
        for db in rds.describe_db_instances().get("DBInstances", []):
            rows.append({
                "id": db["DBInstanceIdentifier"], "label": db["DBInstanceIdentifier"],
                "type": db.get("DBInstanceClass", "—"),
                "az": db.get("AvailabilityZone", region), "region": region,
                "state": db.get("DBInstanceStatus", "unknown"),
                "cpu": "—", "mem": "—", "uptime": "—",
            })

    elif svc == "Lambda":
        lm = session.client("lambda", region_name=region)
        for fn in lm.list_functions().get("Functions", []):
            rows.append({
                "id": fn["FunctionName"], "label": fn["FunctionName"],
                "type": fn.get("Runtime", "—"), "az": region, "region": region,
                "state": "active", "cpu": "—",
                "mem": str(fn.get("MemorySize", "—")) + " MB", "uptime": "—",
            })

    elif svc == "ELB":
        elbv2 = session.client("elbv2", region_name=region)
        for lb in elbv2.describe_load_balancers().get("LoadBalancers", []):
            azs = "/".join(a["ZoneName"] for a in lb.get("AvailabilityZones", []))
            rows.append({
                "id": lb["LoadBalancerName"], "label": lb["LoadBalancerName"],
                "type": lb.get("Type", "application").upper() + " LB",
                "az": azs or region, "region": region,
                "state": lb.get("State", {}).get("Code", "active"),
                "cpu": "—", "mem": "—", "uptime": "—",
            })

    elif svc == "S3" and region == primary_region:
        s3 = session.client("s3", region_name="us-east-1")
        for b in s3.list_buckets().get("Buckets", []):
            rows.append({
                "id": b["Name"], "label": b["Name"],
                "type": "Standard", "az": "global", "region": "global",
                "state": "active", "cpu": "—", "mem": "—", "uptime": "—",
            })

    elif svc == "ECS":
        ecs = session.client("ecs", region_name=region)
        clusters = ecs.list_clusters().get("clusterArns", [])
        for arn in clusters[:10]:
            name = arn.split("/")[-1]
            rows.append({
                "id": name, "label": name, "type": "ECS Cluster",
                "az": region, "region": region, "state": "active",
                "cpu": "—", "mem": "—", "uptime": "—",
            })

    elif svc == "DynamoDB":
        ddb = session.client("dynamodb", region_name=region)
        for tbl in ddb.list_tables().get("TableNames", [])[:20]:
            rows.append({
                "id": tbl, "label": tbl, "type": "DynamoDB Table",
                "az": region, "region": region, "state": "active",
                "cpu": "—", "mem": "—", "uptime": "—",
            })

    return rows


def fetch_health(cw_client, acc: dict) -> dict:
    try:
        alarms = cw_client.describe_alarms(StateValue="ALARM", MaxRecords=100).get("MetricAlarms", [])
        count = len(alarms)
        if count == 0:
            status = "healthy"
        elif any("critical" in a.get("AlarmName", "").lower() for a in alarms):
            status = "critical"
        else:
            status = "warning"
        cpu = _aggregate_ec2_cpu(cw_client)
        return {
            "status": status, "alerts": count,
            "metrics": {"cpu": f"{cpu:.1f}%" if cpu is not None else "—", "alerts": count},
        }
    except Exception as e:
        log.warning(f"fetch_health error: {e}")
        return {"status": "unknown", "alerts": 0, "metrics": {"cpu": "—", "alerts": 0}}


def _aggregate_ec2_cpu(cw_client) -> Optional[float]:
    try:
        now = datetime.now(timezone.utc)
        resp = cw_client.get_metric_data(
            MetricDataQueries=[{
                "Id": "cpu_avg",
                "Expression": 'AVG(SEARCH(\'{AWS/EC2,InstanceId} MetricName="CPUUtilization"\', \'Average\', 300))',
                "Label": "AverageCPU", "ReturnData": True,
            }],
            StartTime=now - timedelta(minutes=30), EndTime=now,
        )
        values = resp["MetricDataResults"][0].get("Values", [])
        return round(sum(values) / len(values), 1) if values else None
    except Exception:
        return None


def fetch_active_alarms(cw_client, region: str = "—") -> list:
    try:
        results = []
        now = datetime.now(timezone.utc)
        for a in cw_client.describe_alarms(StateValue="ALARM", MaxRecords=50).get("MetricAlarms", []):
            sev = "critical" if "critical" in a.get("AlarmName", "").lower() else "warning"
            ts = a.get("StateUpdatedTimestamp")
            results.append({
                "name": a["AlarmName"],
                "service": a.get("Namespace", "").split("/")[-1],
                "region": region, "sev": sev,
                "metric": a.get("MetricName", "?"),
                "metricLabel": f"{a.get('MetricName','?')} {a.get('ComparisonOperator','>')} {a.get('Threshold',0)}",
                "threshold": a.get("Threshold"),
                "currentValue": None,
                "unit": a.get("Unit", ""),
                "stateReason": a.get("StateReason", ""),
                "time": ts.strftime("%H:%M UTC") if ts else "—",
                "timeISO": ts.isoformat() if ts else None,
                "provider": "aws",
            })
        return results
    except Exception as e:
        log.warning(f"fetch_active_alarms error: {e}")
        return []


def fetch_cost(session: boto3.Session) -> list:
    try:
        ce = session.client("ce", region_name="us-east-1")
        end = datetime.now(timezone.utc).date()
        start = (end.replace(day=1) - timedelta(days=150)).replace(day=1)
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY", Metrics=["UnblendedCost"],
        )
        return [
            {
                "month": r["TimePeriod"]["Start"][:7],
                "cost": float(r["Total"]["UnblendedCost"]["Amount"]),
                "unit": r["Total"]["UnblendedCost"]["Unit"],
            }
            for r in resp["ResultsByTime"]
        ]
    except Exception as e:
        log.warning(f"fetch_cost error: {e}")
        return []


def fetch_service_metrics(cw_client, session: boto3.Session, service: str, region: str) -> dict:
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=30)
    period = 1800
    svc_meta = SERVICE_CATALOG.get(service, {"icon": "☁️", "color": "#6b8299"})

    def batch_avg(namespace, metric, dim_key, ids, stat="Average"):
        if not ids:
            return None
        queries = [
            {"Id": f"m{i}", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": metric,
             "Dimensions": [{"Name": dim_key, "Value": rid}]}, "Period": period, "Stat": stat}, "ReturnData": True}
            for i, rid in enumerate(ids[:10])
        ]
        try:
            resp = cw_client.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=now, ScanBy="TimestampDescending")
            vals = [r["Values"][0] for r in resp.get("MetricDataResults", []) if r.get("Values")]
            return round(sum(vals) / len(vals), 1) if vals else None
        except Exception:
            return None

    if service == "EC2":
        ids = _get_ec2_ids(session, region)
        cpu = batch_avg("AWS/EC2", "CPUUtilization", "InstanceId", ids)
        return {**svc_meta, "cpu": f"{cpu}%" if cpu else "—", "mem": "—", "alerts": 0, "status": "ok",
                "sub": f"{len(ids)} instance{'s' if len(ids)!=1 else ''}", "resources": ids}

    elif service == "RDS":
        ids = _get_rds_ids(session, region)
        cpu = batch_avg("AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", ids)
        mem = batch_avg("AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", ids)
        return {**svc_meta, "cpu": f"{cpu}%" if cpu else "—",
                "mem": f"{round(mem/1024**3,1)} GB free" if mem else "—",
                "alerts": 0, "status": "ok",
                "sub": f"{len(ids)} cluster{'s' if len(ids)!=1 else ''}", "resources": ids}

    elif service == "Lambda":
        names = _get_lambda_names(session, region)
        errors = batch_avg("AWS/Lambda", "Errors", "FunctionName", names, "Sum")
        invoc = batch_avg("AWS/Lambda", "Invocations", "FunctionName", names, "Sum")
        return {**svc_meta, "cpu": "—", "mem": "—",
                "alerts": 1 if errors and errors > 0 else 0,
                "status": "alert" if errors and errors > 0 else "ok",
                "sub": f"{len(names)} function{'s' if len(names)!=1 else ''} · {int(invoc or 0)} inv",
                "resources": names}

    elif service == "S3":
        try:
            s3 = session.client("s3")
            buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            return {**svc_meta, "cpu": "—", "mem": "—", "alerts": 0, "status": "ok",
                    "sub": f"{len(buckets)} bucket{'s' if len(buckets)!=1 else ''}", "resources": buckets}
        except Exception:
            return {**svc_meta, "cpu": "—", "mem": "—", "alerts": 0, "status": "ok", "sub": "S3", "resources": []}

    return {**svc_meta, "cpu": "—", "mem": "—", "alerts": 0, "status": "ok", "sub": service, "resources": []}


def _get_ec2_ids(session, region):
    try:
        ec2 = session.client("ec2", region_name=region)
        resp = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        return [i["InstanceId"] for r in resp["Reservations"] for i in r["Instances"]]
    except Exception:
        return []


def _get_rds_ids(session, region):
    try:
        return [db["DBInstanceIdentifier"] for db in
                session.client("rds", region_name=region).describe_db_instances().get("DBInstances", [])]
    except Exception:
        return []


def _get_lambda_names(session, region):
    try:
        return [f["FunctionName"] for f in
                session.client("lambda", region_name=region).list_functions().get("Functions", [])]
    except Exception:
        return []
