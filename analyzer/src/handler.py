"""Analyzer Lambda: consumer maps from CloudTrail, readiness scores,
Bedrock runbooks for high-risk secrets, evidence artifacts, and
Security Hub export."""

import json
import logging
import os
import statistics
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

import athena_client
import consumers as consumers_mod
import evidence as evidence_mod
import runbook as runbook_mod
import scoring
from redact import redact

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = os.environ["INVENTORY_TABLE"]
DATABASE = os.environ["ATHENA_DATABASE"]
WORKGROUP = os.environ["ATHENA_WORKGROUP"]
TRAIL_BUCKET = os.environ["TRAIL_BUCKET"]
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "90"))
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
SECURITYHUB_ENABLED = os.environ.get("SECURITYHUB_ENABLED", "false") == "true"
MAX_RUNBOOKS = int(os.environ.get("MAX_RUNBOOKS", "5"))


def latest_scan_id(table):
    resp = table.scan(ProjectionExpression="scan_id")
    ids = {item["scan_id"] for item in resp.get("Items", [])}
    return max(ids) if ids else None


def to_plain(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_plain(v) for v in obj]
    return obj


def compute_metrics(records, analyses):
    ages = [r["age_days"] for r in records]
    secrets = [r for r in records if r["kind"] != "iam_access_key"]
    with_consumers = [a for a in analyses if a["consumer_map"]["consumers"]]
    verified_path = [
        a for a in analyses
        if a["record"].get("rotation_enabled")
        or (a.get("runbook") or {}).get("confidence") in ("medium", "high")
    ]
    return {
        "total_secrets": len(records),
        "mean_age_days": round(statistics.mean(ages), 1) if ages else 0,
        "median_age_days": statistics.median(ages) if ages else 0,
        "pct_with_identified_consumers":
            round(100 * len(with_consumers) / len(secrets), 1) if secrets else 0,
        "pct_with_verified_rotation_path":
            round(100 * len(verified_path) / len(secrets), 1) if secrets else 0,
    }


def handler(event, context):
    event = event or {}
    session = boto3.Session()
    account_id = session.client("sts").get_caller_identity()["Account"]
    region = session.region_name or "us-east-1"
    table = session.resource("dynamodb").Table(TABLE)
    athena = session.client("athena")

    # Direct invoke passes scan_id; a Lambda on-success destination wraps
    # the upstream result in responsePayload.
    scan_id = (event.get("scan_id")
               or event.get("responsePayload", {}).get("scan_id")
               or latest_scan_id(table))
    if not scan_id:
        return {"error": "no scans found"}
    log.info("analyzing scan %s", scan_id)

    resp = table.query(
        IndexName="scan-index",
        KeyConditionExpression=Key("scan_id").eq(scan_id),
    )
    records = [to_plain(i) for i in resp["Items"]
               if i["sk"].startswith("INVENTORY#")]

    access_rows = athena_client.query_access_events(
        athena, DATABASE, WORKGROUP, TRAIL_BUCKET, account_id, region,
        LOOKBACK_DAYS)
    consumer_maps = consumers_mod.build_consumer_maps(
        [r for r in access_rows if r.get("resource_id")])
    log.info("consumer maps for %d resources from %d access rows",
             len(consumer_maps), len(access_rows))

    mappings = evidence_mod.load_mappings()
    analyses = []
    findings = []
    for record in records:
        cmap = consumers_mod.match_resource(record, consumer_maps)
        score = scoring.readiness_score(record, cmap)
        analyses.append({
            "record": record,
            "consumer_map": cmap,
            "score": score,
            "tier": scoring.risk_tier(score),
            "runbook": None,
        })

    # Runbooks only for the highest-risk secrets, bounded for cost.
    high_risk = sorted(
        [a for a in analyses
         if a["tier"] == "high" and a["record"]["kind"] != "iam_access_key"],
        key=lambda a: a["score"])[:MAX_RUNBOOKS]
    for a in high_risk:
        try:
            a["runbook"] = runbook_mod.generate_runbook(a["record"], a["consumer_map"])
        except Exception as exc:
            log.warning("bedrock runbook failed for %s, using rule-based "
                        "fallback: %s", a["record"]["name"], exc)
            a["runbook"] = runbook_mod.build_fallback_runbook(
                a["record"], a["consumer_map"])

    for a in analyses:
        findings.extend(evidence_mod.derive_findings(
            a["record"], a["consumer_map"], a["score"], mappings))

    metrics = compute_metrics(records, analyses)
    by_control = {}
    for f in findings:
        for c in f["control_ids"]:
            by_control[c] = by_control.get(c, 0) + 1
    metrics["findings_by_control"] = by_control
    metrics["resources_with_findings"] = len({f["resource_arn"] for f in findings})

    with table.batch_writer() as batch:
        for a in analyses:
            item = redact({
                "pk": a["record"]["arn"],
                "sk": f"ANALYSIS#{scan_id}",
                "scan_id": scan_id,
                "name": a["record"]["name"],
                "kind": a["record"]["kind"],
                "readiness_score": a["score"],
                "risk_tier": a["tier"],
                "consumer_map": a["consumer_map"],
                "runbook": a["runbook"],
                "age_days": a["record"]["age_days"],
                "rotation_enabled": a["record"].get("rotation_enabled", False),
            })
            batch.put_item(Item=json.loads(json.dumps(item), parse_float=Decimal))
        batch.put_item(Item=json.loads(
            json.dumps({
                "pk": f"SCAN#{scan_id}",
                "sk": f"METRICS#{scan_id}",
                "scan_id": scan_id,
                "metrics": metrics,
                "finding_count": len(findings),
            }), parse_float=Decimal))

    result = {
        "scan_id": scan_id,
        "analyzed": len(analyses),
        "findings": len(findings),
        "runbooks_generated": sum(1 for a in analyses if a["runbook"]),
        "metrics": metrics,
    }

    if EVIDENCE_BUCKET:
        s3 = session.client("s3")
        key = evidence_mod.write_evidence_artifact(
            s3, EVIDENCE_BUCKET, scan_id, findings, metrics)
        result["evidence_key"] = key

    if SECURITYHUB_ENABLED and findings:
        hub = session.client("securityhub")
        result["securityhub_imported"] = evidence_mod.push_to_securityhub(
            hub, findings, account_id, region)

    log.info("analysis complete %s", json.dumps(result, default=str))
    return result
