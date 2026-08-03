"""Compliance evidence layer: control-mapped findings, evidence
artifacts to S3 (versioned + Object Lock), and ASFF export to
Security Hub."""

import hashlib
import json
import os
from datetime import datetime, timezone

import yaml


def load_mappings(path=None):
    path = path or os.path.join(os.path.dirname(__file__), "control-mappings.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def derive_findings(record, consumer_map, score, mappings):
    """Emit control-mapped finding dicts for one analyzed resource."""
    t = mappings["thresholds"]
    kinds = []
    age = int(record.get("age_days", 0))
    consumers = consumer_map.get("consumers", [])

    if record.get("kind") == "iam_access_key":
        if age > t["key_stale_age_days"]:
            kinds.append("ACCESS_KEY_STALE")
    else:
        if age > t["stale_age_days"] and not record.get("rotation_enabled"):
            kinds.append("SECRET_STALE")
        if not record.get("rotation_enabled"):
            kinds.append("SECRET_NO_ROTATION_CONFIG")
        if not consumers:
            kinds.append("SECRET_ORPHANED")
        elif any(not c.get("principal_arn") for c in consumers):
            kinds.append("SECRET_UNIDENTIFIED_CONSUMERS")

    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for kind in kinds:
        meta = mappings["findings"][kind]
        controls = [mappings["frameworks"][c] for c in meta["controls"]]
        fid = hashlib.sha256(
            f"{record['arn']}|{kind}|{record['scan_id']}".encode()).hexdigest()[:16]
        findings.append({
            "finding_id": f"secops-{fid}",
            "finding_type": kind,
            "title": meta["title"],
            "severity": meta["severity"],
            "control_ids": controls,
            "resource_arn": record["arn"],
            "evidence_timestamp": now,
            "remediation_status": "OPEN",
            "owner_tag": record.get("tags", {}).get("owner", "unassigned"),
            "readiness_score": score,
            "scan_id": record["scan_id"],
        })
    return findings


def write_evidence_artifact(s3, bucket, scan_id, findings, metrics):
    key = f"evidence/{scan_id}/evidence.json"
    body = json.dumps({
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "findings": findings,
    }, indent=2, default=str)
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
    return key


SEVERITY_MAP = {"LOW": 20, "MEDIUM": 50, "HIGH": 80}


def to_asff(finding, account_id, region):
    return {
        "SchemaVersion": "2018-10-08",
        "Id": finding["finding_id"],
        "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": "secops-secrets-lifecycle",
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
        "CreatedAt": finding["evidence_timestamp"],
        "UpdatedAt": finding["evidence_timestamp"],
        "Severity": {"Normalized": SEVERITY_MAP[finding["severity"]]},
        "Title": finding["title"],
        "Description": (
            f"{finding['finding_type']} on {finding['resource_arn']} "
            f"(readiness {finding['readiness_score']}/100)"
        ),
        "Resources": [{
            "Type": "Other",
            "Id": finding["resource_arn"],
        }],
        "Compliance": {
            "Status": "FAILED",
            "RelatedRequirements": finding["control_ids"],
        },
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }


def push_to_securityhub(securityhub, findings, account_id, region):
    imported = 0
    batch = [to_asff(f, account_id, region) for f in findings]
    for start in range(0, len(batch), 100):
        resp = securityhub.batch_import_findings(Findings=batch[start:start + 100])
        imported += resp.get("SuccessCount", 0)
    return imported
