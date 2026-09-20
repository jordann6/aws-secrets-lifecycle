"""Rotation executor Lambda.

Two entry paths, chosen by the event shape:

  Orchestration  an operator invokes with {secret_arn, scan_id, approve,
                 dry_run}. The executor loads the analyzer's stored runbook
                 for that secret, runs the approval guardrails, and either
                 returns the plan (dry_run, the default) or calls
                 RotateSecret to hand the secret to the four-step contract.

  Rotation step  Secrets Manager invokes with {SecretId, ClientRequestToken,
                 Step} once per step. The executor runs that one step.

Governance decides, a separately-permissioned executor acts. Nothing here
rotates a secret the analyzer never scored or an operator never tagged.
"""

import logging
import os

import boto3

import approval
import rotation

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = os.environ["INVENTORY_TABLE"]
EXECUTOR_ARN = os.environ.get("EXECUTOR_FUNCTION_ARN", "")
DEFAULT_ROTATION_DAYS = int(os.environ.get("ROTATION_DAYS", "30"))


def _analysis_item(table, secret_arn, scan_id):
    resp = table.get_item(Key={"pk": secret_arn, "sk": f"ANALYSIS#{scan_id}"})
    return resp.get("Item")


def _handle_rotation_step(event):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    log.info("rotation step %s for %s", step, arn)
    client = boto3.client("secretsmanager")
    rotation.run_step(client, arn, token, step)
    return {"status": "ok", "step": step, "secret_arn": arn}


def _handle_orchestration(event):
    secret_arn = event["secret_arn"]
    scan_id = event["scan_id"]
    dry_run = event.get("dry_run", True)
    allow_medium = bool(event.get("allow_medium", False))
    force = bool(event.get("force", False))

    session = boto3.Session()
    table = session.resource("dynamodb").Table(TABLE)
    sm = session.client("secretsmanager")

    analysis = _analysis_item(table, secret_arn, scan_id)
    meta = sm.describe_secret(SecretId=secret_arn)
    tags = approval.tags_to_dict(meta.get("Tags"))

    approved, reasons = approval.evaluate(
        event, analysis, tags, allow_medium=allow_medium, force=force)

    runbook = (analysis or {}).get("runbook") or {}
    plan = {
        "secret_arn": secret_arn,
        "scan_id": scan_id,
        "approved": approved,
        "reasons": reasons,
        "runbook_confidence": runbook.get("confidence"),
        "runbook_generator": runbook.get("generator"),
        "runbook_steps": runbook.get("steps"),
    }

    if not approved:
        log.info("rotation refused for %s: %s", secret_arn, reasons)
        return {"status": "refused", **plan}

    if dry_run:
        log.info("dry run for %s: approved, not rotating", secret_arn)
        return {"status": "dry_run", **plan}

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=EXECUTOR_ARN,
        RotationRules={"AutomaticallyAfterDays": DEFAULT_ROTATION_DAYS},
        RotateImmediately=True,
    )
    log.info("rotation started for %s", secret_arn)
    return {"status": "rotating", **plan}


def handler(event, context):
    event = event or {}
    if event.get("Step") and event.get("SecretId"):
        return _handle_rotation_step(event)
    return _handle_orchestration(event)
