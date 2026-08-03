"""Reporter Lambda: reads a scan's analyses and metrics from DynamoDB,
renders the static dashboard, writes it to the dashboard bucket."""

import logging
import os
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

import render

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = os.environ["INVENTORY_TABLE"]
DASHBOARD_BUCKET = os.environ["DASHBOARD_BUCKET"]


def to_plain(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_plain(v) for v in obj]
    return obj


def handler(event, context):
    event = event or {}
    table = boto3.resource("dynamodb").Table(TABLE)
    s3 = boto3.client("s3")

    scan_id = (event.get("scan_id")
               or event.get("responsePayload", {}).get("scan_id"))
    if not scan_id:
        resp = table.scan(ProjectionExpression="scan_id")
        ids = {i["scan_id"] for i in resp.get("Items", [])}
        if not ids:
            return {"error": "no scans found"}
        scan_id = max(ids)

    items = table.query(
        IndexName="scan-index",
        KeyConditionExpression=Key("scan_id").eq(scan_id),
    )["Items"]
    analyses = [to_plain(i) for i in items if i["sk"].startswith("ANALYSIS#")]
    metrics_items = [to_plain(i) for i in items if i["sk"].startswith("METRICS#")]
    metrics = metrics_items[0].get("metrics", {}) if metrics_items else {}

    page = render.render(scan_id, metrics, analyses)
    for key in (f"scans/{scan_id}.html", "index.html"):
        s3.put_object(Bucket=DASHBOARD_BUCKET, Key=key, Body=page.encode(),
                      ContentType="text/html; charset=utf-8")

    url = f"http://{DASHBOARD_BUCKET}.s3-website-us-east-1.amazonaws.com/"
    log.info("dashboard written for %s: %s", scan_id, url)
    return {"scan_id": scan_id, "analyses": len(analyses), "url": url}
