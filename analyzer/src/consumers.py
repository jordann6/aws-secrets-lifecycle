"""Build the consumer map for each secret from CloudTrail access rows
and resource policy principals."""

import json
from collections import defaultdict


def parse_policy_principals(resource_policy):
    """Extract principal ARNs a resource policy grants read access to."""
    if not resource_policy:
        return []
    try:
        policy = json.loads(resource_policy)
    except (ValueError, TypeError):
        return []
    principals = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        p = stmt.get("Principal", {})
        if p == "*":
            principals.append("*")
        elif isinstance(p, dict):
            aws = p.get("AWS", [])
            if isinstance(aws, str):
                aws = [aws]
            principals.extend(aws)
    return principals


def build_consumer_maps(access_rows):
    """Group CloudTrail access rows by target resource.

    access_rows: iterable of dicts with keys
      resource_id, principal_arn, event_name, access_count, last_accessed
    Returns {resource_id: consumer_map}."""
    by_resource = defaultdict(list)
    for row in access_rows:
        by_resource[row["resource_id"]].append(row)

    maps = {}
    for resource_id, rows in by_resource.items():
        by_principal = defaultdict(lambda: {"access_count": 0, "last_accessed": ""})
        for r in rows:
            entry = by_principal[r.get("principal_arn") or "unknown"]
            entry["access_count"] += int(r.get("access_count", 0))
            entry["last_accessed"] = max(entry["last_accessed"], r.get("last_accessed", ""))
        consumers = []
        for arn, agg in sorted(by_principal.items()):
            consumers.append({
                "principal_arn": arn if arn != "unknown" else None,
                "service": _service_of(arn),
                "access_count": agg["access_count"],
                "last_accessed": agg["last_accessed"],
            })
        maps[resource_id] = {
            "consumers": consumers,
            "total_reads": sum(c["access_count"] for c in consumers),
        }
    return maps


def _service_of(arn):
    if not arn or arn == "unknown":
        return "unknown"
    if ":assumed-role/" in arn:
        # Lambda execution roles show up as assumed-role sessions whose
        # session name is the function name.
        return "lambda" if "consumer" in arn or "lambda" in arn.lower() else "assumed-role"
    if ":user/" in arn:
        return "iam-user"
    if ":role/" in arn:
        return "iam-role"
    return "other"


def match_resource(secret_record, consumer_maps):
    """A secret matches a consumer map by name (Secrets Manager passes
    secretId as name or ARN; SSM passes the parameter name)."""
    name = secret_record.get("name", "")
    arn = secret_record.get("arn", "")
    for key, cmap in consumer_maps.items():
        if key and (key == arn or key == name or key in arn or name == key):
            return cmap
    return {"consumers": [], "total_reads": 0}
