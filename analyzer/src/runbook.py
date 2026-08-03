"""Rotation runbook synthesis via Claude on Amazon Bedrock.

Inputs are the consumer map, resource policy, and access pattern for a
single high-risk secret. The model is prompted to return strict JSON
only, no preamble and no markdown fences, and the parse is validated.
One retry on a parse failure."""

import json
import os

from redact import redact

MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

REQUIRED_KEYS = ("secret_name", "steps", "rollback", "confidence",
                 "confidence_rationale")

PROMPT = """You are a cloud security engineer producing a rotation runbook \
for one AWS secret. Base every step on the observed consumer map: name the \
actual consumers, order steps so consumers are updated before the old \
version is invalidated, and keep the rollback path concrete. Confidence \
reflects how completely the consumers are identified: unknown principals \
or zero observed consumers on a secret that policies say is readable \
lower confidence.

Return strict JSON only. No preamble, no markdown fences, no text outside \
the JSON object. Use exactly this shape:
{{"secret_name": str,
  "steps": [{{"order": int, "action": str, "verification": str}}],
  "rollback": [str],
  "confidence": "low" | "medium" | "high",
  "confidence_rationale": str}}

Secret metadata and consumer map:
{context}
"""


def _client():
    import boto3
    # Pinned independently of the Lambda's region: the Anthropic use case
    # gate on this account clears in us-east-2 but not us-east-1.
    return boto3.client(
        "bedrock-runtime",
        region_name=os.environ.get("BEDROCK_REGION", "us-east-2"))


def _parse(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.index("{"):text.rindex("}") + 1]
    runbook = json.loads(text)
    for key in REQUIRED_KEYS:
        if key not in runbook:
            raise ValueError(f"runbook missing required key {key}")
    if runbook["confidence"] not in ("low", "medium", "high"):
        raise ValueError("invalid confidence level")
    return runbook


def build_fallback_runbook(record, consumer_map):
    """Deterministic rule-based runbook used when Bedrock is unavailable.
    Marked generator=fallback so dashboards can distinguish it from
    model-synthesized runbooks."""
    name = record.get("name", "unknown")
    consumers = consumer_map.get("consumers", [])
    identified = [c for c in consumers if c.get("principal_arn")]
    steps = [{"order": 1,
              "action": f"Create a new version of {name} alongside the current one",
              "verification": "New version readable with AWSPENDING or staging label"}]
    n = 2
    for c in identified:
        steps.append({
            "order": n,
            "action": f"Update consumer {c['principal_arn']} to read the new version",
            "verification": "Consumer reads succeed against the new version"})
        n += 1
    if not consumers:
        steps.append({
            "order": n,
            "action": "No consumers observed in the lookback window; "
                      "confirm with the owner tag before invalidating",
            "verification": "Owner acknowledges the secret is unused"})
        n += 1
    steps.append({"order": n,
                  "action": "Promote the new version and deactivate the old one",
                  "verification": "No access errors for one full access cycle"})
    if consumers and not identified:
        confidence = "low"
        rationale = "Consumers observed but principals could not be identified"
    elif not consumers:
        confidence = "medium"
        rationale = "No observed consumers; rotation carries low outage risk"
    else:
        confidence = "medium"
        rationale = "All observed consumers identified; steps are rule-derived"
    return {
        "secret_name": name,
        "steps": steps,
        "rollback": ["Restore the previous version stage (AWSPREVIOUS)",
                     "Revert consumer configuration to the prior version",
                     "Verify consumer reads succeed against the restored version"],
        "confidence": confidence,
        "confidence_rationale": rationale,
        "generator": "fallback",
    }


def generate_runbook(record, consumer_map, client=None):
    context = redact({
        "secret_name": record.get("name"),
        "kind": record.get("kind"),
        "age_days": record.get("age_days"),
        "rotation_enabled": record.get("rotation_enabled"),
        "rotation_days": record.get("rotation_days"),
        "resource_policy": record.get("resource_policy") or None,
        "consumer_map": consumer_map,
    })
    client = client or _client()
    prompt = PROMPT.format(context=json.dumps(context, default=str))

    last_error = None
    for _ in range(2):
        resp = client.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 1500},
        )
        text = resp["output"]["message"]["content"][0]["text"]
        try:
            parsed = _parse(text)
            parsed["generator"] = "bedrock"
            return parsed
        except (ValueError, json.JSONDecodeError, IndexError) as exc:
            last_error = exc
    raise ValueError(f"runbook parse failed after retry: {last_error}")
