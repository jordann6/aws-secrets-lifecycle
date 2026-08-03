"""Rotation runbook synthesis via Claude Opus 5 on Amazon Bedrock.

Inputs are the consumer map, resource policy, and access pattern for a
single high-risk secret. Output is strict JSON enforced by a schema
through structured outputs, then validated again on parse."""

import json
import os

from redact import redact

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-opus-5")

RUNBOOK_SCHEMA = {
    "type": "object",
    "properties": {
        "secret_name": {"type": "string"},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "order": {"type": "integer"},
                    "action": {"type": "string"},
                    "verification": {"type": "string"},
                },
                "required": ["order", "action", "verification"],
                "additionalProperties": False,
            },
        },
        "rollback": {
            "type": "array",
            "items": {"type": "string"},
        },
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "confidence_rationale": {"type": "string"},
    },
    "required": ["secret_name", "steps", "rollback", "confidence",
                 "confidence_rationale"],
    "additionalProperties": False,
}

PROMPT = """You are a cloud security engineer producing a rotation runbook \
for one AWS secret. Base every step on the observed consumer map: name the \
actual consumers, order steps so consumers are updated before the old \
version is invalidated, and keep the rollback path concrete. Confidence \
reflects how completely the consumers are identified: unknown principals \
or zero observed consumers on a secret that policies say is readable \
lower confidence.

Return strict JSON only. No preamble and no markdown fences.

Secret metadata and consumer map:
{context}
"""


def _client():
    from anthropic import AnthropicBedrockMantle
    return AnthropicBedrockMantle(aws_region=os.environ.get("AWS_REGION", "us-east-1"))


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
    response = client.messages.create(
        model=MODEL_ID,
        max_tokens=2048,
        output_config={"format": {"type": "json_schema", "schema": RUNBOOK_SCHEMA}},
        messages=[{
            "role": "user",
            "content": PROMPT.format(context=json.dumps(context, default=str)),
        }],
    )
    if response.stop_reason == "refusal":
        return None
    text = next(b.text for b in response.content if b.type == "text")
    runbook = json.loads(text)
    for key in ("secret_name", "steps", "rollback", "confidence"):
        if key not in runbook:
            raise ValueError(f"runbook missing required key {key}")
    return runbook
