"""Redaction guard. Nothing in this pipeline ever reads secret values,
but every payload headed to logs, DynamoDB, or Bedrock passes through
here as defense in depth."""

import re

SENSITIVE_KEYS = re.compile(
    r"(secretstring|secretbinary|password|private_key|clientsecret|token_value)",
    re.IGNORECASE,
)

# High-entropy literals that look like key material.
SUSPICIOUS_VALUE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,})"
)

REDACTED = "[REDACTED]"


def redact(obj):
    """Recursively redact suspicious keys and values in dicts, lists,
    and strings. Returns a new structure."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if SENSITIVE_KEYS.search(str(k)) else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return SUSPICIOUS_VALUE.sub(REDACTED, obj)
    return obj
