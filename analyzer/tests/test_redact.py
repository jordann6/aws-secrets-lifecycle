import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from redact import redact, REDACTED


def test_sensitive_keys_redacted():
    obj = {"SecretString": "hunter2", "password": "x", "name": "db-primary"}
    out = redact(obj)
    assert out["SecretString"] == REDACTED
    assert out["password"] == REDACTED
    assert out["name"] == "db-primary"


def test_access_key_ids_scrubbed_from_strings():
    s = "used key AKIAIOSFODNN7EXAMPLE yesterday"
    assert "AKIA" not in redact(s)


def test_jwt_like_values_scrubbed():
    s = "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"
    assert "eyJ" not in redact(s)


def test_nested_structures():
    obj = {"a": [{"SecretBinary": b"x", "ok": "fine"}]}
    out = redact(obj)
    assert out["a"][0]["SecretBinary"] == REDACTED
    assert out["a"][0]["ok"] == "fine"
