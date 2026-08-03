import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import runbook


class FakeClient:
    def __init__(self, text, stop_reason="end_turn"):
        self._text = text
        self._stop = stop_reason
        self.messages = self
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        block = SimpleNamespace(type="text", text=self._text)
        return SimpleNamespace(content=[block], stop_reason=self._stop)


GOOD = json.dumps({
    "secret_name": "secops-test/db-primary",
    "steps": [{"order": 1, "action": "create new version",
               "verification": "consumer reads succeed"}],
    "rollback": ["restore previous version stage"],
    "confidence": "medium",
    "confidence_rationale": "consumers identified via CloudTrail",
})

RECORD = {"name": "secops-test/db-primary", "kind": "secretsmanager",
          "age_days": 400, "rotation_enabled": False, "rotation_days": 0}
CMAP = {"consumers": [], "total_reads": 0}


def test_valid_runbook_parses():
    rb = runbook.generate_runbook(RECORD, CMAP, client=FakeClient(GOOD))
    assert rb["confidence"] == "medium"
    assert rb["steps"][0]["order"] == 1


def test_schema_is_sent_and_no_secret_material_in_prompt():
    client = FakeClient(GOOD)
    runbook.generate_runbook(
        {**RECORD, "resource_policy": "key AKIAIOSFODNN7EXAMPLE"},
        CMAP, client=client)
    fmt = client.last_kwargs["output_config"]["format"]
    assert fmt["type"] == "json_schema"
    prompt = client.last_kwargs["messages"][0]["content"]
    assert "AKIA" not in prompt


def test_missing_keys_raise():
    with pytest.raises(ValueError):
        runbook.generate_runbook(RECORD, CMAP,
                                 client=FakeClient('{"steps": []}'))


def test_refusal_returns_none():
    assert runbook.generate_runbook(
        RECORD, CMAP, client=FakeClient(GOOD, stop_reason="refusal")) is None
