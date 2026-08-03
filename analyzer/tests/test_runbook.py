import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import runbook


class FakeBedrock:
    def __init__(self, texts):
        self.texts = list(texts)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        text = self.texts.pop(0)
        return {"output": {"message": {"content": [{"text": text}]}}}


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
    rb = runbook.generate_runbook(RECORD, CMAP, client=FakeBedrock([GOOD]))
    assert rb["confidence"] == "medium"
    assert rb["steps"][0]["order"] == 1


def test_markdown_fences_stripped():
    fenced = f"```json\n{GOOD}\n```"
    rb = runbook.generate_runbook(RECORD, CMAP, client=FakeBedrock([fenced]))
    assert rb["secret_name"] == "secops-test/db-primary"


def test_no_secret_material_in_prompt():
    client = FakeBedrock([GOOD])
    runbook.generate_runbook(
        {**RECORD, "resource_policy": "key AKIAIOSFODNN7EXAMPLE"},
        CMAP, client=client)
    prompt = client.calls[0]["messages"][0]["content"][0]["text"]
    assert "AKIA" not in prompt
    assert "strict JSON only" in prompt


def test_retry_once_then_succeed():
    client = FakeBedrock(["not json at all", GOOD])
    rb = runbook.generate_runbook(RECORD, CMAP, client=client)
    assert rb["confidence"] == "medium"
    assert len(client.calls) == 2


def test_persistent_garbage_raises():
    client = FakeBedrock(["nope", "still nope"])
    with pytest.raises(ValueError):
        runbook.generate_runbook(RECORD, CMAP, client=client)


def test_missing_keys_raise():
    with pytest.raises(ValueError):
        runbook.generate_runbook(RECORD, CMAP,
                                 client=FakeBedrock(['{"steps": []}', '{"steps": []}']))


def test_fallback_runbook_orders_consumers_before_promotion():
    cmap = {"consumers": [
        {"principal_arn": "arn:aws:sts::1:assumed-role/x/consumer-app",
         "access_count": 5, "last_accessed": "2026-08-03"}]}
    rb = runbook.build_fallback_runbook(RECORD, cmap)
    assert rb["generator"] == "fallback"
    actions = [s["action"] for s in rb["steps"]]
    assert "consumer-app" in actions[1]
    assert "Promote" in actions[-1]
    assert rb["confidence"] == "medium"


def test_fallback_runbook_orphan_requires_owner_ack():
    rb = runbook.build_fallback_runbook(RECORD, {"consumers": []})
    assert any("owner" in s["action"].lower() for s in rb["steps"])
    assert rb["confidence"] == "medium"


def test_fallback_runbook_unidentified_consumers_low_confidence():
    rb = runbook.build_fallback_runbook(
        RECORD, {"consumers": [{"principal_arn": None, "access_count": 2}]})
    assert rb["confidence"] == "low"
