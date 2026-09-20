import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import approval


TAGS_OK = {approval.APPROVED_TAG_KEY: approval.APPROVED_TAG_VALUE}


def _analysis(confidence="high", generator="bedrock"):
    return {"runbook": {"confidence": confidence, "generator": generator,
                        "steps": [{"order": 1, "action": "x"}]}}


def test_all_controls_pass():
    ok, reasons = approval.evaluate(
        {"approve": True}, _analysis(), TAGS_OK)
    assert ok is True
    assert reasons == []


def test_missing_approve_flag_blocks():
    ok, reasons = approval.evaluate({}, _analysis(), TAGS_OK)
    assert ok is False
    assert any("approve" in r for r in reasons)


def test_approve_must_be_true_not_truthy():
    ok, reasons = approval.evaluate(
        {"approve": "yes"}, _analysis(), TAGS_OK)
    assert ok is False


def test_missing_opt_in_tag_blocks():
    ok, reasons = approval.evaluate({"approve": True}, _analysis(), {})
    assert ok is False
    assert any(approval.APPROVED_TAG_KEY in r for r in reasons)


def test_low_confidence_blocked_by_default():
    ok, reasons = approval.evaluate(
        {"approve": True}, _analysis(confidence="low"), TAGS_OK)
    assert ok is False
    assert any("confidence" in r for r in reasons)


def test_medium_needs_allow_medium():
    ok, _ = approval.evaluate(
        {"approve": True}, _analysis(confidence="medium"), TAGS_OK)
    assert ok is False
    ok, _ = approval.evaluate(
        {"approve": True}, _analysis(confidence="medium"), TAGS_OK,
        allow_medium=True)
    assert ok is True


def test_fallback_runbook_blocked_unless_forced():
    ok, reasons = approval.evaluate(
        {"approve": True}, _analysis(generator="fallback"), TAGS_OK)
    assert ok is False
    assert any("fallback" in r for r in reasons)
    ok, _ = approval.evaluate(
        {"approve": True}, _analysis(generator="fallback"), TAGS_OK,
        force=True)
    assert ok is True


def test_force_does_not_bypass_tag_or_approve():
    ok, reasons = approval.evaluate(
        {"approve": True}, _analysis(confidence="low"), {}, force=True)
    assert ok is False
    assert any(approval.APPROVED_TAG_KEY in r for r in reasons)


def test_missing_analysis_reports_reason():
    ok, reasons = approval.evaluate({"approve": True}, None, TAGS_OK)
    assert ok is False
    assert any("no analyzer record" in r for r in reasons)
