import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import evidence

MAPPINGS_PATH = Path(__file__).parents[2] / "config" / "control-mappings.yaml"


def mappings():
    return evidence.load_mappings(str(MAPPINGS_PATH))


BASE = {
    "arn": "arn:aws:secretsmanager:us-east-1:1:secret:x",
    "scan_id": "s1",
    "kind": "secretsmanager",
    "tags": {"owner": "platform-team"},
}


def test_stale_unrotated_orphan_gets_three_findings():
    record = {**BASE, "age_days": 500, "rotation_enabled": False}
    found = evidence.derive_findings(record, {"consumers": []}, 30, mappings())
    kinds = {f["finding_type"] for f in found}
    assert kinds == {"SECRET_STALE", "SECRET_NO_ROTATION_CONFIG", "SECRET_ORPHANED"}
    stale = next(f for f in found if f["finding_type"] == "SECRET_STALE")
    assert "HIPAA 164.308(a)(5)(ii)(D)" in stale["control_ids"]
    assert "CIS AWS Foundations 1.14" in stale["control_ids"]
    assert stale["owner_tag"] == "platform-team"


def test_rotated_consumed_secret_is_clean():
    record = {**BASE, "age_days": 30, "rotation_enabled": True}
    cmap = {"consumers": [{"principal_arn": "arn:aws:iam::1:role/app"}]}
    assert evidence.derive_findings(record, cmap, 90, mappings()) == []


def test_access_key_only_gets_key_finding():
    record = {**BASE, "kind": "iam_access_key", "age_days": 200}
    found = evidence.derive_findings(record, {"consumers": []}, 50, mappings())
    assert [f["finding_type"] for f in found] == ["ACCESS_KEY_STALE"]


def test_asff_shape():
    record = {**BASE, "age_days": 500, "rotation_enabled": False}
    f = evidence.derive_findings(record, {"consumers": []}, 30, mappings())[0]
    asff = evidence.to_asff(f, "692859913278", "us-east-1")
    assert asff["SchemaVersion"] == "2018-10-08"
    assert asff["ProductArn"].endswith("product/692859913278/default")
    assert asff["Compliance"]["Status"] == "FAILED"
    assert asff["Severity"]["Normalized"] == 80
