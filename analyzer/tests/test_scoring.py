import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from scoring import readiness_score, risk_tier


def test_orphaned_rotated_secret_scores_high():
    record = {"rotation_enabled": True, "age_days": 30}
    score = readiness_score(record, {"consumers": []})
    assert score == 90
    assert risk_tier(score) == "low"


def test_old_unrotated_secret_with_unknown_consumers_scores_low():
    record = {"rotation_enabled": False, "age_days": 700}
    cmap = {"consumers": [{"principal_arn": None, "access_count": 3}]}
    score = readiness_score(record, cmap)
    assert score == 30
    assert risk_tier(score) == "high"


def test_identified_consumers_beat_unknown():
    record = {"rotation_enabled": False, "age_days": 100}
    known = {"consumers": [{"principal_arn": "arn:aws:iam::1:role/app"}]}
    unknown = {"consumers": [{"principal_arn": None}]}
    assert readiness_score(record, known) > readiness_score(record, unknown)


def test_score_clamped_to_bounds():
    worst = readiness_score(
        {"rotation_enabled": False, "age_days": 9999},
        {"consumers": [{"principal_arn": None}] * 10},
    )
    assert 0 <= worst <= 100
