import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import render

ANALYSES = [
    {"name": "secops-test/legacy-ftp", "kind": "secretsmanager", "age_days": 700,
     "readiness_score": 30, "risk_tier": "high",
     "consumer_map": {"consumers": []},
     "runbook": {"confidence": "low", "confidence_rationale": "no consumers observed",
                 "steps": [{"order": 1, "action": "notify owner",
                            "verification": "ticket acknowledged"}],
                 "rollback": ["restore AWSPREVIOUS stage"]}},
    {"name": "secops-test/webhook-hmac", "kind": "secretsmanager", "age_days": 45,
     "readiness_score": 75, "risk_tier": "low",
     "consumer_map": {"consumers": [
         {"principal_arn": "arn:aws:sts::1:assumed-role/x/consumer-app",
          "access_count": 5, "last_accessed": "2026-08-03"}]},
     "runbook": None},
    {"name": "user/AKIA_KEY", "kind": "iam_access_key", "age_days": 10,
     "readiness_score": 60, "risk_tier": "medium",
     "consumer_map": {"consumers": []}, "runbook": None},
]

METRICS = {
    "total_secrets": 3, "mean_age_days": 251.7, "median_age_days": 45,
    "pct_with_identified_consumers": 50.0,
    "pct_with_verified_rotation_path": 50.0,
    "findings_by_control": {"SOC 2 CC6.1": 2, "NIST 800-53 IA-5": 3},
}


def test_render_contains_metrics_and_buckets():
    page = render.render("scan1", METRICS, ANALYSES)
    assert "3" in page and "251.7d" in page
    assert "0-90d" in page and "&gt;365d" in page
    assert "SOC 2 CC6.1" in page


def test_top_risk_excludes_access_keys_and_sorts_worst_first():
    page = render.render("scan1", METRICS, ANALYSES)
    assert "AKIA_KEY" not in page.split("Top risk secrets")[1]
    risk_section = page.split("Top risk secrets")[1]
    assert risk_section.index("legacy-ftp") < risk_section.index("webhook-hmac")


def test_runbook_rendered_with_rollback():
    page = render.render("scan1", METRICS, ANALYSES)
    assert "notify owner" in page
    assert "restore AWSPREVIOUS stage" in page


def test_html_escaping():
    bad = [{"name": "<script>alert(1)</script>", "kind": "secretsmanager",
            "age_days": 1, "readiness_score": 1, "risk_tier": "high",
            "consumer_map": {"consumers": []}, "runbook": None}]
    page = render.render("s", {}, bad)
    assert "<script>alert(1)</script>" not in page
