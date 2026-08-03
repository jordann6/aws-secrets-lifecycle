import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from consumers import build_consumer_maps, match_resource, parse_policy_principals


def test_build_consumer_maps_aggregates_by_principal():
    rows = [
        {"resource_id": "secops-test/db-primary",
         "principal_arn": "arn:aws:sts::1:assumed-role/consumer-role/secops-test-consumer-app",
         "event_name": "GetSecretValue", "access_count": 3,
         "last_accessed": "2026-08-01T00:00:00Z"},
        {"resource_id": "secops-test/db-primary",
         "principal_arn": "arn:aws:sts::1:assumed-role/consumer-role/secops-test-consumer-app",
         "event_name": "GetSecretValue", "access_count": 2,
         "last_accessed": "2026-08-02T00:00:00Z"},
    ]
    maps = build_consumer_maps(rows)
    cmap = maps["secops-test/db-primary"]
    assert len(cmap["consumers"]) == 1
    assert cmap["total_reads"] == 5
    assert cmap["consumers"][0]["last_accessed"] == "2026-08-02T00:00:00Z"
    assert cmap["consumers"][0]["service"] == "lambda"


def test_match_resource_by_name_and_arn():
    maps = {"secops-test/db-primary": {"consumers": [{"x": 1}], "total_reads": 1}}
    record = {
        "name": "secops-test/db-primary",
        "arn": "arn:aws:secretsmanager:us-east-1:1:secret:secops-test/db-primary-AbC123",
    }
    assert match_resource(record, maps)["total_reads"] == 1
    orphan = {"name": "secops-test/legacy-ftp", "arn": "arn:...:legacy-ftp-Zz"}
    assert match_resource(orphan, maps)["consumers"] == []


def test_parse_policy_principals():
    policy = """{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:role/app"},
         "Action":"secretsmanager:GetSecretValue","Resource":"*"},
        {"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::1:role/bad"},
         "Action":"*","Resource":"*"}]}"""
    assert parse_policy_principals(policy) == ["arn:aws:iam::1:role/app"]
    assert parse_policy_principals(None) == []
    assert parse_policy_principals("not json") == []
