import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import rotation


class FakeSecretsManager:
    """In-memory Secrets Manager double: versions, stages, values."""

    def __init__(self, current_value="old-value", rotation_enabled=True):
        self.versions = {"v-current": current_value}
        self.stages = {"v-current": ["AWSCURRENT"]}
        self.rotation_enabled = rotation_enabled
        self.random_calls = 0

    def describe_secret(self, SecretId):
        return {"RotationEnabled": self.rotation_enabled,
                "VersionIdsToStages": {v: list(s)
                                       for v, s in self.stages.items()}}

    def get_random_password(self, **kwargs):
        self.random_calls += 1
        return {"RandomPassword": f"new-value-{self.random_calls}"}

    def get_secret_value(self, SecretId, VersionId=None, VersionStage=None):
        if VersionId:
            return {"SecretString": self.versions[VersionId]}
        for version, labels in self.stages.items():
            if VersionStage in labels:
                return {"SecretString": self.versions[version]}
        raise KeyError(VersionStage)

    def put_secret_value(self, SecretId, ClientRequestToken, SecretString,
                         VersionStages):
        self.versions[ClientRequestToken] = SecretString
        self.stages[ClientRequestToken] = list(VersionStages)

    def update_secret_version_stage(self, SecretId, VersionStage,
                                    MoveToVersionId, RemoveFromVersionId=None):
        for v in self.stages.values():
            if VersionStage in v:
                v.remove(VersionStage)
        self.stages.setdefault(MoveToVersionId, []).append(VersionStage)
        if RemoveFromVersionId:
            self.stages.setdefault(RemoveFromVersionId, []).append("AWSPREVIOUS")

    def _stage_of(self, label):
        for v, labels in self.stages.items():
            if label in labels:
                return v
        return None


def _rotate(client, arn="arn:aws:secretsmanager:us-east-1:1:secret:x",
            token="v-pending"):
    for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
        rotation.run_step(client, arn, token, step)


def test_full_rotation_promotes_new_version():
    c = FakeSecretsManager(current_value="old-value")
    _rotate(c)
    assert c._stage_of("AWSCURRENT") == "v-pending"
    assert c.versions["v-pending"] == "new-value-1"
    assert "AWSPREVIOUS" in c.stages["v-current"]


def test_create_secret_is_idempotent():
    c = FakeSecretsManager()
    rotation.run_step(c, "arn", "v-pending", "createSecret")
    rotation.run_step(c, "arn", "v-pending", "createSecret")
    assert c.random_calls == 1  # second call short-circuits


def test_finish_secret_idempotent_when_already_current():
    c = FakeSecretsManager()
    _rotate(c)
    before = {v: list(s) for v, s in c.stages.items()}
    rotation.run_step(c, "arn", "v-pending", "finishSecret")
    assert {v: list(s) for v, s in c.stages.items()} == before


def test_test_secret_rejects_empty_pending():
    c = FakeSecretsManager()
    rotation.run_step(c, "arn", "v-pending", "createSecret")
    c.versions["v-pending"] = ""
    with pytest.raises(ValueError):
        rotation.run_step(c, "arn", "v-pending", "testSecret")


def test_unknown_step_raises():
    c = FakeSecretsManager()
    with pytest.raises(ValueError):
        rotation.run_step(c, "arn", "v-pending", "bogusStep")
