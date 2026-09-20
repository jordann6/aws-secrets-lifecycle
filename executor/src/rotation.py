"""AWS Secrets Manager four-step rotation contract.

Secrets Manager drives rotation by invoking this Lambda four times per
rotation, once per Step, passing a ClientRequestToken that names the new
version:

  createSecret  stage a new AWSPENDING version with a fresh value
  setSecret     change the credential in the backing service
  testSecret    prove the new credential works
  finishSecret  promote AWSPENDING to AWSCURRENT, demote old to AWSPREVIOUS

The staging-label moves are identical for every secret; only setSecret
and testSecret know anything about the backing service. That
service-specific part is a Strategy, so rotating an RDS password later is
a new Strategy, not a rewrite of the contract. The shipped GenericStrategy
rotates a self-contained secret (an API token or key stored in Secrets
Manager with no external system to update): setSecret is a no-op and
testSecret confirms the pending value is retrievable and non-empty. This
runs end to end with no database in the loop.
"""

import logging

log = logging.getLogger()

PENDING = "AWSPENDING"
CURRENT = "AWSCURRENT"
PREVIOUS = "AWSPREVIOUS"


class GenericStrategy:
    """Rotate a standalone secret value with no external dependency."""

    password_length = 32

    def new_value(self, client, arn, current_value):
        resp = client.get_random_password(
            PasswordLength=self.password_length, ExcludePunctuation=True)
        return resp["RandomPassword"]

    def set_secret(self, client, arn, pending_value):
        # No backing service to update for a standalone secret. An RDS or
        # third-party-API strategy would push pending_value to the service
        # here before testSecret verifies it.
        log.info("set_secret: generic strategy, nothing external to update")

    def test_secret(self, client, arn, pending_value):
        if not pending_value:
            raise ValueError("pending value is empty; refusing to finish")
        log.info("test_secret: pending value present and non-empty")


def _stages(client, arn):
    meta = client.describe_secret(SecretId=arn)
    return meta, meta.get("VersionIdsToStages", {})


def create_secret(client, arn, token, strategy):
    meta, stages = _stages(client, arn)
    if token in stages and PENDING in stages[token]:
        log.info("create_secret: AWSPENDING already staged for %s", token)
        return
    current = client.get_secret_value(SecretId=arn, VersionStage=CURRENT)
    pending = strategy.new_value(client, arn, current.get("SecretString"))
    client.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=pending,
        VersionStages=[PENDING],
    )
    log.info("create_secret: staged AWSPENDING version %s", token)


def set_secret(client, arn, token, strategy):
    pending = client.get_secret_value(
        SecretId=arn, VersionId=token, VersionStage=PENDING)
    strategy.set_secret(client, arn, pending.get("SecretString"))


def test_secret(client, arn, token, strategy):
    pending = client.get_secret_value(
        SecretId=arn, VersionId=token, VersionStage=PENDING)
    strategy.test_secret(client, arn, pending.get("SecretString"))


def finish_secret(client, arn, token):
    meta, stages = _stages(client, arn)
    current_version = None
    for version, labels in stages.items():
        if CURRENT in labels:
            current_version = version
            break
    if current_version == token:
        log.info("finish_secret: %s already AWSCURRENT", token)
        return
    client.update_secret_version_stage(
        SecretId=arn,
        VersionStage=CURRENT,
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    log.info("finish_secret: promoted %s to AWSCURRENT (was %s)",
             token, current_version)


_STEPS = {
    "createSecret": create_secret,
    "setSecret": set_secret,
    "testSecret": test_secret,
}


def run_step(client, arn, token, step, strategy=None):
    """Dispatch one rotation step. Called by Secrets Manager per step."""
    strategy = strategy or GenericStrategy()
    meta = client.describe_secret(SecretId=arn)
    if not meta.get("RotationEnabled", False):
        # RotateSecret enables this before the first invoke; a bare invoke
        # against a secret with rotation off is a misfire, not a rotation.
        log.warning("run_step: rotation not enabled on %s", arn)
    if step == "finishSecret":
        return finish_secret(client, arn, token)
    handler = _STEPS.get(step)
    if not handler:
        raise ValueError(f"unknown rotation step {step!r}")
    return handler(client, arn, token, strategy)
