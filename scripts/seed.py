"""Seed a realistic secrets test environment for the secops platform.

Creates:
  - 10 Secrets Manager secrets with varying simulated ages
  - 5 SSM SecureString parameters
  - 1 IAM test user with an access key
  - A working no-op rotation Lambda, wired to 2 secrets
  - 2 consumer Lambdas that read specific secrets and parameters,
    invoked repeatedly so CloudTrail records real access patterns

Real creation dates cannot be backdated, so age is simulated with the
tag secops:simulated-age-days. The scanner honors that tag and marks
the record as simulated. Documented in the README.

Usage:
  python3 seed.py            create everything and generate traffic
  python3 seed.py --traffic  only re-invoke consumers to add CloudTrail events
  python3 seed.py --destroy  remove everything this script created
"""

import argparse
import io
import json
import sys
import time
import zipfile

import boto3

REGION = "us-east-1"
PREFIX = "secops-test"

session = boto3.Session(region_name=REGION)
sm = session.client("secretsmanager")
ssm = session.client("ssm")
iam = session.client("iam")
lam = session.client("lambda")
sts = session.client("sts")

ACCOUNT = sts.get_caller_identity()["Account"]

SECRETS = [
    # (name, simulated_age_days, rotation, consumers)
    ("secops-test/db-primary", 400, False, "app"),
    ("secops-test/db-replica", 200, False, "batch"),
    ("secops-test/api-key-stripe", 500, False, None),
    ("secops-test/api-key-datadog", 90, False, None),
    ("secops-test/app-jwt-signing", 120, True, "app"),
    ("secops-test/svc-queue-token", 60, True, None),
    ("secops-test/legacy-ftp", 700, False, None),
    ("secops-test/redis-auth", 150, False, "app"),
    ("secops-test/smtp-creds", 365, False, None),
    ("secops-test/webhook-hmac", 45, False, "app"),
]

PARAMS = [
    ("/secops-test/app/db-conn", 300, "app"),
    ("/secops-test/app/feature-key", 30, "app"),
    ("/secops-test/batch/export-token", 250, "batch"),
    ("/secops-test/orphan/old-license", 600, None),
    ("/secops-test/orphan/deprecated-key", 420, None),
]

ROTATION_FN = "secops-test-rotation-noop"
CONSUMERS = {"app": "secops-test-consumer-app", "batch": "secops-test-consumer-batch"}
TEST_USER = "secops-test-user"

ROTATION_CODE = '''
import boto3

def handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    sm = boto3.client("secretsmanager")
    meta = sm.describe_secret(SecretId=arn)
    versions = meta["VersionIdsToStages"]
    if step == "createSecret":
        try:
            sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except sm.exceptions.ResourceNotFoundException:
            current = sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            sm.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=current["SecretString"] + ".r",
                VersionStages=["AWSPENDING"],
            )
    elif step == "finishSecret":
        current_version = [v for v, s in versions.items() if "AWSCURRENT" in s][0]
        if current_version != token:
            sm.update_secret_version_stage(
                SecretId=arn,
                VersionStage="AWSCURRENT",
                MoveToVersionId=token,
                RemoveFromVersionId=current_version,
            )
'''

CONSUMER_CODE = '''
import boto3
import json
import os

def handler(event, context):
    sm = boto3.client("secretsmanager")
    ssm = boto3.client("ssm")
    read = []
    for s in json.loads(os.environ.get("SECRET_IDS", "[]")):
        sm.get_secret_value(SecretId=s)
        read.append(s)
    for p in json.loads(os.environ.get("PARAM_NAMES", "[]")):
        ssm.get_parameter(Name=p, WithDecryption=True)
        read.append(p)
    return {"read": read}
'''


def zip_source(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", code)
    return buf.getvalue()


def ensure_role(name, policy_doc):
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    try:
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]
        created = True
    except iam.exceptions.EntityAlreadyExistsException:
        role = iam.get_role(RoleName=name)["Role"]
        created = False
    iam.put_role_policy(RoleName=name, PolicyName=f"{name}-policy",
                        PolicyDocument=json.dumps(policy_doc))
    if created:
        time.sleep(12)
    return role["Arn"]


def ensure_lambda(name, role_arn, code, env=None):
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Handler": "index.handler",
        "Role": role_arn,
        "Code": {"ZipFile": zip_source(code)},
        "Timeout": 30,
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    for attempt in range(6):
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.ResourceConflictException:
            lam.update_function_code(FunctionName=name, ZipFile=zip_source(code))
            waiter = lam.get_waiter("function_updated_v2")
            waiter.wait(FunctionName=name)
            if env:
                lam.update_function_configuration(
                    FunctionName=name, Environment={"Variables": env})
            break
        except lam.exceptions.InvalidParameterValueException:
            time.sleep(8)
    lam.get_waiter("function_active_v2").wait(FunctionName=name)


def create():
    logs_stmt = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }

    rotation_role = ensure_role(f"{ROTATION_FN}-role", {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                ],
                "Resource": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:secops-test/*",
            },
            logs_stmt,
        ],
    })

    consumer_role = ensure_role("secops-test-consumer-role", {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:secops-test/*",
            },
            {
                "Effect": "Allow",
                "Action": "ssm:GetParameter",
                "Resource": f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/secops-test/*",
            },
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"},
            logs_stmt,
        ],
    })

    print("creating rotation lambda")
    ensure_lambda(ROTATION_FN, rotation_role, ROTATION_CODE)
    try:
        lam.add_permission(
            FunctionName=ROTATION_FN,
            StatementId="SecretsManagerInvoke",
            Action="lambda:InvokeFunction",
            Principal="secretsmanager.amazonaws.com",
        )
    except lam.exceptions.ResourceConflictException:
        pass

    print("creating secrets")
    secret_arns = {}
    for name, age, rotate, _ in SECRETS:
        tags = [
            {"Key": "secops:simulated-age-days", "Value": str(age)},
            {"Key": "owner", "Value": "platform-team"},
            {"Key": "seeded-by", "Value": "secops"},
        ]
        try:
            resp = sm.create_secret(Name=name, SecretString=f"demo-{name}-v1", Tags=tags)
            secret_arns[name] = resp["ARN"]
        except sm.exceptions.ResourceExistsException:
            secret_arns[name] = sm.describe_secret(SecretId=name)["ARN"]
            sm.tag_resource(SecretId=name, Tags=tags)

    rotation_arn = lam.get_function(FunctionName=ROTATION_FN)["Configuration"]["FunctionArn"]
    for name, _, rotate, _ in SECRETS:
        if rotate:
            print(f"enabling rotation on {name}")
            sm.rotate_secret(
                SecretId=name,
                RotationLambdaARN=rotation_arn,
                RotationRules={"AutomaticallyAfterDays": 30},
            )

    print("creating ssm parameters")
    for name, age, _ in PARAMS:
        ssm.put_parameter(Name=name, Value=f"demo-{name}", Type="SecureString",
                          Overwrite=True)
        ssm.add_tags_to_resource(
            ResourceType="Parameter", ResourceId=name,
            Tags=[{"Key": "secops:simulated-age-days", "Value": str(age)},
                  {"Key": "seeded-by", "Value": "secops"}])

    print("creating test IAM user + access key")
    try:
        iam.create_user(UserName=TEST_USER,
                        Tags=[{"Key": "seeded-by", "Value": "secops"}])
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    keys = iam.list_access_keys(UserName=TEST_USER)["AccessKeyMetadata"]
    if not keys:
        iam.create_access_key(UserName=TEST_USER)

    print("creating consumer lambdas")
    app_secrets = [n for n, _, _, c in SECRETS if c == "app"]
    app_params = [n for n, _, c in PARAMS if c == "app"]
    batch_secrets = [n for n, _, _, c in SECRETS if c == "batch"]
    batch_params = [n for n, _, c in PARAMS if c == "batch"]
    ensure_lambda(CONSUMERS["app"], consumer_role, CONSUMER_CODE, {
        "SECRET_IDS": json.dumps(app_secrets),
        "PARAM_NAMES": json.dumps(app_params),
    })
    ensure_lambda(CONSUMERS["batch"], consumer_role, CONSUMER_CODE, {
        "SECRET_IDS": json.dumps(batch_secrets),
        "PARAM_NAMES": json.dumps(batch_params),
    })

    traffic()
    print("seed complete")


def traffic():
    print("generating consumer traffic for CloudTrail")
    for fn, count in ((CONSUMERS["app"], 5), (CONSUMERS["batch"], 2)):
        for i in range(count):
            resp = lam.invoke(FunctionName=fn, Payload=b"{}")
            body = json.loads(resp["Payload"].read())
            if "errorMessage" in body:
                print(f"  {fn} invocation error: {body['errorMessage']}")
                sys.exit(1)
        print(f"  {fn} invoked {count}x")


def destroy():
    for name, _, _, _ in SECRETS:
        try:
            sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
            print(f"deleted secret {name}")
        except sm.exceptions.ResourceNotFoundException:
            pass
    for name, _, _ in PARAMS:
        try:
            ssm.delete_parameter(Name=name)
            print(f"deleted parameter {name}")
        except ssm.exceptions.ParameterNotFound:
            pass
    for fn in [ROTATION_FN, *CONSUMERS.values()]:
        try:
            lam.delete_function(FunctionName=fn)
            print(f"deleted lambda {fn}")
        except lam.exceptions.ResourceNotFoundException:
            pass
    for role in [f"{ROTATION_FN}-role", "secops-test-consumer-role"]:
        try:
            for p in iam.list_role_policies(RoleName=role)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role, PolicyName=p)
            iam.delete_role(RoleName=role)
            print(f"deleted role {role}")
        except iam.exceptions.NoSuchEntityException:
            pass
    try:
        for k in iam.list_access_keys(UserName=TEST_USER)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=TEST_USER, AccessKeyId=k["AccessKeyId"])
        iam.delete_user(UserName=TEST_USER)
        print(f"deleted user {TEST_USER}")
    except iam.exceptions.NoSuchEntityException:
        pass
    print("destroy complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--destroy", action="store_true")
    parser.add_argument("--traffic", action="store_true")
    args = parser.parse_args()
    if args.destroy:
        destroy()
    elif args.traffic:
        traffic()
    else:
        create()
