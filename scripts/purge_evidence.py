"""Delete every object version in the evidence bucket with a governance
retention bypass, so terraform destroy can remove the bucket. Demo
retention is 1 day; production would never ship this script."""

import sys

import boto3

bucket = sys.argv[1] if len(sys.argv) > 1 else None
if not bucket:
    sts = boto3.client("sts")
    bucket = f"secops-evidence-{sts.get_caller_identity()['Account']}"

s3 = boto3.client("s3")
paginator = s3.get_paginator("list_object_versions")
deleted = 0
try:
    for page in paginator.paginate(Bucket=bucket):
        for group in ("Versions", "DeleteMarkers"):
            for v in page.get(group, []):
                s3.delete_object(
                    Bucket=bucket,
                    Key=v["Key"],
                    VersionId=v["VersionId"],
                    BypassGovernanceRetention=True,
                )
                deleted += 1
except s3.exceptions.NoSuchBucket:
    pass
print(f"purged {deleted} object versions from {bucket}")
