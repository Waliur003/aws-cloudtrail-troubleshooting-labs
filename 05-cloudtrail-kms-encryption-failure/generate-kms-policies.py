#!/usr/bin/env python3

import json
import os

account = os.environ["ACCOUNT_ID"]
region = os.environ["AWS_REGION"]
trail = os.environ["TRAIL_ARN"]

admin_statement = {
    "Sid": "EnableAccountKeyAdministration",
    "Effect": "Allow",
    "Principal": {
        "AWS": f"arn:aws:iam::{account}:root"
    },
    "Action": "kms:*",
    "Resource": "*"
}

encrypt_statement = {
    "Sid": "AllowCloudTrailGenerateDataKey",
    "Effect": "Allow",
    "Principal": {
        "Service": "cloudtrail.amazonaws.com"
    },
    "Action": "kms:GenerateDataKey*",
    "Resource": "*",
    "Condition": {
        "StringEquals": {
            "aws:SourceArn": trail
        },
        "StringLike": {
            "kms:EncryptionContext:aws:cloudtrail:arn":
                f"arn:aws:cloudtrail:*:{account}:trail/*"
        }
    }
}

describe_statement = {
    "Sid": "AllowCloudTrailDescribeKey",
    "Effect": "Allow",
    "Principal": {
        "Service": "cloudtrail.amazonaws.com"
    },
    "Action": "kms:DescribeKey",
    "Resource": "*",
    "Condition": {
        "StringEquals": {
            "aws:SourceArn": trail
        }
    }
}

correct_policy = {
    "Version": "2012-10-17",
    "Statement": [
        admin_statement,
        encrypt_statement,
        describe_statement
    ]
}

broken_policy = {
    "Version": "2012-10-17",
    "Statement": [
        admin_statement,
        describe_statement
    ]
}

for filename, policy in [
    ("correct-kms-policy.json", correct_policy),
    ("broken-kms-policy.json", broken_policy)
]:
    with open(filename, "w") as f:
        json.dump(policy, f, indent=2)

    print("Generated:", filename)
