#!/usr/bin/env python3

import json
import os

bucket = os.environ["BUCKET_NAME"]
account_id = os.environ["ACCOUNT_ID"]
trail_arn = os.environ["TRAIL_ARN"]

correct_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::{bucket}",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": trail_arn
                }
            }
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": (
                f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*"
            ),
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": trail_arn
                }
            }
        }
    ]
}

# Broken policy intentionally removes the
# CloudTrail s3:PutObject statement.

broken_policy = {
    "Version": "2012-10-17",
    "Statement": [
        correct_policy["Statement"][0]
    ]
}

with open("correct-bucket-policy.json", "w") as f:
    json.dump(correct_policy, f, indent=2)

with open("broken-bucket-policy.json", "w") as f:
    json.dump(broken_policy, f, indent=2)

print("Created correct-bucket-policy.json")
print("Created broken-bucket-policy.json")
