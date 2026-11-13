#!/usr/bin/env python3

import json
import os
import sys

if len(sys.argv) != 3:
    print(
        "Usage: python3 generate-bucket-policy.py "
        "BUCKET_NAME OUTPUT_FILE"
    )
    sys.exit(1)

bucket = sys.argv[1]
output_file = sys.argv[2]

account_id = os.environ["ACCOUNT_ID"]
trail_arn = os.environ["TRAIL_ARN"]

policy = {
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

with open(output_file, "w") as file:
    json.dump(policy, file, indent=2)

print(f"Generated policy: {output_file}")
