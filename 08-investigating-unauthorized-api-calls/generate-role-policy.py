#!/usr/bin/env python3

import json
import os

account = os.environ["ACCOUNT_ID"]
region = os.environ["AWS_REGION"]
parameter = os.environ["PARAMETER_NAME"]

resource = (
    f"arn:aws:ssm:{region}:{account}:parameter"
    f"{parameter}"
)

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadingLabParameter",
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": resource
        },
        {
            "Sid": "ExplicitlyDenyDeletingLabParameter",
            "Effect": "Deny",
            "Action": "ssm:DeleteParameter",
            "Resource": resource
        }
    ]
}

with open("lab08-role-policy.json", "w") as file:
    json.dump(policy, file, indent=2)

print("Restricted IAM role policy generated")
