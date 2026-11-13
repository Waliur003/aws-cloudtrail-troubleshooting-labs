#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 2:
    print("Usage: python3 verify-s3-delivery.py PARAMETER_NAME")
    sys.exit(2)

target = sys.argv[1]
matches = []

for filename in glob.glob(
    "downloaded-cloudtrail-logs/**/*.json.gz",
    recursive=True
):
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        request = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "PutParameter"
            and request.get("name") == target
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "awsRegion": event.get("awsRegion"),
                "parameterName": request.get("name"),
                "sourceFile": filename
            })

with open("lab02-recovery-s3-evidence.json", "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    print("Recovery event not yet found in downloaded S3 logs")
    sys.exit(1)

print("SUCCESS: Recovery event found in delivered CloudTrail S3 log")
