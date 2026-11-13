#!/usr/bin/env python3

import glob
import gzip
import json
import os
import sys

if len(sys.argv) != 4:
    print(
        "Usage: python3 verify-cloudtrail-logs.py "
        "LOG_DIRECTORY PARAMETER_NAME OUTPUT_FILE"
    )
    sys.exit(2)

directory = sys.argv[1]
parameter_name = sys.argv[2]
output_file = sys.argv[3]

matches = []
files = glob.glob(
    os.path.join(directory, "**", "*.json.gz"),
    recursive=True
)

print(f"Scanning {len(files)} CloudTrail files")

for filename in files:
    with gzip.open(filename, "rt") as file:
        data = json.load(file)

    for event in data.get("Records", []):
        request = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "PutParameter"
            and event.get("eventSource") == "ssm.amazonaws.com"
            and request.get("name") == parameter_name
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "eventSource": event.get("eventSource"),
                "awsRegion": event.get("awsRegion"),
                "parameterName": request.get("name"),
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    print("ERROR: Target event not found in downloaded logs")
    sys.exit(1)

print("SUCCESS: Verified CloudTrail event in S3 logs")
