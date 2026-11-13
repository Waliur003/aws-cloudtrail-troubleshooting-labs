#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 4:
    print(
        "Usage: python3 verify-kms-cloudtrail-logs.py "
        "DIRECTORY PARAMETER_NAME OUTPUT_FILE"
    )
    sys.exit(2)

directory, parameter_name, output_file = sys.argv[1:]

matches = []

for filename in glob.glob(
    f"{directory}/**/*.json.gz",
    recursive=True
):
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
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
                "awsRegion": event.get("awsRegion"),
                "parameterName": parameter_name,
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit("Target event not found")

print("SUCCESS: CloudTrail event verified")
