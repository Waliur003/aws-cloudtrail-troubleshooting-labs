#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 4:
    print(
        "Usage: python3 verify-s3-delivery.py "
        "LOG_DIR PARAMETER_NAME OUTPUT_FILE"
    )
    sys.exit(2)

log_dir = sys.argv[1]
target_name = sys.argv[2]
output_file = sys.argv[3]

matches = []

for filename in glob.glob(
    f"{log_dir}/**/*.json.gz",
    recursive=True
):
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        request = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "PutParameter"
            and request.get("name") == target_name
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "awsRegion": event.get("awsRegion"),
                "parameterName": target_name,
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    print("Target event not yet found in S3 logs")
    sys.exit(1)

print("SUCCESS: Target CloudTrail event found in S3")
