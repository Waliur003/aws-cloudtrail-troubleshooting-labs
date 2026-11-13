#!/usr/bin/env python3

import glob
import gzip
import json
import os
import sys

if len(sys.argv) != 6:
    print(
        "Usage: python3 verify-unauthorized-api-event.py "
        "LOG_DIR PARAMETER_NAME PRINCIPAL_ARN "
        "INCIDENT_JSON OUTPUT_JSON"
    )
    sys.exit(2)

log_dir, parameter, principal, incident_file, output_file = sys.argv[1:]

with open(incident_file) as file:
    incident_events = json.load(file)

expected_ids = {
    event["eventID"]
    for event in incident_events
    if event.get("eventID")
}

if not expected_ids:
    raise SystemExit("No verified Event history IDs provided")

matches = []

files = glob.glob(
    os.path.join(log_dir, "**", "*.json.gz"),
    recursive=True
)

for filename in files:
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        request = event.get("requestParameters") or {}
        identity = event.get("userIdentity") or {}
        error = str(event.get("errorCode") or "")

        if (
            event.get("eventID") in expected_ids
            and event.get("eventName") == "DeleteParameter"
            and event.get("eventSource") == "ssm.amazonaws.com"
            and request.get("name") == parameter
            and identity.get("arn") == principal
            and (
                "accessdenied" in error.lower()
                or "unauthorized" in error.lower()
            )
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "eventSource": event.get("eventSource"),
                "awsRegion": event.get("awsRegion"),
                "principalArn": identity.get("arn"),
                "errorCode": event.get("errorCode"),
                "parameterName": parameter,
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit("Denied incident event not yet found in S3 logs")

print("SUCCESS: Denied API call verified in S3 audit logs")
