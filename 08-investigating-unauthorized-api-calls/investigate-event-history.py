#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 5:
    print(
        "Usage: python3 investigate-event-history.py "
        "HISTORY_JSON PARAMETER_NAME PRINCIPAL_ARN OUTPUT_JSON"
    )
    sys.exit(2)

history_file, parameter_name, principal_arn, output_file = sys.argv[1:]

with open(history_file) as file:
    document = json.load(file)

matches = []

for item in document.get("Events", []):
    raw = item.get("CloudTrailEvent")

    if not raw:
        continue

    event = json.loads(raw)

    request = event.get("requestParameters") or {}
    identity = event.get("userIdentity") or {}
    error = str(event.get("errorCode") or "")

    if (
        event.get("eventName") == "DeleteParameter"
        and event.get("eventSource") == "ssm.amazonaws.com"
        and request.get("name") == parameter_name
        and identity.get("arn") == principal_arn
        and (
            "accessdenied" in error.lower()
            or "unauthorized" in error.lower()
        )
    ):
        session_context = identity.get("sessionContext") or {}
        session_issuer = session_context.get("sessionIssuer") or {}

        matches.append({
            "eventID": event.get("eventID"),
            "eventTime": event.get("eventTime"),
            "awsRegion": event.get("awsRegion"),
            "eventSource": event.get("eventSource"),
            "eventName": event.get("eventName"),
            "errorCode": event.get("errorCode"),
            "errorMessage": event.get("errorMessage"),
            "identityType": identity.get("type"),
            "principalArn": identity.get("arn"),
            "roleArn": session_issuer.get("arn"),
            "sourceIPAddress": event.get("sourceIPAddress"),
            "userAgent": event.get("userAgent"),
            "parameterName": parameter_name,
            "readOnly": event.get("readOnly")
        })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit("Target denied event not found")

print("SUCCESS: Exact denied API event identified")
