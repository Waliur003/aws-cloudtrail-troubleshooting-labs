#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 3:
    print(
        "Usage: python3 verify-event-history.py "
        "EVENT_HISTORY_JSON PARAMETER_NAME"
    )
    sys.exit(2)

filename, parameter = sys.argv[1:]

with open(filename) as f:
    document = json.load(f)

matches = []

for item in document.get("Events", []):
    raw_event = item.get("CloudTrailEvent")

    if not raw_event:
        continue

    event = json.loads(raw_event)
    request = event.get("requestParameters") or {}

    if (
        event.get("eventName") == "PutParameter"
        and event.get("eventSource") == "ssm.amazonaws.com"
        and request.get("name") == parameter
    ):
        matches.append({
            "eventID": event.get("eventID"),
            "eventTime": event.get("eventTime"),
            "awsRegion": event.get("awsRegion"),
            "eventName": event.get("eventName"),
            "parameterName": parameter
        })

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit("Target event not found in Event history")

print("SUCCESS: Matching Event history record found")
