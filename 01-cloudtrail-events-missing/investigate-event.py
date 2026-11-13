#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 3:
    print(
        "Usage: python3 investigate-event.py "
        "EVENTS_FILE PARAMETER_NAME"
    )
    sys.exit(1)

filename = sys.argv[1]
target_name = sys.argv[2]

with open(filename) as file:
    data = json.load(file)

matches = []

for item in data.get("Events", []):
    event = json.loads(item["CloudTrailEvent"])

    request = event.get("requestParameters") or {}

    if request.get("name") != target_name:
        continue

    result = {
        "eventID": event.get("eventID"),
        "eventTime": event.get("eventTime"),
        "eventName": event.get("eventName"),
        "eventSource": event.get("eventSource"),
        "awsRegion": event.get("awsRegion"),
        "parameterName": request.get("name"),
        "identityType": (
            event.get("userIdentity") or {}
        ).get("type"),
        "errorCode": event.get("errorCode"),
    }

    matches.append(result)

print(json.dumps(matches, indent=2))

with open("lab01-verified-event.json", "w") as file:
    json.dump(matches, file, indent=2)

if not matches:
    print("Target event not found.")
    sys.exit(1)

print("SUCCESS: Target CloudTrail event found.")
