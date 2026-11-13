#!/usr/bin/env python3

import json

with open("lab08-incident-event.json") as file:
    events = json.load(file)

if not events:
    raise SystemExit("Incident event was not verified")

event = events[0]

timeline = {
    "incidentID": "INC-CT-008",
    "classification": "Controlled denied API operation",
    "eventID": event["eventID"],
    "eventTime": event["eventTime"],
    "awsRegion": event["awsRegion"],
    "eventSource": event["eventSource"],
    "eventName": event["eventName"],
    "principalArn": event["principalArn"],
    "roleArn": event["roleArn"],
    "sourceIPAddress": event["sourceIPAddress"],
    "userAgent": event["userAgent"],
    "resource": event["parameterName"],
    "errorCode": event["errorCode"],
    "outcome": "Denied",
    "rootCause": "Explicit IAM deny for ssm:DeleteParameter",
    "resourceDeleted": False
}

with open("lab08-incident-timeline.json", "w") as file:
    json.dump(timeline, file, indent=2)

print(json.dumps(timeline, indent=2))
