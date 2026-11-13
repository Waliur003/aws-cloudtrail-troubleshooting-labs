#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 5:
    print(
        "Usage: python3 verify-s3-data-events.py "
        "LOG_DIR BUCKET_NAME OBJECT_KEY OUTPUT_FILE"
    )
    sys.exit(2)

log_dir, bucket, key, output = sys.argv[1:]

required = {"PutObject", "GetObject"}
matches = []

files = glob.glob(
    f"{log_dir}/**/*.json.gz",
    recursive=True
)

print(f"Inspecting {len(files)} CloudTrail files")

for filename in files:
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        name = event.get("eventName")

        if name not in required:
            continue

        if event.get("eventSource") != "s3.amazonaws.com":
            continue

        request = event.get("requestParameters") or {}

        event_bucket = request.get("bucketName")
        event_key = request.get("key")

        if event_bucket != bucket or event_key != key:
            continue

        matches.append({
            "eventID": event.get("eventID"),
            "eventTime": event.get("eventTime"),
            "eventName": name,
            "eventCategory": event.get("eventCategory"),
            "eventSource": event.get("eventSource"),
            "awsRegion": event.get("awsRegion"),
            "bucketName": event_bucket,
            "objectKey": event_key,
            "sourceFile": filename
        })

with open(output, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

found = {event["eventName"] for event in matches}
missing = required - found

if missing:
    print("Missing events:", ", ".join(sorted(missing)))
    sys.exit(1)

print("SUCCESS: PutObject and GetObject data events verified")
