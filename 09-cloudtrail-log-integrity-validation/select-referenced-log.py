#!/usr/bin/env python3

import glob
import gzip
import json
import os

files = sorted(glob.glob(
    "evidence/digests/**/*.json.gz",
    recursive=True
))

bucket = os.environ["LOG_BUCKET"]
account = os.environ["ACCOUNT_ID"]
region = os.environ["AWS_REGION"]

expected_prefix = (
    f"AWSLogs/{account}/CloudTrail/{region}/"
)

for filename in files:
    with gzip.open(filename, "rt") as file:
        digest = json.load(file)

    if digest.get("digestS3Bucket") != bucket:
        continue

    for log in digest.get("logFiles", []):
        if (
            log.get("s3Bucket") == bucket
            and log.get("s3Object", "").startswith(expected_prefix)
        ):
            with open("lab09-target-log-key.txt", "w") as target:
                target.write(log["s3Object"] + "\n")

            with open("lab09-target-hash.txt", "w") as target:
                target.write(log["hashValue"] + "\n")

            print("Selected:", log["s3Object"])
            print("Expected SHA-256:", log["hashValue"])
            raise SystemExit(0)

raise SystemExit(
    "No digest-referenced lab log found yet"
)
