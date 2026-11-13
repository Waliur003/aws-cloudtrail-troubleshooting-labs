#!/usr/bin/env python3

import glob
import gzip
import json
import os

directory = "evidence/digests"
files = sorted(
    glob.glob(
        os.path.join(directory, "**", "*.json.gz"),
        recursive=True
    )
)

if not files:
    raise SystemExit(
        "No digest files downloaded yet"
    )

for filename in files:
    with gzip.open(filename, "rt") as file:
        digest = json.load(file)

    print("\nDigest:", filename)
    print("Start:", digest.get("digestStartTime"))
    print("End:", digest.get("digestEndTime"))
    print("S3 bucket:", digest.get("digestS3Bucket"))
    print("S3 object:", digest.get("digestS3Object"))
    print(
        "Signature algorithm:",
        digest.get("digestSignatureAlgorithm")
    )
    print(
        "Previous digest:",
        digest.get("previousDigestS3Object")
    )

    logs = digest.get("logFiles", [])
    print("Referenced log files:", len(logs))

    for item in logs:
        print("  Log:", item.get("s3Object"))
        print("  Hash:", item.get("hashValue"))
