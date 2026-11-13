#!/usr/bin/env python3

import gzip
import hashlib
import sys

if len(sys.argv) != 3:
    print(
        "Usage: python3 compare-digest-hash.py "
        "LOG_FILE EXPECTED_HASH_FILE"
    )
    sys.exit(2)

filename, hash_file = sys.argv[1:]

with open(hash_file) as file:
    expected = file.read().strip().lower()

with gzip.open(filename, "rb") as file:
    content = file.read()

actual = hashlib.sha256(content).hexdigest()

print("Expected SHA-256:", expected)
print("Actual SHA-256:  ", actual)

if actual == expected:
    print("SUCCESS: Log matches digest hash")
else:
    print("FAILURE: Log hash mismatch")
    sys.exit(1)
