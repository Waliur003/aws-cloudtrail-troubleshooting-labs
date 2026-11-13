#!/usr/bin/env python3

import json
import sqlite3
import sys

if len(sys.argv) != 2:
    sys.exit("Usage: python3 run-local-query.py QUERY.sql")

with open(sys.argv[1]) as file:
    query = file.read()

connection = sqlite3.connect("lab10-audit.db")
connection.row_factory = sqlite3.Row

rows = [
    dict(row)
    for row in connection.execute(query).fetchall()
]

print(json.dumps(rows, indent=2))
print(f"Rows returned: {len(rows)}")

connection.close()
