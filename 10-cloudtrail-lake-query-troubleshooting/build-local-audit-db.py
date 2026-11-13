#!/usr/bin/env python3

import json
import sqlite3

with open("lab10-event-history.json") as file:
    history = json.load(file)

connection = sqlite3.connect("lab10-audit.db")

connection.execute("""
CREATE TABLE IF NOT EXISTS events (
    eventID TEXT PRIMARY KEY,
    eventTime TEXT,
    eventName TEXT,
    eventSource TEXT,
    awsRegion TEXT,
    parameterName TEXT,
    errorCode TEXT
)
""")

for entry in history.get("Events", []):
    raw = entry.get("CloudTrailEvent")
    if not raw:
        continue

    event = json.loads(raw)
    request = event.get("requestParameters") or {}

    connection.execute("""
    INSERT OR REPLACE INTO events
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("eventID"),
        event.get("eventTime"),
        event.get("eventName"),
        event.get("eventSource"),
        event.get("awsRegion"),
        request.get("name"),
        event.get("errorCode")
    ))

connection.commit()

count = connection.execute(
    "SELECT COUNT(*) FROM events"
).fetchone()[0]

connection.close()

print(f"Imported {count} CloudTrail events")
