# Lab 10 — CloudTrail Lake Query Troubleshooting

**AWS CloudTrail Troubleshooting Labs | Cloud Engineering & Cloud Security Engineering**

## Overview

This lab demonstrates how to investigate and troubleshoot missing AWS API events in CloudTrail Lake SQL queries.

AWS CloudTrail provides audit records of supported AWS API operations. Cloud Engineers and Cloud Security Engineers use these records to investigate security incidents, troubleshoot infrastructure problems, and understand changes to AWS resources.

CloudTrail Lake provides a managed event data store where supported audit events can be queried using SQL.

However, a query can return zero results even when the expected AWS API operation occurred.

Possible causes include incorrect SQL filters, an invalid time range, the wrong AWS Region, an incorrect event name, missing ingestion, or querying the wrong event data store.

In this lab, we reproduce these common troubleshooting scenarios.

We create a dedicated CloudTrail Lake event data store where the AWS account is eligible, generate real Systems Manager API activity, and execute SQL queries with intentionally incorrect filters.

We investigate query execution status and statistics, identify the incorrect conditions, and correct the SQL to retrieve the expected management events.

We also examine how to distinguish a query configuration problem from a CloudTrail Lake ingestion problem.

Because CloudTrail Lake stopped accepting new customers on May 31, 2026, this lab includes a second implementation using AWS CloudTrail Event history and Python SQLite.

The alternative path allows engineers to practice SQL-based audit investigations using real AWS event records without requiring access to CloudTrail Lake.

Finally, we verify the investigation findings and remove temporary AWS resources.

### Troubleshooting Workflow

```text
Generate AWS Management Activity
                |
                v
Inspect CloudTrail Event History
                |
                v
Create or Identify Event Data Store
                |
                v
Execute SQL Query
                |
                v
No Matching Results
                |
                v
Inspect Query Status and Statistics
                |
                v
Investigate SQL Filters
                |
                v
Check Event Name / Source / Region
                |
                v
Verify Time Range and Ingestion
                |
                v
Correct Query
                |
                v
Retrieve Matching Events
                |
                v
Verify Exact Resource Activity
                |
                v
Document and Cleanup
```

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-010 |
| Lab Name | CloudTrail Lake Query Troubleshooting |
| Difficulty | Advanced |
| Primary Service | AWS CloudTrail |
| Optional Service | CloudTrail Lake |
| Supporting Service | AWS Systems Manager |
| AWS Region | `us-east-1` |
| Operating System | WSL2 Ubuntu |
| Interface | AWS CLI v2 |
| Languages | Bash, Python 3, SQL |
| Event Data Store | Dedicated Lab 10 EDS |
| EDS Scope | Single-Region, single-account |
| Event Category | Management |
| Retention | 7 days |
| Billing Mode | EXTENDABLE_RETENTION_PRICING |
| Test APIs | `PutParameter`, `GetParameter` |
| SQL Problems | Wrong event name, source, Region, time |
| Query APIs | StartQuery, DescribeQuery, GetQueryResults |
| Alternative Query Engine | SQLite |
| Investigation | Missing management events |
| Root Cause | Incorrect filters or missing ingestion |
| Recovery | Correct SQL and validate events |
| Cleanup | Delete parameter and disposable EDS |

### Learning Objectives

- Understand CloudTrail Lake event data stores.
- Understand CloudTrail Lake service availability.
- Create a small event data store when eligible.
- Understand event ingestion.
- Generate real AWS management events.
- Write SQL queries against CloudTrail events.
- Troubleshoot incorrect event names.
- Troubleshoot incorrect event sources.
- Troubleshoot incorrect Region filters.
- Troubleshoot incorrect timestamps.
- Inspect query execution status.
- Understand asynchronous SQL queries.
- Interpret query statistics.
- Identify missing ingestion.
- Compare Event history with Lake results.
- Query actual CloudTrail events using SQLite.
- Verify the exact affected resource.
- Understand query cost considerations.
- Document root cause and remediation.
- Safely delete temporary resources.

---

## 2. Production Incident Scenario

### Incident Description

A company's Cloud Security team uses CloudTrail Lake to investigate AWS infrastructure activity.

During an investigation, an engineer needs to locate a `PutParameter` operation performed in `us-east-1`.

The API call was successful and appears in CloudTrail Event history.

However, the engineer's CloudTrail Lake SQL query returns no matching records.

Initially, the engineer suspects that CloudTrail failed to collect the event.

The engineer investigates the SQL statement, event data store configuration, ingestion settings, and query execution status.

The investigation reveals that the original SQL query includes incorrect conditions.

Examples include:

```sql
eventName = 'PutParameters'
```

Instead of:

```sql
eventName = 'PutParameter'
```

Another query incorrectly references:

```sql
awsRegion = 'eu-west-1'
```

Even though the API operation occurred in:

```sql
awsRegion = 'us-east-1'
```

A third query uses an unrelated event source.

The engineer corrects these filters and verifies whether the expected event is present.

If the corrected query still returns no results, the engineer checks whether the event data store has successfully ingested the activity.

The investigation concludes by identifying the actual cause, verifying the event, and documenting the findings.

### Incident Symptoms

- An AWS API operation completes successfully.
- The operation appears in regional Event history.
- CloudTrail Lake query returns no matching rows.
- Query may have status `FINISHED`.
- SQL filters do not match the event.
- A broader diagnostic query may return records.
- Incorrect conditions exclude the intended activity.
- Alternatively, event ingestion may be incomplete or delayed.

### Business Impact

- Incomplete security investigations.
- Difficulty locating AWS API activity.
- Incorrect conclusions about missing audit records.
- Delayed incident response.
- Increased query scanning costs.
- Poor visibility into resource changes.
- Incorrect compliance investigation results.
- Wasted engineering time.

### Objective

Determine whether expected audit records are missing because of incorrect SQL, event data store configuration, ingestion problems, or query execution failures.

---

## 3. AWS Architecture

### CloudTrail Lake Architecture

```text
                 AWS Account
                      |
                      v
                 AWS API Activity
                      |
                      v
                  CloudTrail
                      |
                      v
                Management Events
                      |
                      v
             CloudTrail Lake Ingestion
                      |
                      v
                Event Data Store
                      |
                      v
                 SQL Query Engine
                      |
                      v
                 Query Results
                      |
                      v
              Security Investigation
```

### Broken Query Architecture

```text
AWS API: PutParameter
          |
          v
CloudTrail Event Generated
          |
          v
Event Data Store
          |
          v
SQL Query Executed
          |
          v
Incorrect WHERE Conditions
          |
          v
Matching Event Excluded
          |
          v
Query Returns Zero Rows
```

### Recovered Architecture

```text
CloudTrail Management Event
          |
          v
Event Data Store
          |
          v
Correct SQL Query
          |
          v
Matching Event Name
Matching Event Source
Matching AWS Region
Correct Time Window
          |
          v
Expected Event Returned
          |
          v
Investigation Verified
```

### Alternative Architecture — SQLite

```text
AWS API Operation
          |
          v
CloudTrail Event History
          |
          v
AWS CLI LookupEvents
          |
          v
JSON Event Records
          |
          v
Python JSON Parser
          |
          v
Local SQLite Database
          |
          v
SQL Investigation
          |
          v
Matching AWS Event
```

### Architecture Components

| Component | Purpose |
|---|---|
| CloudTrail Event history | Provides recent regional management events |
| CloudTrail Lake | Managed audit analytics service |
| Event Data Store | Stores events selected for ingestion |
| SQL Query Engine | Filters and analyzes events |
| StartQuery | Submits a query |
| DescribeQuery | Reports execution status |
| GetQueryResults | Retrieves matching records |
| Systems Manager | Generates controlled API activity |
| SQLite | Provides local SQL analysis |
| AWS CLI | Retrieves and investigates events |
| Python | Parses and verifies results |

---

## 4. Understanding CloudTrail Lake

### What Is CloudTrail Lake?

CloudTrail Lake is a managed service for storing and analyzing supported audit events using SQL.

### Important Service Availability

AWS CloudTrail Lake closed to new customers on May 31, 2026.

Existing CloudTrail Lake customers can continue using the service.

New AWS accounts may not be eligible to create event data stores.

Standard CloudTrail trails and Event history remain available.

### What Is an Event Data Store?

An event data store, or EDS, stores selected events for CloudTrail Lake analysis.

### What Is Event Ingestion?

Event ingestion is the process of collecting supported events into an event data store.

### What Is StartQuery?

`StartQuery` submits a SQL query for execution.

The operation returns a query ID.

### What Is DescribeQuery?

`DescribeQuery` returns metadata about a submitted query.

This includes:

- Query status.
- Error information.
- Events scanned.
- Events matched.
- Bytes scanned.
- Execution time.

### What Is GetQueryResults?

`GetQueryResults` retrieves the result rows of a CloudTrail Lake query.

### What Is QueryStatus?

CloudTrail Lake supports these states:

```text
QUEUED
RUNNING
FINISHED
FAILED
TIMED_OUT
CANCELLED
```

### What Is QueryResultRows?

`QueryResultRows` contains the individual result rows.

Rows are represented as collections of field/value mappings rather than ordinary flat JSON objects.

### Why Are Time Filters Important?

Time filters help restrict queries to relevant events and reduce the amount of data scanned.

### What Is SQLite?

SQLite is a lightweight SQL database engine.

Python includes support for SQLite through its standard `sqlite3` module.

In this lab, SQLite provides a practical SQL troubleshooting alternative when CloudTrail Lake is unavailable.

### Does an Empty Result Mean the Event Never Occurred?

No.

It may mean the SQL filters are wrong, the event has not been ingested, the wrong event data store was queried, or the time window excludes the event.

---

## 5. Prerequisites, Permissions, and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL2 Ubuntu.
- Bash.
- Python 3.
- Systems Manager permissions.
- CloudTrail Event history access.
- Existing CloudTrail Lake eligibility for the managed path.

### Relevant AWS Permissions

```text
sts:GetCallerIdentity

cloudtrail:LookupEvents
cloudtrail:ListEventDataStores
cloudtrail:CreateEventDataStore
cloudtrail:GetEventDataStore
cloudtrail:StartQuery
cloudtrail:DescribeQuery
cloudtrail:GetQueryResults
cloudtrail:UpdateEventDataStore
cloudtrail:DeleteEventDataStore

ssm:PutParameter
ssm:GetParameter
ssm:DeleteParameter
```

### Safety Rules

- Never modify existing production event data stores.
- Never delete an event data store that you did not create for this lab.
- Use synthetic Parameter Store values.
- Use a dedicated disposable resource.
- Restrict event data store scope.
- Use a short retention period.
- Limit query frequency and data scanned.
- Preserve evidence before cleanup.
- Never publish unredacted account audit records.
- Verify the EDS project tag before deletion.

### Cost Considerations

CloudTrail Lake can incur charges for:

- Event ingestion.
- Event storage.
- SQL query scanning.

Use the smallest practical scope and delete the temporary event data store after verification.

The SQLite alternative does not incur CloudTrail Lake charges.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Create Directory

```bash
cd ~/aws-cloudtrail-troubleshooting-labs

mkdir -p 10-cloudtrail-lake-query-troubleshooting

cd 10-cloudtrail-lake-query-troubleshooting
```

### Step 2 — Verify Environment

```bash
aws --version
python3 --version
aws sts get-caller-identity
```

### Step 3 — Configure Variables

```bash
export AWS_REGION="us-east-1"
export AWS_PAGER=""

export ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text)

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab10"

export SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export EDS_NAME="cloudtrail-lab10-${SUFFIX}"

export PARAMETER_NAME="/cloudtrail-lab10/test-${SUFFIX}"

export LAB_START="$(date -u -d '10 minutes ago' \
  +'%Y-%m-%d %H:%M:%S')"
```

### Step 4 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$EDS_NAME"
echo "$PARAMETER_NAME"
echo "$LAB_START"
```

### Step 5 — Save Environment

```bash
cat > lab10-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export EDS_NAME="$EDS_NAME"
export PARAMETER_NAME="$PARAMETER_NAME"
export LAB_START="$LAB_START"
EOF
```

Restore with:

```bash
source lab10-resources.env
```

Keep this file private.

---

## 7. Check CloudTrail Lake Eligibility

### Step 1 — List Event Data Stores

```bash
aws cloudtrail list-event-data-stores \
  --region "$AWS_REGION" \
  --output json
```

### Step 2 — Interpret the Result

| Result | Meaning |
|---|---|
| Event data stores listed | Stores are visible to your identity |
| Empty list | No visible stores; eligibility not established |
| AccessDenied | Insufficient authorization or account restriction |
| Service restriction | Lake creation may be unavailable |

An empty list does not prove that a new CloudTrail Lake event data store can be created.

### Decision

**Path A — Existing CloudTrail Lake customer:** Continue to Section 8.

**Path B — No CloudTrail Lake access:** Skip to Section 16 and complete the SQLite alternative.

Do not attempt to bypass CloudTrail Lake account eligibility restrictions.

---

## 8. Create a CloudTrail Lake Event Data Store

This section applies only to eligible existing customers.

### Step 1 — Create the Event Data Store

```bash
aws cloudtrail create-event-data-store \
  --name "$EDS_NAME" \
  --no-multi-region-enabled \
  --no-organization-enabled \
  --retention-period 7 \
  --billing-mode EXTENDABLE_RETENTION_PRICING \
  --no-termination-protection-enabled \
  --tags-list "Key=Project,Value=$PROJECT_TAG" \
  --region "$AWS_REGION" \
  > lab10-create-eds.json
```

The default event selection includes management events.

### Step 2 — Retrieve the ARN

```bash
export EDS_ARN=$(python3 - <<'PY'
import json

with open("lab10-create-eds.json") as file:
    data = json.load(file)

print(data["EventDataStoreArn"])
PY
)
```

### Step 3 — Retrieve the Event Data Store ID

```bash
export EDS_ID="${EDS_ARN##*/}"
```

### Step 4 — Verify Identifiers

```bash
echo "$EDS_ARN"
echo "$EDS_ID"
```

### Step 5 — Save Identifiers

```bash
cat >> lab10-resources.env <<EOF
export EDS_ARN="$EDS_ARN"
export EDS_ID="$EDS_ID"
EOF
```

### Step 6 — Verify Configuration

```bash
aws cloudtrail get-event-data-store \
  --event-data-store "$EDS_ARN" \
  --query '{Name:Name,Status:Status,RegionScope:MultiRegionEnabled,Ingestion:IngestionEnabled,Retention:RetentionPeriod,Protection:TerminationProtectionEnabled,Selectors:AdvancedEventSelectors}' \
  --output json \
  --region "$AWS_REGION"
```

### Expected Configuration

| Setting | Expected |
|---|---|
| Single Region | true |
| MultiRegionEnabled | false |
| OrganizationEnabled | false |
| Retention | 7 days |
| Termination protection | false |
| Management events | Selected |
| Ingestion | Enabled |

Do not proceed with querying until the event data store has been created successfully and its ingestion settings are correct.

---

## 9. Generate AWS Management Events

### Step 1 — Create the Test Parameter

```bash
aws ssm put-parameter \
  --name "$PARAMETER_NAME" \
  --type String \
  --tier Standard \
  --value "cloudtrail-lake-lab10" \
  --region "$AWS_REGION"
```

### Step 2 — Read the Parameter

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --region "$AWS_REGION"
```

### Step 3 — Inspect Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab10-event-history.json
```

### Step 4 — Configure the Query End Time

```bash
export LAB_END="$(date -u -d '+10 minutes' \
  +'%Y-%m-%d %H:%M:%S')"
```

### Baseline Summary

| Component | Expected |
|---|---|
| Test parameter | Created |
| PutParameter | Successful |
| GetParameter | Successful |
| Event history | Event available after indexing |
| Event data store | Management-event ingestion enabled |
| CloudTrail Lake record | Available after ingestion |

CloudTrail Event history indexing and Lake ingestion are separate processes.

An event appearing in Event history does not automatically prove it has already been ingested into the event data store.

---

<WritingBlock id="81744" variant="document">## 10. Create Incorrect SQL Queries

### Purpose

We intentionally create SQL queries that exclude the expected management event.

These queries are syntactically valid but contain incorrect filtering conditions.

### Step 1 — Generate SQL Files

```bash
python3 - <<'PY'
import os

eds = os.environ["EDS_ID"]
start = os.environ["LAB_START"]
end = os.environ["LAB_END"]

base = f"""
SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion
FROM {eds}
WHERE eventTime >= timestamp '{start}'
  AND eventTime <= timestamp '{end}'
"""

queries = {
    "01-wrong-event-name.sql":
        base + """
  AND eventName = 'PutParameters'
LIMIT 20
""",

    "02-wrong-region.sql":
        base + """
  AND eventName = 'PutParameter'
  AND awsRegion = 'eu-west-1'
LIMIT 20
""",

    "03-wrong-event-source.sql":
        base + """
  AND eventName = 'PutParameter'
  AND eventSource = 'ec2.amazonaws.com'
LIMIT 20
"""
}

for filename, query in queries.items():
    with open(filename, "w") as file:
        file.write(query.strip() + "\n")

    print("Created:", filename)
PY
```

### Step 2 — Inspect the Queries

```bash
cat 01-wrong-event-name.sql
```

```bash
cat 02-wrong-region.sql
```

```bash
cat 03-wrong-event-source.sql
```

### Incorrect Configuration Matrix

| Query | Incorrect Field | Expected Result |
|---|---|---|
| Wrong event name | PutParameters | No matching PutParameter records |
| Wrong Region | eu-west-1 | Excludes us-east-1 event |
| Wrong source | ec2.amazonaws.com | Excludes SSM event |

### Understanding the Failure

The SQL query can finish successfully while returning zero rows.

This is a query filtering problem rather than necessarily an ingestion failure.

---

## 11. Execute and Investigate CloudTrail Lake Queries

### Step 1 — Create a Query Runner

Save as `run-lake-query.sh`:

```bash
#!/usr/bin/env bash

set -euo pipefail

SQL_FILE="${1:?Usage: ./run-lake-query.sh FILE.sql LABEL}"
LABEL="${2:?Provide a query label}"

QUERY_ID=$(aws cloudtrail start-query \
  --query-statement "file://${SQL_FILE}" \
  --query QueryId \
  --output text \
  --region "$AWS_REGION")

echo "Query ID: $QUERY_ID"

printf '%s\n' "$QUERY_ID" \
  > "${LABEL}-query-id.txt"

aws cloudtrail describe-query \
  --query-id "$QUERY_ID" \
  --output json \
  --region "$AWS_REGION" \
  > "${LABEL}-query-status.json"

cat "${LABEL}-query-status.json"
```

### Step 2 — Make Script Executable

```bash
chmod +x run-lake-query.sh
```

### Step 3 — Run the Incorrect Event Name Query

```bash
./run-lake-query.sh \
  01-wrong-event-name.sql \
  lab10-wrong-name
```

### Step 4 — Retrieve Query ID

```bash
export WRONG_QUERY_ID="$(cat lab10-wrong-name-query-id.txt)"
```

### Step 5 — Check Query Status

```bash
aws cloudtrail describe-query \
  --query-id "$WRONG_QUERY_ID" \
  --query '{Status:QueryStatus,Error:ErrorMessage,Statistics:QueryStatistics}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 6 — Interpret Status

| Status | Meaning |
|---|---|
| QUEUED | Waiting to execute |
| RUNNING | Still executing |
| FINISHED | Query completed |
| FAILED | Query execution failed |
| TIMED_OUT | Query exceeded permitted execution time |
| CANCELLED | Query was canceled |

### Step 7 — Retrieve Query Results

Only after the query reaches `FINISHED`:

```bash
aws cloudtrail get-query-results \
  --query-id "$WRONG_QUERY_ID" \
  --output json \
  --region "$AWS_REGION" \
  > lab10-wrong-name-results.json
```

### Step 8 — Inspect the Results

```bash
python3 -m json.tool lab10-wrong-name-results.json
```

Expected for a successfully completed query:

```json
{
  "QueryStatus": "FINISHED",
  "QueryResultRows": []
}
```

The full response may include additional statistics.

### Step 9 — Run the Wrong Region Query

```bash
./run-lake-query.sh \
  02-wrong-region.sql \
  lab10-wrong-region
```

### Step 10 — Run the Wrong Event Source Query

```bash
./run-lake-query.sh \
  03-wrong-event-source.sql \
  lab10-wrong-source
```

For each query, inspect `DescribeQuery` before retrieving its results.

### Investigation Summary

| Query | Expected Result | Cause |
|---|---|---|
| Wrong event name | Empty | Event name does not match |
| Wrong Region | Empty | Region excludes actual event |
| Wrong source | Empty | Event source does not match |
| Query FAILED | Error details | Syntax, permission, or execution issue |

---

## 12. Root Cause Investigation

### Step 1 — Confirm the Actual Event Name

The successful test operation uses:

```text
PutParameter
```

Not:

```text
PutParameters
```

### Step 2 — Confirm the Event Source

Correct:

```text
ssm.amazonaws.com
```

Incorrect:

```text
ec2.amazonaws.com
```

### Step 3 — Confirm the AWS Region

Correct:

```text
us-east-1
```

Incorrect:

```text
eu-west-1
```

### Step 4 — Check the Event Time

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=PutParameter \
  --region "$AWS_REGION" \
  --output json
```

Examine the exact event timestamp.

### Step 5 — Inspect Event Data Store Configuration

```bash
aws cloudtrail get-event-data-store \
  --event-data-store "$EDS_ARN" \
  --query '{Status:Status,Ingestion:IngestionEnabled,MultiRegion:MultiRegionEnabled,Selectors:AdvancedEventSelectors}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 6 — Inspect Query Statistics

```bash
aws cloudtrail describe-query \
  --query-id "$WRONG_QUERY_ID" \
  --query '{Status:QueryStatus,Error:ErrorMessage,Statistics:QueryStatistics}' \
  --output json \
  --region "$AWS_REGION"
```

Relevant statistics include:

```text
EventsScanned
EventsMatched
BytesScanned
ExecutionTimeInMillis
```

### Root Cause Matrix

| Investigation | Finding |
|---|---|
| AWS API operation | Successful |
| Event history | Event recorded |
| SQL query | Completed |
| Query result | Empty |
| Event name filter | Incorrect |
| Region filter | Incorrect in second query |
| Event source filter | Incorrect in third query |
| Corrective action | Fix SQL conditions |

### Investigation Conclusion

The intentionally broken queries excluded the expected event because their WHERE clauses did not match the event's actual properties.

An empty result does not independently establish that the event data store is malfunctioning.

---

## 13. Remediation — Correct the SQL

### Step 1 — Generate the Correct Query

```bash
python3 - <<'PY'
import os

eds = os.environ["EDS_ID"]
start = os.environ["LAB_START"]
end = os.environ["LAB_END"]

query = f"""
SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion
FROM {eds}
WHERE eventTime >= timestamp '{start}'
  AND eventTime <= timestamp '{end}'
  AND eventSource = 'ssm.amazonaws.com'
  AND eventName = 'PutParameter'
  AND awsRegion = 'us-east-1'
ORDER BY eventTime DESC
LIMIT 20
"""

with open("04-correct-query.sql", "w") as file:
    file.write(query.strip() + "\n")

print(query)
PY
```

### Step 2 — Execute the Correct Query

```bash
./run-lake-query.sh \
  04-correct-query.sql \
  lab10-correct
```

### Step 3 — Retrieve Query ID

```bash
export CORRECT_QUERY_ID="$(cat lab10-correct-query-id.txt)"
```

### Step 4 — Check Query Status

```bash
aws cloudtrail describe-query \
  --query-id "$CORRECT_QUERY_ID" \
  --output json \
  --region "$AWS_REGION"
```

Wait for `FINISHED` before retrieving the final results.

If the query fails, inspect `ErrorMessage` and the SQL statement.

### Step 5 — Retrieve Results

```bash
aws cloudtrail get-query-results \
  --query-id "$CORRECT_QUERY_ID" \
  --output json \
  --region "$AWS_REGION" \
  > lab10-correct-results.json
```

### Step 6 — Inspect Query Results

```bash
python3 -m json.tool lab10-correct-results.json
```

### Expected Event Fields

| Field | Expected |
|---|---|
| eventName | PutParameter |
| eventSource | ssm.amazonaws.com |
| awsRegion | us-east-1 |
| eventTime | Within query interval |
| eventID | Actual CloudTrail event ID |

These filters identify the expected event category and source but do not by themselves prove the event belongs to the exact Lab 10 parameter.

The event ID should be correlated with the known test operation for stronger verification.

---

## 14. Verify Query Results with Python

### Step 1 — Create Results Verification Script

Save as `verify-lake-results.py`:

```python
#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 2:
    sys.exit(
        "Usage: python3 verify-lake-results.py "
        "RESULTS_JSON"
    )

with open(sys.argv[1]) as file:
    payload = json.load(file)

if payload.get("QueryStatus") != "FINISHED":
    sys.exit("Query has not finished successfully")

rows = []

for raw_row in payload.get("QueryResultRows", []):
    row = {}

    for field in raw_row:
        row.update(field)

    rows.append(row)

matches = []

for row in rows:
    if (
        row.get("eventName") == "PutParameter"
        and row.get("eventSource") == "ssm.amazonaws.com"
        and row.get("awsRegion") == "us-east-1"
    ):
        matches.append(row)

print(json.dumps(matches, indent=2))

if not matches:
    sys.exit("No matching PutParameter events found")

print("SUCCESS: Matching management events found")
```

### Step 2 — Run Verification

```bash
python3 verify-lake-results.py \
  lab10-correct-results.json
```

Expected after the event has been ingested:

```text
SUCCESS: Matching management events found
```

### Step 3 — Verify Against Event History

Inspect your actual Event history records and compare event IDs.

The final confirmation should identify the specific `PutParameter` operation generated during the lab.

### Verification Matrix

| Component | Expected |
|---|---|
| Query execution | FINISHED |
| Event name | Correct |
| Event source | Correct |
| AWS Region | Correct |
| Event timestamp | In range |
| Event ID | Matches actual activity |
| Investigation | Expected event identified |

---

## 15. Troubleshoot Missing Ingestion and Query Failures

### Scenario A — Query Completes but Returns No Results

Possible causes include:

- Incorrect WHERE conditions.
- Event not yet ingested.
- Wrong event data store.
- Wrong AWS Region.
- Time range excludes the event.
- Event category not selected.

### Scenario B — Query Remains Running

CloudTrail Lake executes queries asynchronously.

Use `DescribeQuery` to check the actual status.

### Scenario C — Query Fails

Inspect:

```text
QueryStatus
ErrorMessage
```

Possible causes include SQL syntax, unsupported statements, insufficient IAM permissions, or event data store problems.

### Scenario D — Event History Contains the Operation but Lake Does Not

Event history and Lake ingestion are separate systems.

Verify:

- Event data store creation time.
- Ingestion enabled.
- Advanced event selectors.
- Region scope.
- Query time range.
- Ingestion status.

### Step 1 — Inspect Ingestion Configuration

```bash
aws cloudtrail get-event-data-store \
  --event-data-store "$EDS_ARN" \
  --query '{Status:Status,Ingestion:IngestionEnabled,Selectors:AdvancedEventSelectors,RegionScope:MultiRegionEnabled}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 2 — Create a Bounded Diagnostic Query

```bash
python3 - <<'PY'
import os

eds = os.environ["EDS_ID"]
start = os.environ["LAB_START"]
end = os.environ["LAB_END"]

query = f"""
SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion
FROM {eds}
WHERE eventTime >= timestamp '{start}'
  AND eventTime <= timestamp '{end}'
ORDER BY eventTime DESC
LIMIT 20
"""

with open("05-diagnostic-query.sql", "w") as file:
    file.write(query.strip() + "\n")
PY
```

### Step 3 — Execute Diagnostic Query if Needed

```bash
./run-lake-query.sh \
  05-diagnostic-query.sql \
  lab10-diagnostic
```

### Step 4 — Interpret Results

| Observation | Likely Investigation |
|---|---|
| Diagnostic has rows, specific query empty | Filtering problem |
| Both queries empty | Ingestion or time-window problem |
| Query FAILED | ErrorMessage |
| Query RUNNING | Not finished |
| Query FINISHED with matching event | Recovery verified |
| High BytesScanned | Query scope too broad |

Avoid repeatedly running broad SQL queries because Lake charges for scanned data.

---

<WritingBlock id="81745" variant="document">## 16. Alternative Lab — CloudTrail SQL Investigation with SQLite

### When to Use This Path

Use this implementation when your AWS account cannot create CloudTrail Lake event data stores.

It uses real AWS management-event records from CloudTrail Event history and loads them into a local SQL database.

It demonstrates SQL troubleshooting but does not reproduce CloudTrail Lake's managed ingestion, asynchronous execution, or query billing.

### Step 1 — Generate a Real AWS API Event

If the parameter does not already exist:

```bash
aws ssm put-parameter \
  --name "$PARAMETER_NAME" \
  --type String \
  --tier Standard \
  --value "cloudtrail-lab10-local-query" \
  --region "$AWS_REGION"
```

### Step 2 — Retrieve CloudTrail Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=PutParameter \
  --region "$AWS_REGION" \
  --output json \
  > lab10-event-history.json
```

### Step 3 — Create Local Database Builder

Save as `build-local-audit-db.py`:

```python
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
```

### Step 4 — Build SQLite Database

```bash
python3 build-local-audit-db.py
```

Expected: the script reports the number of events imported.

### Step 5 — Create Local Query Runner

Save as `run-local-query.py`:

```python
#!/usr/bin/env python3

import json
import sqlite3
import sys

if len(sys.argv) != 2:
    sys.exit(
        "Usage: python3 run-local-query.py QUERY.sql"
    )

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
```

### Step 6 — Create an Incorrect SQL Query

Save as `local-wrong-query.sql`:

```sql
SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion,
    parameterName
FROM events
WHERE eventName = 'PutParameters'
  AND awsRegion = 'us-east-1'
LIMIT 20;
```

### Step 7 — Execute the Incorrect Query

```bash
python3 run-local-query.py \
  local-wrong-query.sql
```

Expected:

```text
Rows returned: 0
```

### Step 8 — Create the Correct SQL Query

Save as `local-correct-query.sql`:

```sql
SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion,
    parameterName
FROM events
WHERE eventName = 'PutParameter'
  AND eventSource = 'ssm.amazonaws.com'
  AND awsRegion = 'us-east-1'
ORDER BY eventTime DESC
LIMIT 20;
```

### Step 9 — Execute Correct Query

```bash
python3 run-local-query.py \
  local-correct-query.sql
```

Expected: matching CloudTrail management events if the expected operation is present in the imported Event history data.

### Step 10 — Verify the Exact Lab Parameter

```bash
python3 - <<'PY'
import os
import sqlite3

parameter = os.environ["PARAMETER_NAME"]

db = sqlite3.connect("lab10-audit.db")

rows = db.execute("""
SELECT
    eventID,
    eventTime,
    eventName,
    awsRegion,
    parameterName
FROM events
WHERE eventName = 'PutParameter'
  AND eventSource = 'ssm.amazonaws.com'
  AND awsRegion = 'us-east-1'
  AND parameterName = ?
ORDER BY eventTime DESC
""", (parameter,)).fetchall()

for row in rows:
    print(row)

print("Matching lab events:", len(rows))

db.close()
PY
```

This verifies the specific resource rather than any unrelated `PutParameter` operation.

### Step 11 — Troubleshoot an Incorrect Time Range

Save as `local-wrong-time.sql`:

```sql
SELECT
    eventTime,
    eventName,
    parameterName
FROM events
WHERE eventTime >= '2020-01-01T00:00:00'
  AND eventTime < '2020-01-02T00:00:00'
  AND eventName = 'PutParameter';
```

Execute:

```bash
python3 run-local-query.py \
  local-wrong-time.sql
```

Expected: the recent Lab 10 operation is excluded.

### Local SQL Verification

| Scenario | Broken | Corrected |
|---|---|---|
| Event name | PutParameters | PutParameter |
| Event source | ec2.amazonaws.com | ssm.amazonaws.com |
| Region | eu-west-1 | us-east-1 |
| Time range | Historical unrelated period | Actual event period |
| Resource | Unverified | Exact parameter name |
| Query output | Empty | Matching record |

### Important Limitation

SQLite is a useful way to practice SQL filters and audit data analysis.

However, it does not demonstrate actual CloudTrail Lake ingestion or managed query execution.

For a public portfolio, describe this path accurately as **CloudTrail Event History Analysis with SQLite** if that is the path you performed.

---

## 17. Root Cause Analysis

### Root Cause

The SQL queries did not match the properties of the expected management event.

The original query used incorrect filtering conditions.

For example:

```sql
eventName = 'PutParameters'
```

But the correct AWS API event name was:

```sql
eventName = 'PutParameter'
```

Similar problems occurred with the AWS Region and event source filters.

Because SQL WHERE clauses only return records satisfying their conditions, the expected event was excluded.

### Root Cause Diagram

```text
AWS PutParameter Operation
          |
          v
CloudTrail Event Recorded
          |
          v
Event Data Available
          |
          v
SQL Query Executed
          |
          v
Incorrect WHERE Condition
          |
          v
Expected Record Excluded
          |
          v
Query Returns Zero Rows
          |
          v
Engineer Investigates Filters
          |
          v
Correct SQL Conditions
          |
          v
Matching Event Returned
```

### Five Whys

**Why 1 — Why did the query return no matching events?**

Its filters excluded the expected record.

**Why 2 — Why did the filters exclude it?**

The event name, source, or Region did not match the actual values.

**Why 3 — Why was the problem difficult to identify?**

A query can finish successfully while returning no rows.

**Why 4 — Why should the engineer also inspect ingestion?**

An empty result can also occur when the event has not yet been ingested or was not selected for ingestion.

**Why 5 — How can similar incidents be prevented?**

Use verified event fields, bounded time windows, query-status checks, and correlation with known API activity.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-010 |
| AWS Service | CloudTrail |
| Query Engine | Lake or SQLite |
| Symptom | No matching events |
| Fault | Incorrect SQL filters |
| Root Cause | WHERE conditions exclude target event |
| Remediation | Correct filters |
| Verification | Matching management event |
| Alternative | CloudTrail Event history with SQLite |

---

## 18. Production Troubleshooting Best Practices

### Investigation Checklist

1. Verify the AWS account.
2. Confirm the AWS Region.
3. Verify the API operation succeeded.
4. Identify the expected event name.
5. Identify the expected event source.
6. Confirm the event timestamp.
7. Search regional Event history where applicable.
8. Identify the event data store.
9. Verify event data store status.
10. Check ingestion configuration.
11. Inspect event selectors.
12. Review the SQL WHERE conditions.
13. Verify timestamp boundaries.
14. Submit the query.
15. Inspect query status.
16. Review errors and query statistics.
17. Retrieve results only after completion.
18. Match the exact event ID or resource.
19. Document the root cause.
20. Remove temporary resources.

### Production Troubleshooting Workflow

```text
Expected Event Missing
         |
         v
Verify Actual API Activity
         |
         v
Check Event History
         |
         v
Identify Event Data Store
         |
         v
Inspect Ingestion Settings
         |
         v
Review SQL Conditions
         |
         v
Check Query Status
         |
         v
Check Query Statistics
         |
         v
Correct Filters
         |
         v
Execute Bounded Query
         |
         v
Verify Matching Event
         |
         v
Document Investigation
```

### Other Query Failure Scenarios

| Symptom | Possible Cause | Investigation |
|---|---|---|
| Zero rows | Incorrect WHERE conditions | Review SQL |
| Query fails | Invalid SQL | ErrorMessage |
| Query doesn't finish | Still processing | DescribeQuery |
| High query cost | Large scanned range | BytesScanned |
| Missing recent event | Ingestion delay | EDS status |
| Wrong event category | Selector mismatch | AdvancedEventSelectors |
| Wrong Region | EDS scope or SQL | Region configuration |
| Incorrect resource | Query lacks exact match | Resource/event ID |
| EDS unavailable | Service access restriction | Account eligibility |

### Production Recommendations

- Use bounded UTC time ranges.
- Avoid unnecessary full-store scans.
- Verify event names against actual AWS API operations.
- Review query execution statistics.
- Correlate audit findings with Event history and other logs.
- Validate the event data store's ingestion configuration.
- Avoid modifying production event selectors during investigations.
- Use approved infrastructure management procedures.
- Minimize data retention and query costs according to organizational requirements.
- Preserve original audit evidence when investigating incidents.

### Important Investigation Principle

**A successful SQL query returning zero rows is not proof that an AWS API event never occurred.**

The engineer must verify event collection, ingestion, query scope, and filtering before reaching that conclusion.

---

## 19. AWS Resource Cleanup

### Step 1 — Delete the Disposable SSM Parameter

```bash
case "$PARAMETER_NAME" in
  /cloudtrail-lab10/*)
    aws ssm delete-parameter \
      --name "$PARAMETER_NAME" \
      --region "$AWS_REGION"
    ;;
  *)
    echo "Unexpected parameter name — skipping"
    ;;
esac
```

### Step 2 — Identify the Lab Event Data Store

If CloudTrail Lake was used:

```bash
aws cloudtrail get-event-data-store \
  --event-data-store "$EDS_ARN" \
  --output json \
  --region "$AWS_REGION"
```

Verify the name and account ID.

Check the project tag using `list-tags` where supported by your AWS CLI and permissions.

Do not proceed unless the EDS belongs to Lab 10.

### Step 3 — Inspect Termination Protection

```bash
aws cloudtrail get-event-data-store \
  --event-data-store "$EDS_ARN" \
  --query '{Name:Name,Status:Status,Protection:TerminationProtectionEnabled,Federation:FederationStatus}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 4 — Disable Termination Protection if Necessary

```bash
aws cloudtrail update-event-data-store \
  --event-data-store "$EDS_ARN" \
  --no-termination-protection-enabled \
  --region "$AWS_REGION"
```

Run this only against the verified disposable Lab 10 event data store.

### Step 5 — Delete the Event Data Store

```bash
aws cloudtrail delete-event-data-store \
  --event-data-store "$EDS_ARN" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Deletion Status

```bash
aws cloudtrail get-event-data-store \
  --event-data-store "$EDS_ARN" \
  --query '{Name:Name,Status:Status}' \
  --output json \
  --region "$AWS_REGION"
```

The EDS may enter `PENDING_DELETION` before being removed.

### Step 7 — Local Cleanup

The following files should remain private:

```text
lab10-resources.env
lab10-create-eds.json
lab10-event-history.json
lab10-audit.db
lab10-*-results.json
lab10-*-query-id.txt
lab10-*-query-status.json
```

Remove these from your local workspace only after preserving any evidence you need.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| SSM parameter | Deleted |
| Dedicated Event Data Store | Deleted or pending deletion |
| Production Event Data Stores | Unchanged |
| Local SQLite database | Removed if no longer needed |
| Existing CloudTrail trails | Unchanged |
| EC2 instances | None created |
| S3 buckets | None created by this lab |
| IAM roles | None created |

---

## 20. Interview Questions and Answers

### Q1. What is CloudTrail Lake?

A managed service for storing and querying supported AWS audit activity using SQL.

### Q2. Can new AWS accounts use CloudTrail Lake?

CloudTrail Lake closed to new customers on May 31, 2026. Existing customers can continue using it.

### Q3. What is an event data store?

A managed store containing events selected for CloudTrail Lake ingestion.

### Q4. What is StartQuery?

An AWS API operation that submits SQL and returns a query ID.

### Q5. What is DescribeQuery?

An operation that returns query status, errors, and execution statistics.

### Q6. What is GetQueryResults?

An operation that retrieves the result rows of a query.

### Q7. What are common query statuses?

QUEUED, RUNNING, FINISHED, FAILED, TIMED_OUT, and CANCELLED.

### Q8. Why might a query return zero rows?

Incorrect SQL filters, time range, AWS Region, event data store, or missing ingestion.

### Q9. Does a FINISHED query guarantee matching results?

No. It indicates the query completed, not that records matched.

### Q10. Why is eventTime important?

It restricts the query to a relevant interval and helps reduce scanned data.

### Q11. What is BytesScanned?

A query statistic indicating how much data the query scanned.

### Q12. Why should engineers investigate ingestion?

An event may exist in CloudTrail Event history without being available in a particular event data store.

### Q13. What is the difference between CloudTrail Event history and CloudTrail Lake?

Event history provides recent regional management-event records. Lake provides managed event ingestion, storage, and SQL-based analysis.

### Q14. What is SQLite?

A lightweight relational database engine that can query structured data using SQL.

### Q15. Why use SQLite in this lab?

It provides a practical SQL troubleshooting path when CloudTrail Lake is unavailable.

### Q16. Does SQLite demonstrate all CloudTrail Lake capabilities?

No. It demonstrates SQL filtering and analysis, not managed Lake ingestion, asynchronous queries, or Lake query billing.

### Q17. Why might the wrong AWS Region return no events?

A Region filter excludes records whose `awsRegion` does not match the selected value.

### Q18. How can you distinguish a filter problem from an ingestion problem?

Verify actual event occurrence, inspect EDS ingestion and selectors, then run a bounded diagnostic query without unnecessarily narrow filters.

### Q19. How should CloudTrail Lake query costs be controlled?

Limit the scanned time range, avoid unnecessary broad queries, and monitor query statistics.

### Q20. How would you explain this lab in an interview?

I investigated missing AWS management events in SQL audit queries.

I generated controlled Systems Manager API activity and retrieved the corresponding CloudTrail Event history records.

I created SQL queries with intentionally incorrect event names, event sources, and AWS Regions.

I reviewed query conditions and corrected them to match the actual event fields.

For eligible CloudTrail Lake accounts, I also examined event data store ingestion, query execution status, and query statistics.

I used Python to parse the returned results and verify the expected event details.

Because CloudTrail Lake is no longer open to new customers, I also documented an alternative workflow using SQLite and actual CloudTrail Event history JSON.

Finally, I cleaned up the temporary resources and documented the investigation findings.

---

## 21. Repository Structure, Lessons Learned, and Skills Demonstrated

### Repository Structure

```text
aws-cloudtrail-troubleshooting-labs/
│
├── README.md
├── 01-cloudtrail-events-missing/
├── 02-trail-logging-disabled/
├── 03-cloudtrail-s3-delivery-failure/
├── 04-cloudtrail-bucket-policy-error/
├── 05-cloudtrail-kms-encryption-failure/
├── 06-data-events-not-recorded/
├── 07-multi-region-trail-misconfiguration/
├── 08-investigating-unauthorized-api-calls/
├── 09-cloudtrail-log-integrity-validation/
│
└── 10-cloudtrail-lake-query-troubleshooting/
    ├── README.md
    ├── run-lake-query.sh
    ├── verify-lake-results.py
    ├── 01-wrong-event-name.sql
    ├── 02-wrong-region.sql
    ├── 03-wrong-event-source.sql
    ├── 04-correct-query.sql
    ├── 05-diagnostic-query.sql
    ├── build-local-audit-db.py
    ├── run-local-query.py
    ├── local-wrong-query.sql
    ├── local-correct-query.sql
    ├── local-wrong-time.sql
    ├── lab10-resources.env
    ├── lab10-create-eds.json
    ├── lab10-event-history.json
    ├── lab10-audit.db
    ├── lab10-correct-results.json
    ├── lab10-wrong-name-results.json
    └── evidence/
```

### File Descriptions

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `run-lake-query.sh` | Submits CloudTrail Lake SQL queries |
| `verify-lake-results.py` | Verifies Lake query results |
| `01-wrong-event-name.sql` | Incorrect event-name filter |
| `02-wrong-region.sql` | Incorrect Region filter |
| `03-wrong-event-source.sql` | Incorrect event-source filter |
| `04-correct-query.sql` | Corrected Lake query |
| `05-diagnostic-query.sql` | Bounded diagnostic query |
| `build-local-audit-db.py` | Imports Event history into SQLite |
| `run-local-query.py` | Executes local SQL |
| `local-wrong-query.sql` | Deliberately incorrect SQLite query |
| `local-correct-query.sql` | Corrected SQLite query |
| `local-wrong-time.sql` | Incorrect time-range example |
| `lab10-resources.env` | Local AWS resource identifiers |
| `lab10-event-history.json` | Actual Event history evidence |
| `lab10-audit.db` | Local audit database |

### Recommended .gitignore

```gitignore
__pycache__/
*.pyc
.venv/
.env

**/lab10-resources.env
**/lab10-create-eds.json
**/lab10-event-history.json
**/lab10-audit.db
**/lab10-*-results.json
**/lab10-*-query-id.txt
**/lab10-*-query-status.json
**/evidence/
```

Before publishing generated SQL files, review them for account-specific resource identifiers.

### Lessons Learned

This lab demonstrates how SQL query problems can create the appearance of missing AWS audit activity.

We generated AWS management events and investigated the differences between actual event records and query results.

We reproduced problems involving incorrect event names, event sources, AWS Regions, and timestamps.

We examined query execution states and discussed how ingestion affects event availability.

We corrected the SQL conditions and established a method for verifying the exact expected event.

We also created an alternative local workflow using Python SQLite and real CloudTrail Event history records.

This allowed the same audit-query troubleshooting concepts to be practiced without depending on new CloudTrail Lake access.

**Key Lesson:** A query returning zero results does not prove that the underlying API event never happened. Engineers must validate event occurrence, query conditions, ingestion scope, and execution status.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail Event history
- CloudTrail Lake concepts
- Event data stores
- Event ingestion
- SQL troubleshooting
- AWS CLI StartQuery
- AWS CLI DescribeQuery
- AWS CLI GetQueryResults
- Query statistics
- Time-range filtering
- Region-based filtering
- Event-source filtering
- Python 3
- SQLite
- JSON processing
- Linux Bash
- AWS Systems Manager
- Audit event correlation
- Root cause analysis
- Cloud security investigation
- Query cost optimization
- Resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-010 |
| Scenario | CloudTrail Lake Query Troubleshooting |
| Region | us-east-1 |
| Test API | PutParameter |
| Broken Queries | Empty results |
| Root Cause | Incorrect SQL filters |
| Remediation | Correct SQL and verify ingestion |
| Query Results | Expected event identified |
| Lake Path | Existing eligible customers |
| Alternative Path | CloudTrail Event history + SQLite |
| Cleanup | Test resources removed |
| Incident Status | Resolved after actual verification |

**Key Takeaway:** Cloud Engineers and Cloud Security Engineers must understand both how AWS audit events are collected and how SQL query conditions affect the results of an investigation.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Lake Availability Change](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html)
- [Creating an Event Data Store with AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/lake-cli-create-eds.html)
- [CloudTrail Lake SQL Queries](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-queries.html)
- [Running CloudTrail Lake Queries with AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/lake-queries-cli.html)
- [AWS CLI — CreateEventDataStore](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/create-event-data-store.html)
- [AWS CLI — StartQuery](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/start-query.html)
- [AWS CLI — DescribeQuery](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/describe-query.html)
- [AWS CLI — GetQueryResults](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-query-results.html)
- [CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/)