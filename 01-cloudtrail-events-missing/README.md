# Lab 01 — CloudTrail Events Missing

## Overview

This lab demonstrates how to troubleshoot an AWS CloudTrail management event that appears to be missing from Event history.

AWS CloudTrail records supported AWS API activity and helps Cloud Engineers and Cloud Security Engineers investigate resource changes, security incidents, and account activity.

In this lab, we simulate a production incident where a Cloud Security Engineer needs to investigate an AWS API operation, but the expected event cannot be found in CloudTrail Event history.

We create a temporary AWS Systems Manager Parameter Store parameter in the `us-east-1` Region. This operation generates a `PutParameter` management API event.

However, we intentionally search CloudTrail Event history in `us-west-2`.

Because CloudTrail Event history searches are Region-specific, the expected regional API event does not appear in the incorrect Region.

The engineer initially suspects that CloudTrail has failed to record the event.

We investigate the problem by verifying the AWS account, resource location, API operation, Event history search configuration, event timestamps, and CloudTrail event details.

After identifying the Region mismatch, we search CloudTrail Event history in `us-east-1`.

We then use a Python investigation script to locate the exact `PutParameter` event associated with our temporary resource.

The script extracts the event ID, event time, event source, AWS Region, resource name, identity type, and error information.

Finally, we delete the temporary parameter and document the incident findings.

**Troubleshooting Workflow:**

AWS CLI Authentication → Parameter Creation → PutParameter API Call → Wrong-Region CloudTrail Search → Event Not Found → AWS CLI Investigation → Region Mismatch Identified → Correct-Region Search → Event Verification → Root Cause Analysis → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-001 |
| Difficulty | Beginner to Intermediate |
| AWS Region | `us-east-1` |
| Incorrect Search Region | `us-west-2` |
| Primary AWS Service | AWS CloudTrail |
| Supporting Service | AWS Systems Manager Parameter Store |
| Local Environment | WSL Ubuntu |
| Interface | AWS CLI v2 |
| Scripting Languages | Bash, Python 3 |
| CloudTrail Capability | Event history |
| Event Category | Management event |
| Event Name | `PutParameter` |
| Event Source | `ssm.amazonaws.com` |
| Parameter Type | Standard String |
| Parameter Path | `/cloudtrail-lab01/audit-test-*` |
| Fault Injection | Search Event history in the wrong Region |
| Expected Symptom | Target API event not found |
| Root Cause | Incorrect investigation Region |
| Remediation | Search the Region where the API call occurred |
| Verification | Match the exact parameter in CloudTrail event JSON |
| Cleanup | Delete temporary SSM parameter |

### Lab Objectives

- Understand AWS CloudTrail Event history.
- Generate a real AWS management API event.
- Understand regional event recording.
- Reproduce an apparently missing CloudTrail event.
- Verify AWS account and Region configuration.
- Search Event history using AWS CLI.
- Investigate CloudTrail event timestamps.
- Understand management events and data events.
- Extract structured CloudTrail event information.
- Identify the API caller.
- Perform root cause analysis.
- Verify the corrected investigation process.
- Save relevant incident evidence.
- Clean up temporary AWS resources.

---

## 2. Production Incident Scenario

### Incident Description

A company operates multiple AWS workloads across different Regions.

The Cloud Security team regularly investigates AWS API activity to understand resource changes and identify suspicious operations.

During an investigation, a Cloud Security Engineer needs to determine who created an application configuration parameter.

The parameter was created through AWS Systems Manager Parameter Store in `us-east-1`.

The corresponding API operation was `PutParameter`.

However, the engineer searches CloudTrail Event history in `us-west-2`.

The expected event is not found.

The engineer initially believes that CloudTrail is failing to record AWS API operations.

Before changing any CloudTrail configuration, the engineer checks the AWS account, operation Region, resource location, event name, and search time range.

The investigation reveals that the resource exists in `us-east-1`, while the original CloudTrail search targeted `us-west-2`.

The engineer repeats the search in the correct Region.

After CloudTrail makes the management event available, the engineer locates the expected `PutParameter` event.

The engineer then examines the event information to determine which AWS identity performed the operation and which resource was affected.

The incident is resolved without modifying existing CloudTrail trails or audit logging infrastructure.

### Incident Symptoms

- The API operation completed successfully.
- The temporary parameter exists in `us-east-1`.
- CloudTrail search returns no matching test event in `us-west-2`.
- The investigator initially suspects missing audit records.
- The search Region differs from the resource Region.
- CloudTrail Event history remains operational.
- The expected event becomes discoverable in the correct Region.

### Business Impact

An incorrect investigation scope can result in:

- Delayed security investigations.
- Incorrect assumptions about logging failures.
- Unnecessary troubleshooting of CloudTrail infrastructure.
- Wasted incident response time.
- Incomplete resource change investigations.
- Incorrect security incident conclusions.
- Reduced confidence in cloud audit visibility.

### Objective

Identify why a successful AWS API operation appears missing from CloudTrail Event history, correct the investigation scope, and verify the exact API event.

---

## 3. AWS Architecture

### Standard Event History Architecture

```text
                    Cloud Engineer
                          |
                          v
                       WSL Ubuntu
                          |
                          v
                       AWS CLI v2
                          |
                          v
                  PutParameter API Call
                          |
                          v
               AWS Systems Manager
                     Parameter Store
                          |
                          v
                 AWS Region: us-east-1
                          |
                          v
                 CloudTrail Event History
                          |
                          v
                  PutParameter Event
                          |
                          v
                Security Investigation
```

### Architecture Before Remediation

```text
                   AWS CLI
                      |
                      v
               PutParameter API
                      |
                      v
                  us-east-1
                      |
                      v
            Parameter Created
                      |
                      v
             CloudTrail Event
                      |
                      |
        Engineer Searches us-west-2
                      |
                      v
               Event Not Found
                      |
                      v
             Suspected Logging Issue
```

### Architecture After Remediation

```text
                   AWS CLI
                      |
                      v
               PutParameter API
                      |
                      v
                  us-east-1
                      |
                      v
             CloudTrail Event History
                      |
                      v
            Correct Regional Search
                      |
                      v
              PutParameter Found
                      |
                      v
              CloudTrailEvent JSON
                      |
                      v
              Event Details Verified
                      |
                      v
               Incident Resolved
```

### Architecture Components

| Component | Purpose |
|---|---|
| AWS CLI v2 | Generates and investigates API activity |
| WSL Ubuntu | Local Linux troubleshooting environment |
| Systems Manager Parameter Store | Creates a test AWS resource |
| CloudTrail Event history | Provides recent management API events |
| us-east-1 | Region where the operation occurs |
| us-west-2 | Intentionally incorrect investigation Region |
| Python Investigation Script | Identifies the exact CloudTrail event |
| JSON Evidence Files | Preserve relevant investigation results |

### Important Design Detail

This lab does not create a CloudTrail trail.

CloudTrail Event history is sufficient to investigate the supported management API operation used in this exercise.

This allows us to demonstrate regional event investigation without creating an S3 log destination or changing existing audit infrastructure.

---

## 4. Understanding AWS CloudTrail Event History

### What Is AWS CloudTrail?

AWS CloudTrail records supported activity in AWS accounts, including API operations performed through the AWS Management Console, AWS CLI, and AWS SDKs.

CloudTrail supports:

- Security investigations.
- Operational troubleshooting.
- Account activity auditing.
- Resource change investigations.
- Compliance and governance workflows.

### What Is CloudTrail Event History?

Event history provides access to recent CloudTrail management events.

It is available without creating a trail.

Event history supports a rolling 90-day management event history.

### Is Event History Region-Specific?

Yes.

CloudTrail Event history searches are Region-specific.

To investigate a regional management API operation, engineers normally search in the AWS Region where the operation occurred.

### What Is a Management Event?

Management events record supported control-plane API activity.

Examples include:

- Creating AWS resources.
- Updating configurations.
- Modifying access settings.
- Deleting resources.
- Managing AWS service settings.

The `PutParameter` operation used in this lab is a management event.

### What Is a Data Event?

Data events represent supported resource-level operations.

Examples include:

- Amazon S3 object operations.
- AWS Lambda function invocations.

CloudTrail Event history does not provide general data event searches.

Appropriate trail or event data store configuration is needed to collect supported data events.

### What Is PutParameter?

`PutParameter` is an AWS Systems Manager API operation used to create or update a Parameter Store parameter.

In this lab, it creates a harmless Standard String parameter.

### What Is eventName?

The `eventName` field identifies the API operation.

For this lab:

`PutParameter`

### What Is eventSource?

The `eventSource` field identifies the AWS service associated with the API operation.

For this lab:

`ssm.amazonaws.com`

### What Is awsRegion?

The `awsRegion` field identifies the AWS Region associated with the event.

For this lab:

`us-east-1`

### What Is eventID?

The `eventID` field uniquely identifies a CloudTrail event.

It is useful for correlating audit records during investigations.

### What Is userIdentity?

The `userIdentity` object contains information about the identity involved in the API request.

Depending on the type of credentials used, it can contain an IAM user, assumed role, or other AWS identity information.

### What Is sourceIPAddress?

The `sourceIPAddress` field identifies the recorded request source.

It should be interpreted in the context of the AWS service and request path.

### What Is CloudTrailEvent?

The AWS CLI `LookupEvents` response includes a `CloudTrailEvent` field containing the event's detailed JSON representation as an encoded JSON string.

We use Python to parse this information and locate the exact test operation.

---

## 5. Prerequisites and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL Ubuntu.
- Bash.
- Python 3.
- Valid AWS CLI credentials.
- CloudTrail lookup permissions.
- Systems Manager Parameter Store permissions.
- Git and GitHub.

### Required API Permissions

```text
sts:GetCallerIdentity
ssm:PutParameter
ssm:GetParameter
ssm:DescribeParameters
ssm:ListTagsForResource
ssm:DeleteParameter
cloudtrail:LookupEvents
```

### Security Guidelines

- Use a temporary parameter.
- Do not store credentials in Parameter Store test values.
- Do not modify production parameters.
- Do not disable CloudTrail trails.
- Do not delete existing audit infrastructure.
- Avoid publishing raw identity information unnecessarily.
- Review CloudTrail event JSON before committing it.
- Verify resource ownership before deletion.
- Use the correct AWS account and Region.

### Cost Considerations

This lab uses:

- CloudTrail Event history.
- A Standard Parameter Store parameter.
- A small number of AWS API requests.

It does not require:

- A new CloudTrail trail.
- An S3 log bucket.
- A KMS key.
- An EC2 instance.
- A VPC.
- CloudTrail Lake.

Standard Parameter Store parameters and recent CloudTrail management Event history are generally available without additional charges for this basic use, subject to account usage and AWS pricing.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Navigate to Repository

```bash
cd ~/aws-cloudtrail-troubleshooting-labs
```

If the repository is stored elsewhere, use the actual local path.

### Step 2 — Create Lab Directory

```bash
mkdir -p 01-cloudtrail-events-missing

cd 01-cloudtrail-events-missing
```

### Step 3 — Verify AWS CLI

```bash
aws --version
```

### Step 4 — Verify AWS Identity

```bash
aws sts get-caller-identity
```

Review the account and identity information.

### Step 5 — Configure Variables

```bash
export AWS_REGION="us-east-1"
export WRONG_REGION="us-west-2"
export AWS_PAGER=""

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab01"

export EVENT_NAME="PutParameter"
export EVENT_SOURCE="ssm.amazonaws.com"

export PARAMETER_NAME="/cloudtrail-lab01/audit-test-$(date -u +%Y%m%d%H%M%S)"
export PARAMETER_VALUE="cloudtrail-lab01-test"
```

### Step 6 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$WRONG_REGION"
echo "$EVENT_NAME"
echo "$PARAMETER_NAME"
```

### Step 7 — Save Parameter Name

```bash
printf '%s\n' "$PARAMETER_NAME" > lab01-parameter-name.txt
```

The saved parameter name is used during cleanup.

### Step 8 — Inspect Default Region

```bash
aws configure get region
```

The default configured Region may differ from the Region used for an individual AWS CLI operation.

In production troubleshooting, specifying `--region` explicitly can prevent incorrect searches.

---

## 7. Generate a Real AWS Management Event

### Step 1 — Record Investigation Start Time

```bash
export LAB_START_TIME=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

echo "$LAB_START_TIME"
```

This timestamp helps define the beginning of the CloudTrail investigation window.

### Step 2 — Create Temporary SSM Parameter

```bash
aws ssm put-parameter \
  --name "$PARAMETER_NAME" \
  --description "Temporary CloudTrail troubleshooting Lab 01 parameter" \
  --type String \
  --tier Standard \
  --value "$PARAMETER_VALUE" \
  --tags "Key=Project,Value=$PROJECT_TAG" \
  --region "$AWS_REGION"
```

Expected response:

```json
{
  "Version": 1,
  "Tier": "Standard"
}
```

### Step 3 — Verify Parameter Creation

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Type:Type,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

Expected findings:

- The parameter exists.
- The parameter type is String.
- The initial version is 1.
- The resource exists in us-east-1.

### Step 4 — Save Parameter Evidence

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Type:Type,Version:Version}' \
  --output json \
  --region "$AWS_REGION" \
  > lab01-parameter-created.json
```

### Expected Findings

| Component | Expected Result |
|---|---|
| API Operation | PutParameter |
| AWS Service | Systems Manager |
| AWS Region | us-east-1 |
| Parameter Type | Standard String |
| API Request | Successful |
| Parameter | Created |
| CloudTrail Management Event | Expected after availability delay |

---

## 8. Fault Injection — Search Wrong AWS Region

### Step 1 — Search Event History in us-west-2

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT_NAME" \
  --start-time "$LAB_START_TIME" \
  --max-results 50 \
  --query 'Events[].{Time:EventTime,Event:EventName,User:Username}' \
  --output table \
  --region "$WRONG_REGION"
```

### Expected Finding

The specific test event from us-east-1 is not expected to appear in the us-west-2 regional Event history.

Other unrelated `PutParameter` events may appear if the account contains activity in that Region.

Therefore, the investigation must focus on the exact test operation rather than assuming every returned event belongs to this lab.

### Step 2 — Save Wrong-Region Evidence

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT_NAME" \
  --start-time "$LAB_START_TIME" \
  --max-results 50 \
  --output json \
  --region "$WRONG_REGION" \
  > lab01-wrong-region-events.json
```

### Step 3 — Compare Regions

```bash
echo "Resource Region: $AWS_REGION"
echo "Search Region: $WRONG_REGION"
```

Expected:

```text
Resource Region: us-east-1
Search Region: us-west-2
```

### Fault Injection Summary

| Investigation | Expected Finding |
|---|---|
| API Operation | Successful |
| Parameter Created | Yes |
| Resource Region | us-east-1 |
| Initial Event Search | us-west-2 |
| Target Event Found | No |
| Initial Symptom | Apparently missing audit event |
| Suspected Problem | CloudTrail logging failure |
| Actual Problem | Incorrect investigation Region |

---

## 9. Investigate Resource Location

### Step 1 — Verify Parameter in us-east-1

```bash
aws ssm describe-parameters \
  --parameter-filters "Key=Name,Option=Equals,Values=$PARAMETER_NAME" \
  --query 'Parameters[].{Name:Name,Type:Type,Tier:Tier}' \
  --output table \
  --region "$AWS_REGION"
```

Expected: the temporary parameter appears.

### Step 2 — Search for Parameter in us-west-2

```bash
aws ssm describe-parameters \
  --parameter-filters "Key=Name,Option=Equals,Values=$PARAMETER_NAME" \
  --query 'Parameters[].Name' \
  --output json \
  --region "$WRONG_REGION"
```

Expected for a unique lab parameter name:

```json
[]
```

### Step 3 — Confirm Region Mismatch

```bash
echo "Correct AWS Region: $AWS_REGION"
echo "Incorrect Search Region: $WRONG_REGION"
```

### Step 4 — Verify AWS Account

```bash
aws sts get-caller-identity \
  --query '{Account:Account,Arn:Arn}' \
  --output json
```

In a production investigation, verify that the account containing the resource is also the account whose CloudTrail history is being searched.

### Investigation Matrix

| Investigation | Finding |
|---|---|
| Parameter in us-east-1 | Exists |
| Parameter in us-west-2 | Not found |
| Resource Region | Confirmed |
| Initial CloudTrail Region | Incorrect |
| AWS Account | Must match resource account |
| Main Finding | Regional search mismatch |

---

## 10. Investigate CloudTrail Event History

### Step 1 — Understand Event History Scope

CloudTrail Event history provides recent supported management events.

Important characteristics:

- Regional event searches.
- Rolling 90-day Event history.
- Management events rather than general data events.
- No dedicated trail required.
- Event delivery and availability may be delayed.

### Step 2 — Verify Event Name

The expected event is:

`PutParameter`

### Step 3 — Verify Event Source

The expected event source is:

`ssm.amazonaws.com`

### Step 4 — Verify Investigation Time

```bash
echo "$LAB_START_TIME"
date -u
```

The investigation window must include the time the API operation occurred.

### Step 5 — Consider Event Availability Delay

New CloudTrail events are not always available immediately after an API call.

CloudTrail generally delivers events within several minutes, but this is not a strict guarantee.

An initially empty result should be investigated using the correct Region and time window before concluding that event logging failed.

### Step 6 — Distinguish Event History from Trails

CloudTrail Event history is separate from CloudTrail trail delivery.

A trail may be configured to send events to an S3 bucket.

Event history remains a separate capability for recent management events.

A stopped trail does not automatically remove the regional management Event history.

---

## 11. Remediation — Search the Correct Region

### Step 1 — Search us-east-1

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT_NAME" \
  --start-time "$LAB_START_TIME" \
  --max-items 200 \
  --query 'Events[].{Time:EventTime,Event:EventName,User:Username,EventID:EventId}' \
  --output table \
  --region "$AWS_REGION"
```

Expected: the `PutParameter` operation becomes discoverable once the event is available.

### Step 2 — Save Correct-Region Events

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT_NAME" \
  --start-time "$LAB_START_TIME" \
  --max-items 200 \
  --output json \
  --region "$AWS_REGION" \
  > lab01-correct-region-events.json
```

### Step 3 — Understand the Result

CloudTrail may return several events with the same event name.

Each event can represent a different resource or request.

Therefore, the engineer must inspect the embedded event JSON to identify the exact temporary parameter.

### Step 4 — Verify Target Event

The expected event should contain:

```text
eventName = PutParameter
eventSource = ssm.amazonaws.com
awsRegion = us-east-1
requestParameters.name = <test parameter name>
```

A matching event ID and timestamp help confirm that the intended operation was recorded.

### Remediation Summary

| Component | Before | After |
|---|---|---|
| Resource Region | us-east-1 | us-east-1 |
| Search Region | us-west-2 | us-east-1 |
| API Operation | Successful | Successful |
| Target Event | Not found | Found after availability |
| CloudTrail Configuration | Unchanged | Unchanged |
| Root Cause | Region mismatch | Resolved |

---

## 12. Python CloudTrail Event Investigation

### Purpose

The `LookupEvents` API returns event details that include an embedded `CloudTrailEvent` JSON string.

The investigation script parses these events and checks the exact parameter name.

This avoids confusing unrelated `PutParameter` events with the lab's operation.

### Step 1 — Create Investigation Script

Save as `investigate-event.py`:

```python
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
        "errorCode": event.get("errorCode")
    }

    matches.append(result)

print(json.dumps(matches, indent=2))

with open("lab01-verified-event.json", "w") as file:
    json.dump(matches, file, indent=2)

if not matches:
    print("Target event not found.")
    sys.exit(1)

print("SUCCESS: Target CloudTrail event found.")
```

### Step 2 — Execute Investigation

```bash
python3 investigate-event.py \
  lab01-correct-region-events.json \
  "$PARAMETER_NAME"
```

### Expected Output

```json
[
  {
    "eventID": "EXAMPLE-EVENT-ID",
    "eventTime": "EXAMPLE-EVENT-TIME",
    "eventName": "PutParameter",
    "eventSource": "ssm.amazonaws.com",
    "awsRegion": "us-east-1",
    "parameterName": "/cloudtrail-lab01/audit-test-EXAMPLE",
    "identityType": "AssumedRole",
    "errorCode": null
  }
]
```

The values above are illustrative.

The actual event ID, time, resource name, and identity type will depend on the AWS account and execution environment.

### Step 3 — Verify Script Result

Expected success message:

```text
SUCCESS: Target CloudTrail event found.
```

### Step 4 — Inspect Verified Evidence

```bash
python3 -m json.tool lab01-verified-event.json
```

### Verification Fields

| Field | Purpose |
|---|---|
| eventID | Identifies the recorded event |
| eventTime | Shows when the API call occurred |
| eventName | Identifies the API operation |
| eventSource | Identifies the AWS service |
| awsRegion | Identifies the event Region |
| parameterName | Identifies the target resource |
| identityType | Identifies the AWS principal category |
| errorCode | Indicates recorded API failure when present |

### Troubleshooting an Empty Match

If the script returns:

`Target event not found.`

Verify:

- The correct AWS account was used.
- The event search targeted us-east-1.
- The query time window includes the API call.
- CloudTrail has had sufficient time to make the event available.
- The event name is correct.
- The exact parameter name matches.
- The lookup results include the intended event.

In an account with high API activity, use an appropriate bounded time window and pagination to ensure the required event isn't excluded from the retrieved results.

---

## 13. Investigate the API Caller

### Purpose

CloudTrail events contain identity and request information useful for security investigations.

Examples include:

- AWS identity type.
- AWS principal ARN.
- Source IP address.
- User agent.
- Event time.
- Event name.
- Event source.
- AWS Region.

### Step 1 — Inspect the Exact Event

```bash
python3 - <<'PY'
import json

with open("lab01-correct-region-events.json") as file:
    data = json.load(file)

with open("lab01-verified-event.json") as file:
    verified = json.load(file)

if not verified:
    raise SystemExit("No verified event found")

target_id = verified[0]["eventID"]

for item in data["Events"]:
    if item["EventId"] != target_id:
        continue

    event = json.loads(item["CloudTrailEvent"])
    identity = event.get("userIdentity") or {}

    print("Identity Type:", identity.get("type"))
    print("Identity ARN:", identity.get("arn"))
    print("Source IP:", event.get("sourceIPAddress"))
    print("User Agent:", event.get("userAgent"))
    print("Event Time:", event.get("eventTime"))
PY
```

### Step 2 — Analyze Identity Information

CloudTrail identity data may indicate:

- IAM user credentials.
- An assumed IAM role.
- AWS service activity.
- Other supported identity types.

The actual result depends on the credentials used during the exercise.

### Step 3 — Examine the Source

The source IP and user agent can help establish how an API request was made.

For example, the user agent may indicate AWS CLI activity.

### Step 4 — Correlate Event and Resource

The event's resource name should match the parameter created in this lab.

The Region should match `us-east-1`.

The API event name should be `PutParameter`.

### Security Consideration

Raw CloudTrail records may contain identity ARNs, account IDs, IP addresses, and request metadata.

Review and redact sensitive fields before publishing evidence to GitHub.

---

## 14. Root Cause Analysis

### Root Cause

The AWS API event was not missing because of a CloudTrail logging failure.

The engineer searched the incorrect AWS Region.

The `PutParameter` API operation occurred in `us-east-1`.

However, the initial CloudTrail Event history lookup was performed in `us-west-2`.

Since the event was associated with the primary Region, it did not appear in the incorrect regional search.

After correcting the search Region and allowing for normal event availability, the engineer located the expected management event.

### Root Cause Flow

```text
AWS CLI PutParameter
          |
          v
API Operation in us-east-1
          |
          v
SSM Parameter Created
          |
          v
CloudTrail Management Event
          |
          v
Engineer Searches us-west-2
          |
          v
Target Event Not Found
          |
          v
Suspected CloudTrail Failure
          |
          v
AWS Region Investigation
          |
          v
Region Mismatch Identified
          |
          v
Search Correct Region
          |
          v
Target Event Found
          |
          v
Incident Resolved
```

### Five Whys

1. **Why was the event missing?** The expected API event was not found in the original Event history search.
2. **Why wasn't the event found?** The search targeted a different AWS Region.
3. **Why was the incorrect Region used?** The investigator did not verify the Region of the original API operation.
4. **Why was this mistaken for a logging failure?** The investigator assumed the search covered the expected event regardless of Region.
5. **How was the issue resolved?** The API operation's Region was confirmed and the lookup was repeated there.

### Root Cause Summary

| Component | Finding |
|---|---|
| Incident | INC-CT-001 |
| AWS Service | CloudTrail |
| Supporting Service | Systems Manager |
| API Operation | PutParameter |
| Resource Region | us-east-1 |
| Incorrect Search Region | us-west-2 |
| Initial Symptom | Target event missing |
| CloudTrail Failure | Not demonstrated |
| Root Cause | Regional search mismatch |
| Remediation | Correct Event history Region |
| Verification | Exact event found and inspected |

**Key Lesson:** Before assuming that CloudTrail failed to record an API event, verify the AWS account, Region, event category, event name, and investigation time range.

---

## 15. Remediation Verification and Before/After Comparison

### Step 1 — Verify the Correct Region

```bash
echo "$AWS_REGION"
```

Expected:

```text
us-east-1
```

### Step 2 — Verify the Resource

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Type:Type}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 3 — Verify the CloudTrail Event

```bash
python3 investigate-event.py \
  lab01-correct-region-events.json \
  "$PARAMETER_NAME"
```

Expected:

```text
SUCCESS: Target CloudTrail event found.
```

### Step 4 — Verify Recorded Event Fields

```bash
python3 -m json.tool lab01-verified-event.json
```

Confirm:

- `eventName` is PutParameter.
- `eventSource` is ssm.amazonaws.com.
- `awsRegion` is us-east-1.
- `parameterName` matches the temporary resource.
- An event ID is present.
- The recorded event time corresponds to the operation.
- The API operation was successful.

### Before and After

| Investigation | Before Remediation | After Remediation |
|---|---|---|
| Search Region | us-west-2 | us-east-1 |
| Resource Region | us-east-1 | us-east-1 |
| Event Name | PutParameter | PutParameter |
| Target Event | Not found | Found |
| Event ID | Unavailable | Retrieved |
| Event Time | Unavailable | Retrieved |
| API Identity | Not verified | Inspectable |
| Root Cause | Region mismatch | Resolved |
| CloudTrail Configuration Changes | None | None |

### Final Verification Criteria

The incident is considered resolved when:

1. The test API operation is confirmed successful.
2. The temporary parameter exists in us-east-1.
3. The wrong-Region search does not identify the target event.
4. The correct-Region search identifies the event.
5. The event's resource name matches the parameter.
6. The event name and source match the expected API operation.
7. The event's Region is correct.
8. The event ID and timestamp are recorded.
9. The investigation findings are documented.

---

## 16. Additional CloudTrail Investigation Scenarios

The incorrect AWS Region is the root cause in this lab, but production investigations can encounter several other causes of apparently missing events.

### Scenario A — Incorrect Time Range

An event may be excluded because the search time window does not cover when the API operation occurred.

For example:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --start-time "$LAB_START_TIME" \
  --region us-east-1
```

### Scenario B — Wrong AWS Account

Organizations commonly operate multiple AWS accounts.

An engineer may search the correct Region but use credentials for the wrong account.

Verify:

```bash
aws sts get-caller-identity
```

### Scenario C — Event Availability Delay

CloudTrail events are not guaranteed to appear immediately after an API operation.

Engineers should allow for normal event availability delays before concluding that recording has failed.

### Scenario D — Data Events Not Included in Event History

CloudTrail Event history is intended for supported management events.

An engineer investigating S3 object-level operations may require appropriately configured CloudTrail data event collection instead.

### Scenario E — Incorrect Event Name

An operation may be searched using an incorrect API event name.

Verify the actual AWS API operation before applying a CloudTrail lookup attribute.

### Scenario F — Event Outside the 90-Day Window

CloudTrail Event history provides a rolling 90-day history.

For longer-term investigations, organizations may use CloudTrail trails with retained S3 logs or CloudTrail Lake event data stores.

### Troubleshooting Comparison

| Potential Cause | Investigation |
|---|---|
| Wrong AWS Region | Verify API operation Region |
| Wrong AWS account | Check STS caller identity |
| Incorrect time range | Inspect event timestamps |
| Event availability delay | Repeat lookup after propagation |
| Wrong API event name | Verify eventName |
| Data event expected | Check event category and selectors |
| Event older than 90 days | Investigate retained trail logs or Lake |
| Incomplete lookup results | Check pagination and search scope |

---

## 17. Production Troubleshooting Best Practices

### CloudTrail Missing Event Checklist

1. Verify AWS CLI authentication.
2. Confirm the AWS account ID.
3. Identify the affected resource.
4. Verify the resource Region.
5. Confirm the API operation completed.
6. Identify the expected event name.
7. Verify the event source.
8. Determine the correct investigation time range.
9. Confirm that the operation is a supported management event.
10. Search Event history in the correct Region.
11. Allow for normal event availability delay.
12. Check lookup pagination.
13. Inspect the embedded CloudTrailEvent JSON.
14. Verify the affected resource name.
15. Verify the caller identity.
16. Review the event timestamp.
17. Check the source IP and user agent when relevant.
18. Identify the root cause.
19. Save investigation evidence.
20. Document findings and perform cleanup.

### Recommended Production Investigation Workflow

```text
AWS API Activity Reported
          |
          v
Verify AWS Account
          |
          v
Verify Resource and Region
          |
          v
Confirm API Event Name
          |
          v
Determine Event Category
          |
          v
Check Investigation Time Window
          |
          v
Search CloudTrail Event History
          |
          v
Inspect CloudTrailEvent JSON
          |
          v
Verify Resource and Caller
          |
          v
Identify Root Cause
          |
          v
Document Evidence
```

### Security Recommendations

- Protect existing CloudTrail audit infrastructure.
- Avoid disabling trails during unrelated investigations.
- Use least-privilege permissions.
- Preserve audit evidence when investigating real incidents.
- Review sensitive event information before sharing.
- Maintain consistent incident timestamps in UTC.
- Document AWS accounts and Regions involved.
- Use multi-Region trails where organizational requirements demand broader coverage.
- Validate event collection separately from event search configuration.
- Avoid treating an empty lookup result as proof that no API operation occurred.

### Operational Recommendations

- Use explicit AWS Region parameters.
- Record the AWS account used for each investigation.
- Maintain reusable CloudTrail investigation scripts.
- Verify the exact affected resource rather than relying only on event names.
- Document event IDs for correlation.
- Keep investigation time ranges narrow but complete.
- Understand Event history retention limitations.
- Escalate suspected logging failures only after validating the investigation scope.

---

## 18. AWS Resource Cleanup

**Warning:** Delete only the disposable Systems Manager parameter created for this lab.

### Step 1 — Verify the Parameter

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Type:Type}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 2 — Verify Resource Ownership

```bash
aws ssm list-tags-for-resource \
  --resource-type Parameter \
  --resource-id "$PARAMETER_NAME" \
  --region "$AWS_REGION"
```

Confirm the project tag:

`Project=CloudTrail-Troubleshooting-Lab01`

### Step 3 — Delete Temporary Parameter

```bash
aws ssm delete-parameter \
  --name "$PARAMETER_NAME" \
  --region "$AWS_REGION"
```

### Step 4 — Verify Deletion

```bash
aws ssm describe-parameters \
  --parameter-filters "Key=Name,Option=Equals,Values=$PARAMETER_NAME" \
  --query 'Parameters' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```json
[]
```

### Step 5 — Understand CloudTrail Event Retention

Deleting the temporary parameter does not delete its recorded management event from CloudTrail Event history.

The `PutParameter` and `DeleteParameter` operations may remain visible during the normal Event history retention window.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| Temporary SSM Parameter | Deleted |
| CloudTrail Event History | Retained normally |
| CloudTrail Trail | None created |
| S3 Bucket | None created |
| KMS Key | None created |
| EC2 Instance | None created |
| IAM Role | None created |
| VPC Resources | None created |

---

## 19. Interview Questions and Answers

### Q1. What is AWS CloudTrail?

AWS CloudTrail records supported AWS account activity and API operations to support auditing, troubleshooting, and security investigations.

### Q2. What is CloudTrail Event history?

Event history provides access to recent supported management API events without requiring a dedicated trail.

### Q3. How many days of events are available in Event history?

CloudTrail Event history provides a rolling 90-day history of supported management events.

### Q4. Why might CloudTrail events appear missing?

Possible reasons include the wrong AWS Region, wrong account, incorrect time range, event availability delay, unsupported event category, or incorrect search criteria.

### Q5. What caused this lab's incident?

The engineer searched CloudTrail Event history in `us-west-2`, while the API operation occurred in `us-east-1`.

### Q6. How do you search CloudTrail using AWS CLI?

```bash
aws cloudtrail lookup-events \
  --region us-east-1
```

### Q7. How do you filter events by API name?

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --region us-east-1
```

### Q8. What is the difference between Event history and a trail?

Event history provides recent regional management events.

A trail delivers selected CloudTrail events to an S3 bucket for ongoing audit logging.

### Q9. Does stopping a trail disable CloudTrail Event history?

No. Event history is separate from trail logging.

### Q10. What is the CloudTrailEvent field?

It contains the detailed CloudTrail event JSON, represented as a string in the LookupEvents response.

### Q11. What is userIdentity?

The event field containing information about the AWS identity associated with the API operation.

### Q12. What does eventSource indicate?

It identifies the AWS service associated with the event.

### Q13. What does awsRegion indicate?

It identifies the AWS Region recorded for the event.

### Q14. What is eventID?

A unique identifier used to distinguish and correlate CloudTrail events.

### Q15. How do you investigate an API caller?

Inspect the event's userIdentity, eventTime, eventName, sourceIPAddress, userAgent, and related request information.

### Q16. Can CloudTrail Event history show S3 object data events?

No. Supported S3 object-level data events require appropriate CloudTrail collection configuration and are not provided through the standard Event history lookup.

### Q17. What would you check before reporting a CloudTrail logging failure?

I would verify the AWS account, Region, event category, API name, time range, event availability, and lookup results.

### Q18. Why is verifying the exact resource important?

Many API operations share the same event name. Matching the resource ensures that the engineer is investigating the intended operation.

### Q19. How can CloudTrail support security incident response?

It helps engineers investigate supported API activity, identify AWS principals, examine configuration changes, and correlate account actions with incident timelines.

### Q20. How would you explain this lab in an interview?

I simulated a missing CloudTrail management event by creating a temporary Systems Manager parameter in `us-east-1`.

I initially searched CloudTrail Event history in `us-west-2`, where the expected event was not found.

I verified that the AWS API operation completed successfully and confirmed the Region where the parameter existed.

After identifying the Region mismatch, I searched CloudTrail in `us-east-1`.

I used Python to parse the returned CloudTrail events and locate the exact `PutParameter` operation associated with my test resource.

I verified the event ID, timestamp, event source, Region, resource name, and identity information.

Finally, I deleted the temporary parameter and documented the root cause.

The main lesson was that engineers should verify the AWS account, Region, time range, and event category before assuming CloudTrail has failed to record an event.

---

## 20. Repository Structure

```text
aws-cloudtrail-troubleshooting-labs/
│
├── README.md
│
├── 01-cloudtrail-events-missing/
│   ├── README.md
│   ├── investigate-event.py
│   ├── lab01-parameter-name.txt
│   ├── lab01-parameter-created.json
│   ├── lab01-wrong-region-events.json
│   ├── lab01-correct-region-events.json
│   └── lab01-verified-event.json
│
├── 02-trail-logging-disabled/
├── 03-cloudtrail-s3-delivery-failure/
├── 04-cloudtrail-bucket-policy-error/
├── 05-cloudtrail-kms-encryption-failure/
├── 06-data-events-not-recorded/
├── 07-multi-region-trail-misconfiguration/
├── 08-investigating-unauthorized-api-calls/
├── 09-cloudtrail-log-integrity-validation/
└── 10-cloudtrail-lake-query-troubleshooting/
```

### File Descriptions

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `investigate-event.py` | Parses and verifies the exact CloudTrail event |
| `lab01-parameter-name.txt` | Stores the temporary parameter name |
| `lab01-parameter-created.json` | Confirms the API operation |
| `lab01-wrong-region-events.json` | Records incorrect-Region lookup results |
| `lab01-correct-region-events.json` | Records correct-Region lookup results |
| `lab01-verified-event.json` | Records the matching event summary |

### Evidence Guidelines

All AWS evidence files should contain real AWS CLI responses.

Do not fabricate CloudTrail events, event IDs, timestamps, resources, or caller information.

CloudTrail events may contain account identifiers, identity ARNs, IP addresses, user agents, and request metadata.

Review and redact sensitive information before publishing evidence.

For a public GitHub repository, it is safer to publish the verified event summary rather than the entire unredacted CloudTrail event response.

### Suggested Git Ignore Entries

```gitignore
__pycache__/
*.pyc
.venv/
.env
*.log
```

---

## 21. Lessons Learned and Skills Demonstrated

### Lessons Learned

This lab demonstrates how an AWS CloudTrail management event can appear to be missing because the investigation is using the incorrect AWS Region.

We generated a real AWS API event by creating a temporary Systems Manager Parameter Store parameter.

The operation completed successfully in `us-east-1`.

We intentionally searched CloudTrail Event history in `us-west-2`.

The expected test event was not found in the incorrect Region.

We investigated the AWS account, API operation, resource location, event name, and investigation time range.

After identifying the mismatch, we searched Event history in `us-east-1`.

The correct regional search allowed us to retrieve the event after it became available.

We also created a Python script to parse the embedded CloudTrail event JSON and match the exact parameter name.

The script extracted important investigation fields, including the event ID, event time, event name, event source, AWS Region, and identity type.

Finally, we deleted the temporary parameter without changing or disabling any existing CloudTrail audit infrastructure.

**Key Lesson:** An apparently missing CloudTrail event is not necessarily a logging failure. Engineers should first verify the AWS account, Region, time range, event category, and API operation before troubleshooting trail configuration or delivery.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail Event history
- AWS management events
- Regional AWS API investigation
- AWS Systems Manager Parameter Store
- AWS CLI v2
- Linux Bash
- Python 3
- JSON parsing
- CloudTrail LookupEvents
- Systems Manager PutParameter
- Systems Manager GetParameter
- Systems Manager DescribeParameters
- Systems Manager DeleteParameter
- AWS STS GetCallerIdentity
- CloudTrail event identification
- CloudTrail event ID analysis
- CloudTrail event timestamp analysis
- AWS identity investigation
- Source IP investigation
- API user agent analysis
- Cloud audit troubleshooting
- Root cause analysis
- Incident evidence collection
- AWS resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-001 |
| Scenario | CloudTrail Events Missing |
| AWS Service | AWS CloudTrail |
| Supporting Service | Systems Manager |
| Management Event | PutParameter |
| Event Source | ssm.amazonaws.com |
| Operation Region | us-east-1 |
| Incorrect Search Region | us-west-2 |
| API Operation | Successful |
| Initial Target Event Search | Not found |
| Root Cause | Incorrect search Region |
| Remediation | Search us-east-1 |
| Verified Event | Found after normal availability |
| Event ID | Retrieved |
| Event Timestamp | Retrieved |
| Resource Name | Verified |
| Caller Information | Available for investigation |
| Cleanup | Temporary SSM parameter deleted |
| Incident Status | Resolved after event verification |

**Key Takeaway:** CloudTrail is a critical AWS auditing service, but effective investigations require understanding its regional behavior, event categories, and search limitations. Verifying the correct account, Region, time window, and resource details allows engineers to distinguish genuine audit logging failures from investigation mistakes.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [Viewing CloudTrail Events Using AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-cli.html)
- [AWS CLI — LookupEvents](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html)
- [AWS CLI — PutParameter](https://docs.aws.amazon.com/cli/latest/reference/ssm/put-parameter.html)
- [AWS CLI — GetParameter](https://docs.aws.amazon.com/cli/latest/reference/ssm/get-parameter.html)
- [AWS CLI — DeleteParameter](https://docs.aws.amazon.com/cli/latest/reference/ssm/delete-parameter.html)