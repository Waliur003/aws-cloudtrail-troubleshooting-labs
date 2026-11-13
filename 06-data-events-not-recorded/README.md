# Lab 06 — CloudTrail Data Events Not Recorded

**AWS CloudTrail Troubleshooting Labs | Cloud Engineering & Cloud Security Engineering**

## Overview

This lab demonstrates how to investigate and resolve missing Amazon S3 object-level events in AWS CloudTrail.

AWS CloudTrail records supported AWS API activity and provides audit information that helps Cloud Engineers and Cloud Security Engineers investigate resource changes, security incidents, and account activity.

However, not every AWS API operation is recorded by a CloudTrail trail automatically.

CloudTrail distinguishes between management events and data events.

Management events represent supported control-plane operations, while data events represent resource-level operations such as uploading, downloading, or deleting Amazon S3 objects.

In this lab, we simulate a production incident where an engineer cannot find the `PutObject` and `GetObject` API operations performed on an S3 bucket.

The CloudTrail trail exists, logging is enabled, and audit log delivery to Amazon S3 is working.

However, the trail is configured to collect management events only.

The `DataResources` field in the trail's event selectors is empty.

Consequently, the trail does not record the S3 object-level activity.

We investigate the issue using AWS CLI, identify the missing data-event selector, and configure CloudTrail to collect S3 object events for one dedicated test bucket.

After remediation, we generate new `PutObject` and `GetObject` operations and inspect the CloudTrail log files delivered to S3.

A Python script searches compressed JSON audit logs and verifies both events using the exact bucket name and object key.

Finally, we remove the data-event selector, delete the temporary CloudTrail and S3 resources, and document the incident findings.

**Troubleshooting workflow:**

CloudTrail Trail Creation → Management-Only Selectors → S3 Object Upload and Download → Data Events Missing → Event Selector Investigation → Root Cause Analysis → Enable S3 Data Events → Generate New Object Operations → Download CloudTrail Logs → Verify PutObject and GetObject → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-006 |
| Lab Name | CloudTrail Data Events Not Recorded |
| Difficulty | Intermediate to Advanced |
| Primary AWS Service | AWS CloudTrail |
| Supporting Service | Amazon S3 |
| AWS Region | `us-east-1` |
| Operating System | WSL2 Ubuntu |
| Interface | AWS CLI v2 |
| Scripting Languages | Bash, Python 3 |
| Trail Name | `cloudtrail-lab06-trail` |
| Trail Type | Single-Region |
| Organization Trail | No |
| Log Destination | Dedicated private S3 bucket |
| Data Source | Separate private S3 bucket |
| Bucket Encryption | SSE-S3 |
| Public Access | Blocked |
| Initial Event Selection | Management events only |
| Initial `DataResources` | Empty |
| Recovery Event Selection | Management and S3 data events |
| Data Resource Type | `AWS::S3::Object` |
| Data Event Operations | `PutObject`, `GetObject` |
| Fault Injection | Omit S3 data-event selector |
| Root Cause | Data events not configured |
| Remediation API | `PutEventSelectors` |
| Verification | Matching events in CloudTrail S3 logs |
| Cleanup | Remove selectors, trail, and buckets |

### Lab Objectives

- Understand management events and data events.
- Explain why S3 object activity may be missing from CloudTrail.
- Configure a dedicated CloudTrail trail.
- Create separate audit-log and test-data buckets.
- Inspect basic CloudTrail event selectors.
- Understand `IncludeManagementEvents`.
- Understand `ReadWriteType`.
- Understand `DataResources`.
- Reproduce missing S3 object events.
- Configure `AWS::S3::Object` data-event logging.
- Restrict event collection to a specific bucket.
- Generate real S3 object API activity.
- Verify CloudTrail log delivery.
- Parse compressed JSON logs with Python.
- Identify the exact resource associated with an event.
- Document root cause and remediation.
- Control data-event collection costs.
- Safely remove temporary AWS resources.

---

## 2. Production Incident Scenario

### Incident Description

A company uses Amazon S3 to store application files and documents.

The security team needs to investigate who uploaded and downloaded a particular object.

The engineer expects AWS CloudTrail to provide records of the operations.

The engineer searches for the following API events:

```text
PutObject
GetObject
```

However, the expected object-level events cannot be found.

The engineer verifies that the S3 object exists and that the upload and download operations completed successfully.

The CloudTrail trail is also enabled and has a working S3 audit destination.

Initially, the engineer suspects an issue with CloudTrail logging, delivery delays, or the incorrect AWS Region.

After inspecting the trail's event selectors, the engineer discovers that the configuration includes management events only.

The relevant field is:

```json
{
  "DataResources": []
}
```

No S3 object data-event resources are selected.

The engineer concludes that the trail was never configured to record the required object-level operations.

To resolve the issue, the engineer enables data-event logging for the affected S3 bucket.

The engineer generates new upload and download operations, downloads the delivered CloudTrail audit logs, and verifies that both events were recorded.

### Incident Symptoms

- S3 object operations complete successfully.
- CloudTrail trail exists.
- Trail logging is enabled.
- CloudTrail delivers management-event logs.
- `PutObject` and `GetObject` are missing from trail logs.
- `DataResources` is empty.
- Standard Event history does not display S3 object data events.
- The expected resource category is not selected.
- The issue is resolved after enabling data-event collection and generating new operations.

### Business Impact

Missing object-level audit records can result in:

- Incomplete investigations of file access.
- Reduced visibility into sensitive object activity.
- Difficulty identifying object uploads and downloads.
- Delayed incident response.
- Compliance and governance concerns.
- Incomplete access investigations.
- Incorrect assumptions about CloudTrail coverage.
- Lack of evidence for important resource-level operations.

### Objective

Identify why the CloudTrail trail does not record S3 object activity, configure the required data-event selector, and verify successful recording of fresh `PutObject` and `GetObject` events.

---

## 3. AWS Architecture

### AWS Architecture — Normal Management Event Logging

```text
                    AWS Account
                         |
                         v
                  AWS Management APIs
                         |
                         v
                    CloudTrail
                         |
                         v
                cloudtrail-lab06-trail
                         |
                         v
                 Management Events
                         |
                         v
                  CloudTrail S3 Logs
                         |
                         v
                 Security Investigation
```

### Broken Architecture

```text
                    AWS CLI
                       |
             +---------+---------+
             |                   |
             v                   v
        S3 PutObject         S3 GetObject
             |                   |
             +---------+---------+
                       |
                       v
                 S3 Data Bucket
                       |
                       v
                CloudTrail Trail
                       |
                       v
                 Event Selectors
                       |
                       v
          IncludeManagementEvents = true
                DataResources = []
                       |
                       v
             Object Events Not Selected
                       |
                       v
              Missing Data Audit Logs
```

### Recovered Architecture

```text
                  AWS CLI
                     |
           +---------+---------+
           |                   |
           v                   v
       PutObject            GetObject
           |                   |
           +---------+---------+
                     |
                     v
                S3 Data Bucket
                     |
                     v
                CloudTrail Trail
                     |
                     v
               Event Selectors
                     |
                     v
             AWS::S3::Object
                     |
                     v
          Data Bucket ARN Selected
                     |
                     v
              PutObject / GetObject
                     |
                     v
             CloudTrail Log Bucket
                     |
                     v
             Compressed JSON Logs
                     |
                     v
             Python Event Verification
```

### Two-Bucket Architecture

This lab uses two separate S3 buckets.

**Bucket A — CloudTrail Log Bucket**

Stores the audit log files delivered by CloudTrail.

**Bucket B — S3 Data Bucket**

Contains test objects and generates the API activity being investigated.

Separating these buckets prevents the data-event selector from unnecessarily collecting CloudTrail's own object writes to its audit destination.

### Architecture Components

| Component | Purpose |
|---|---|
| CloudTrail Trail | Records selected AWS events |
| Event Selectors | Determine which event categories are logged |
| S3 Log Bucket | Stores CloudTrail audit files |
| S3 Data Bucket | Generates object-level events |
| AWS CLI | Performs S3 operations and investigates CloudTrail |
| Python | Extracts matching events from audit logs |
| JSON | Stores CloudTrail events and selector configurations |
| GZIP | Compresses delivered CloudTrail log files |
| Bash | Executes the troubleshooting workflow |

---

## 4. Understanding CloudTrail Data Events

### What Is a Management Event?

A management event records supported AWS control-plane operations.

Examples include:

- Creating AWS resources.
- Changing configurations.
- Managing access settings.
- Updating service properties.
- Deleting resources.

Management events are enabled by default for newly created trails.

### What Is a Data Event?

A data event records supported resource-level activity.

Examples include:

- S3 object upload.
- S3 object download.
- S3 object deletion.
- Lambda function invocation.
- Other supported resource-level operations.

Data events are not enabled by default for CloudTrail trails.

### What Is PutObject?

`PutObject` is an Amazon S3 API operation used to upload an object.

CloudTrail classifies this operation as an S3 data event.

### What Is GetObject?

`GetObject` retrieves an object from Amazon S3.

It is also an S3 data event.

### What Is an Event Selector?

An event selector controls which AWS events a CloudTrail trail records.

A trail can use basic or advanced event selectors.

This lab uses basic event selectors.

### What Is IncludeManagementEvents?

This property specifies whether management events are included in the event selection.

```text
IncludeManagementEvents = true
```

### What Is ReadWriteType?

`ReadWriteType` identifies whether the selector includes read events, write events, or both.

```text
ReadWriteType = All
```

In this lab, `All` allows the selector to capture both S3 uploads and downloads.

### What Is DataResources?

`DataResources` identifies which supported data resources are selected for logging.

Before remediation:

```json
{
  "DataResources": []
}
```

After remediation:

```json
{
  "DataResources": [
    {
      "Type": "AWS::S3::Object",
      "Values": [
        "arn:aws:s3:::YOUR_DATA_BUCKET/"
      ]
    }
  ]
}
```

### Why Does the S3 ARN End With a Slash?

The trailing slash identifies the bucket's object-resource prefix.

This allows the selector to match object activity within the designated bucket.

### Does Event History Show Data Events?

No.

Standard CloudTrail Event history provides supported management events, not S3 object data events.

To examine the object events in this lab, we inspect the delivered CloudTrail S3 audit logs.

### Are Data Events Retroactive?

No.

Enabling a data-event selector does not retroactively record object operations that occurred before the selector was active.

We must generate new API activity after the configuration change.

### Do Data Events Cost Money?

Yes.

CloudTrail data events are charged separately from standard Event history.

Monitoring high-volume S3 activity can generate substantial event counts, so production configurations should scope collection deliberately.

---

## 5. Prerequisites and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL2 Ubuntu.
- Bash.
- Python 3.
- CloudTrail permissions.
- Amazon S3 permissions.
- Git and GitHub.

### Relevant AWS Permissions

```text
sts:GetCallerIdentity

cloudtrail:CreateTrail
cloudtrail:DescribeTrails
cloudtrail:GetTrailStatus
cloudtrail:GetEventSelectors
cloudtrail:PutEventSelectors
cloudtrail:StartLogging
cloudtrail:StopLogging
cloudtrail:AddTags
cloudtrail:ListTags
cloudtrail:DeleteTrail
cloudtrail:LookupEvents

s3:CreateBucket
s3:HeadBucket
s3:PutBucketPolicy
s3:GetBucketPolicy
s3:PutBucketTagging
s3:GetBucketTagging
s3:PutPublicAccessBlock
s3:PutBucketEncryption
s3:PutObject
s3:GetObject
s3:ListBucket
s3:DeleteObject
s3:DeleteBucket
```

### Safety Rules

- Use only newly created lab-owned resources.
- Do not change existing organization trails.
- Do not select production S3 buckets for the exercise.
- Keep both buckets private.
- Enable data events only for the test bucket.
- Avoid collecting object activity from all buckets.
- Use synthetic object contents.
- Do not publish unredacted CloudTrail audit records.
- Verify resource ownership before cleanup.
- Remove the data-event configuration after testing.

### Cost Considerations

Potential costs include:

- CloudTrail S3 data events.
- Additional management-event copies.
- S3 storage and API requests.

The data-event selector is restricted to one disposable S3 bucket to keep the scope and cost small.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Create Lab Directory

```bash
cd ~/aws-cloudtrail-troubleshooting-labs

mkdir -p 06-data-events-not-recorded

cd 06-data-events-not-recorded
```

### Step 2 — Verify AWS CLI

```bash
aws --version

aws sts get-caller-identity
```

### Step 3 — Configure Environment Variables

```bash
export AWS_REGION="us-east-1"
export AWS_PAGER=""

export ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text)

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab06"

export TRAIL_NAME="cloudtrail-lab06-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export LOG_BUCKET="cloudtrail-lab06-logs-${ACCOUNT_ID}-${SUFFIX}"

export DATA_BUCKET="cloudtrail-lab06-data-${ACCOUNT_ID}-${SUFFIX}"

export OBJECT_KEY="test-object.txt"
```

### Step 4 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$LOG_BUCKET"
echo "$DATA_BUCKET"
echo "$OBJECT_KEY"
```

### Step 5 — Save Resource Identifiers

```bash
cat > lab06-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export LOG_BUCKET="$LOG_BUCKET"
export DATA_BUCKET="$DATA_BUCKET"
export OBJECT_KEY="$OBJECT_KEY"
EOF
```

Restore the configuration in a new terminal session:

```bash
source lab06-resources.env
```

### Step 6 — Inspect Existing Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

Ensure the chosen trail name does not belong to another resource.

---

## 7. Create and Secure the S3 Buckets

### Step 1 — Create CloudTrail Log Bucket

```bash
aws s3api create-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 2 — Create S3 Data Bucket

```bash
aws s3api create-bucket \
  --bucket "$DATA_BUCKET" \
  --region "$AWS_REGION"
```

### Step 3 — Block Public Access

```bash
for BUCKET in "$LOG_BUCKET" "$DATA_BUCKET"
do
  aws s3api put-public-access-block \
    --bucket "$BUCKET" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --region "$AWS_REGION"
done
```

### Step 4 — Enable SSE-S3

```bash
for BUCKET in "$LOG_BUCKET" "$DATA_BUCKET"
do
  aws s3api put-bucket-encryption \
    --bucket "$BUCKET" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
    --region "$AWS_REGION"
done
```

### Step 5 — Tag Both Buckets

```bash
for BUCKET in "$LOG_BUCKET" "$DATA_BUCKET"
do
  aws s3api put-bucket-tagging \
    --bucket "$BUCKET" \
    --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
    --region "$AWS_REGION"
done
```

### Step 6 — Verify Buckets

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

```bash
aws s3api head-bucket \
  --bucket "$DATA_BUCKET" \
  --region "$AWS_REGION"
```

### Configuration Summary

| Component | Expected |
|---|---|
| Log bucket | Available |
| Data bucket | Available |
| Public access | Blocked on both |
| Encryption | SSE-S3 |
| AWS Region | us-east-1 |
| Project tag | Present |

---

## 8. Configure the CloudTrail S3 Log Bucket Policy

### Purpose

CloudTrail needs permission to inspect the logging bucket ACL and deliver log objects.

We configure the log bucket policy without granting unnecessary permissions to the data bucket.

### Step 1 — Create Policy Generator

Save as `generate-log-bucket-policy.py`:

```python
#!/usr/bin/env python3

import json
import os

bucket = os.environ["LOG_BUCKET"]
account = os.environ["ACCOUNT_ID"]
trail = os.environ["TRAIL_ARN"]

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::{bucket}",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": trail
                }
            }
        },
        {
            "Sid": "CloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": (
                f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*"
            ),
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": trail
                }
            }
        }
    ]
}

with open("cloudtrail-log-bucket-policy.json", "w") as file:
    json.dump(policy, file, indent=2)

print("CloudTrail log bucket policy generated")
```

### Step 2 — Generate Policy

```bash
python3 generate-log-bucket-policy.py
```

### Step 3 — Inspect Policy

```bash
python3 -m json.tool cloudtrail-log-bucket-policy.json
```

### Step 4 — Apply Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$LOG_BUCKET" \
  --policy file://cloudtrail-log-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 5 — Verify Applied Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$LOG_BUCKET" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Confirm that CloudTrail has the necessary permissions to deliver log files.

---

## 9. Create CloudTrail with Management Events Only

### Step 1 — Create Trail

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$LOG_BUCKET" \
  --no-is-multi-region-trail \
  --no-include-global-service-events \
  --no-enable-log-file-validation \
  --region "$AWS_REGION"
```

### Step 2 — Tag Trail

```bash
aws cloudtrail add-tags \
  --resource-id "$TRAIL_ARN" \
  --tags-list "Key=Project,Value=$PROJECT_TAG" \
  --region "$AWS_REGION"
```

### Step 3 — Create the Management-Only Selector

Save as `management-only-selectors.json`:

```json
[
  {
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [],
    "ExcludeManagementEventSources": []
  }
]
```

### Step 4 — Apply Selector

```bash
aws cloudtrail put-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --event-selectors file://management-only-selectors.json \
  --region "$AWS_REGION"
```

### Step 5 — Verify Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected:

```json
{
  "ReadWriteType": "All",
  "IncludeManagementEvents": true,
  "DataResources": []
}
```

The displayed fields are the important part of the result; the complete AWS response includes additional information.

### Step 6 — Start Logging

```bash
aws cloudtrail start-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 7 — Verify Logging Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
IsLogging = true
```

### Step 8 — Save Initial Evidence

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab06-broken-event-selectors.json
```

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab06-initial-trail-status.json
```

---

## 10. Reproduce Missing S3 Object Events

### Step 1 — Create a Test File

```bash
echo "CloudTrail Lab 06 - data event troubleshooting" > test-object.txt
```

### Step 2 — Upload the Object

```bash
aws s3api put-object \
  --bucket "$DATA_BUCKET" \
  --key "$OBJECT_KEY" \
  --body test-object.txt \
  --region "$AWS_REGION"
```

The operation generates S3 `PutObject` API activity.

### Step 3 — Download the Object

```bash
aws s3api get-object \
  --bucket "$DATA_BUCKET" \
  --key "$OBJECT_KEY" \
  downloaded-test-object.txt \
  --region "$AWS_REGION"
```

### Step 4 — Verify the File Contents

```bash
cat downloaded-test-object.txt
```

Expected:

```text
CloudTrail Lab 06 - data event troubleshooting
```

### Step 5 — Search CloudTrail Event History

Search for PutObject:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
  --max-items 50 \
  --region "$AWS_REGION"
```

Search for GetObject:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --max-items 50 \
  --region "$AWS_REGION"
```

Standard CloudTrail Event history does not display S3 object data events.

An empty result here is expected and does not, by itself, prove the trail's data-event configuration is incorrect.

### Step 6 — Inspect the Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --query 'EventSelectors[].{Management:IncludeManagementEvents,DataResources:DataResources}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```json
[
  {
    "Management": true,
    "DataResources": []
  }
]
```

### Step 7 — Check CloudTrail Log Delivery

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

The trail may deliver management-event logs, but the initial S3 object operations were not selected for collection.

### Step 8 — Save Broken-State Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab06-before-remediation-status.json
```

### Initial Investigation Summary

| Component | Expected |
|---|---|
| CloudTrail trail | Exists |
| Logging status | Enabled |
| S3 data bucket | Available |
| S3 log bucket | Available |
| PutObject request | Successful |
| GetObject request | Successful |
| Management events | Selected |
| S3 data events | Not selected |
| Root cause | Missing data-event selector |

---

<WritingBlock id="68427" variant="document"># Lab 06 — README.md (Sections 11–21)

## 11. Investigate the Missing Data Events

### Step 1 — Inspect the CloudTrail Trail

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,Region:HomeRegion}' \
  --output table \
  --region "$AWS_REGION"
```

Confirm the trail exists in `us-east-1` and references the dedicated log bucket.

### Step 2 — Check Logging Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
IsLogging = true
```

### Step 3 — Verify the Test Object

```bash
aws s3api head-object \
  --bucket "$DATA_BUCKET" \
  --key "$OBJECT_KEY" \
  --region "$AWS_REGION"
```

Expected: the object exists.

### Step 4 — Inspect Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Focus on:

```text
IncludeManagementEvents
ReadWriteType
DataResources
```

### Step 5 — Verify the Missing Configuration

The critical finding is:

```json
{
  "DataResources": []
}
```

The trail records management events but does not select any S3 object data-event resources.

### Step 6 — Verify the Correct Event Category

The API operations are:

```text
PutObject
GetObject
```

Both are S3 object data events.

They are not management events.

### Step 7 — Identify the Investigation Limitation

CloudTrail Event history provides management events, not S3 object data events.

Therefore, engineers must inspect appropriately configured trail logs or an applicable CloudTrail event data store instead of expecting these events to appear in standard Event history.

### Investigation Matrix

| Investigation | Finding |
|---|---|
| AWS Region | Correct |
| CloudTrail trail | Exists |
| Logging status | Enabled |
| Destination bucket | Available |
| S3 test object | Exists |
| API operations | Successful |
| Management selector | Enabled |
| Data resource selector | Empty |
| Missing event category | S3 object data events |
| Root cause | Incorrect event selection |

---

## 12. Root Cause Analysis

### Root Cause

The CloudTrail trail was configured to collect management events only.

Its basic event selector included:

```json
{
  "IncludeManagementEvents": true,
  "ReadWriteType": "All",
  "DataResources": []
}
```

Because `DataResources` was empty, the trail was not configured to record S3 object operations.

The `PutObject` and `GetObject` API requests succeeded, but the trail did not select those events for logging.

The issue was not caused by a missing S3 bucket, disabled trail logging, or failed management-event delivery.

### Root Cause Flow

```text
S3 PutObject / GetObject
          |
          v
Successful API Operations
          |
          v
CloudTrail Trail
          |
          v
Event Selector Evaluation
          |
          v
Management Events Only
          |
          v
DataResources = []
          |
          v
Object-Level Events Not Selected
          |
          v
Events Missing from Trail Logs
```

### Five Whys

**Why 1 — Why were S3 object events missing?**

The CloudTrail trail did not collect them.

**Why 2 — Why didn't the trail collect the events?**

The S3 object data-event selector was missing.

**Why 3 — Why were management events still recorded?**

Management and data-event collection are configured independently.

**Why 4 — Why didn't Event history display the operations?**

Standard Event history does not include S3 object data events.

**Why 5 — How was the issue resolved?**

We configured the S3 data-event selector and generated new API operations.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-006 |
| AWS Service | CloudTrail |
| Supporting Service | Amazon S3 |
| Trail Logging | Enabled |
| Fault | No S3 data-event selector |
| Root Cause | `DataResources=[]` |
| Missing Events | PutObject and GetObject |
| Remediation | Configure `AWS::S3::Object` |
| Verification | New events found in S3 audit logs |

**Key Lesson:** CloudTrail logging being enabled does not mean every category of AWS activity is being recorded. Engineers must inspect event selectors to understand the trail's actual audit coverage.

---

## 13. Remediation — Enable S3 Object Data Events

### Step 1 — Generate the Correct Selector

```bash
python3 - <<'PY'
import json
import os

data_bucket = os.environ["DATA_BUCKET"]

selectors = [
    {
        "ReadWriteType": "All",
        "IncludeManagementEvents": True,
        "DataResources": [
            {
                "Type": "AWS::S3::Object",
                "Values": [
                    f"arn:aws:s3:::{data_bucket}/"
                ]
            }
        ],
        "ExcludeManagementEventSources": []
    }
]

with open("correct-data-event-selectors.json", "w") as file:
    json.dump(selectors, file, indent=2)

print("S3 data-event selector generated")
PY
```

### Step 2 — Inspect the Correct Selector

```bash
python3 -m json.tool correct-data-event-selectors.json
```

Expected structure:

```json
[
  {
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [
      {
        "Type": "AWS::S3::Object",
        "Values": [
          "arn:aws:s3:::YOUR_DATA_BUCKET/"
        ]
      }
    ],
    "ExcludeManagementEventSources": []
  }
]
```

Replace `YOUR_DATA_BUCKET` with the actual generated bucket name.

### Step 3 — Apply the Correct Event Selector

```bash
aws cloudtrail put-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --event-selectors file://correct-data-event-selectors.json \
  --region "$AWS_REGION"
```

### Step 4 — Verify the Applied Selector

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Verify:

- `IncludeManagementEvents=true`
- `ReadWriteType=All`
- `DataResources.Type=AWS::S3::Object`
- `DataResources.Values` references the correct data bucket

### Step 5 — Save the Updated Configuration

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab06-restored-event-selectors.json
```

### Step 6 — Verify Trail Logging

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
IsLogging = true
```

### Remediation Explanation

The new selector adds S3 object data-event collection for the dedicated data bucket while preserving the existing management-event coverage.

It does not select the CloudTrail logging bucket.

This limits event volume and avoids unnecessary logging of CloudTrail's own audit file delivery.

**Important:** The selector affects future events. Previously uncollected object operations will not be reconstructed.

---

## 14. Generate Recovery S3 Object Events

### Step 1 — Create a Unique Recovery Object Name

```bash
export RECOVERY_OBJECT_KEY="recovery-object-$(date -u +%Y%m%d%H%M%S).txt"
```

### Step 2 — Create the Test File

```bash
echo "CloudTrail Lab 06 - data events enabled" > recovery-object.txt
```

### Step 3 — Upload the Recovery Object

```bash
aws s3api put-object \
  --bucket "$DATA_BUCKET" \
  --key "$RECOVERY_OBJECT_KEY" \
  --body recovery-object.txt \
  --region "$AWS_REGION"
```

This generates a new `PutObject` operation after enabling the selector.

### Step 4 — Save the Recovery Object Key

```bash
printf '%s\n' "$RECOVERY_OBJECT_KEY" \
  > lab06-recovery-object-key.txt
```

### Step 5 — Download the Recovery Object

```bash
aws s3api get-object \
  --bucket "$DATA_BUCKET" \
  --key "$RECOVERY_OBJECT_KEY" \
  downloaded-recovery-object.txt \
  --region "$AWS_REGION"
```

This generates a new `GetObject` operation.

### Step 6 — Verify File Contents

```bash
cat downloaded-recovery-object.txt
```

Expected:

```text
CloudTrail Lab 06 - data events enabled
```

### Step 7 — Verify the Recovery Object

```bash
aws s3api head-object \
  --bucket "$DATA_BUCKET" \
  --key "$RECOVERY_OBJECT_KEY" \
  --query '{Size:ContentLength,Encryption:ServerSideEncryption}' \
  --output json \
  --region "$AWS_REGION"
```

### Recovery Event Matrix

| API Operation | Event Category | Expected |
|---|---|---|
| PutObject | Data | Recorded |
| GetObject | Data | Recorded |
| Event Source | `s3.amazonaws.com` | Both |
| Resource Type | `AWS::S3::Object` | Both |
| AWS Region | us-east-1 | Both |
| Bucket | DATA_BUCKET | Both |

---

## 15. Verify Data Events in CloudTrail S3 Logs

### Step 1 — Inspect Trail Delivery

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 2 — List CloudTrail Logs

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

CloudTrail log delivery is asynchronous.

The two recovery events may appear in different compressed log files.

### Step 3 — Download Log Files

```bash
mkdir -p evidence/cloudtrail-logs
```

```bash
aws s3 cp \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/cloudtrail-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 4 — Create the Verification Script

Save as `verify-s3-data-events.py`:

```python
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
```

### Step 5 — Run the Verification Script

```bash
python3 verify-s3-data-events.py \
  evidence/cloudtrail-logs \
  "$DATA_BUCKET" \
  "$RECOVERY_OBJECT_KEY" \
  lab06-recovered-data-events.json
```

Expected after successful delivery:

```text
SUCCESS: PutObject and GetObject data events verified
```

If an event has not arrived, check the event selectors and trail delivery status, download any newer log files, and run the verification again.

### Step 6 — Inspect Verified Evidence

```bash
python3 -m json.tool lab06-recovered-data-events.json
```

Expected event fields:

| Field | Expected |
|---|---|
| eventName | PutObject or GetObject |
| eventCategory | Data |
| eventSource | s3.amazonaws.com |
| awsRegion | us-east-1 |
| bucketName | Test data bucket |
| objectKey | Exact recovery object |
| eventID | Present |
| eventTime | After remediation |
| sourceFile | Delivered CloudTrail log |

### Step 7 — Save Final Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab06-final-trail-status.json
```

### Before and After Comparison

| Investigation | Broken | Recovered |
|---|---|---|
| Trail exists | Yes | Yes |
| IsLogging | true | true |
| Management events | Enabled | Enabled |
| S3 data events | Not selected | Selected |
| DataResources | Empty | Data bucket ARN |
| PutObject recorded | Not selected for initial call | Verified for recovery call |
| GetObject recorded | Not selected for initial call | Verified for recovery call |
| Event History | No S3 object data events | Still no S3 object data events |
| Root cause | Missing selector | Corrected |

**Recovery is confirmed when the exact new PutObject and GetObject operations are found in the delivered CloudTrail audit logs.**

---

## 16. Other Missing Data Event Scenarios

### Scenario A — Wrong Bucket ARN

The event selector references a different S3 bucket.

The requested object activity falls outside the selected resource scope.

### Scenario B — Incorrect ReadWriteType

The selector may collect only write events.

In that case, PutObject could be recorded while GetObject is missing.

### Scenario C — Data Events Enabled After the API Operation

CloudTrail does not retroactively collect events that occurred before the selector became active.

### Scenario D — Incorrect AWS Region

A single-Region trail does not provide the same regional coverage as a multi-Region trail.

Engineers must check the relevant Region and trail configuration.

### Scenario E — Audit Log Delivery Failure

The selector may be correct, but CloudTrail could fail to deliver the logs to S3.

Inspect `LatestDeliveryError` and the destination configuration.

### Scenario F — Standard Event History Used Instead of Trail Logs

Event history does not display S3 object data events.

Engineers must use the appropriate trail delivery or event data store.

### Scenario G — Incorrect Data Resource Type

The configured resource type does not match the activity being investigated.

### Scenario H — Advanced Selector Misconfiguration

An advanced event selector may exclude the expected event category, event name, or resource ARN.

Also, applying advanced event selectors replaces existing basic event selectors.

### Troubleshooting Matrix

| Symptom | Possible Cause | Investigation |
|---|---|---|
| PutObject missing | Data events disabled | GetEventSelectors |
| GetObject missing | Read events excluded | ReadWriteType |
| One bucket missing | Incorrect bucket ARN | DataResources |
| Older events missing | Selector enabled later | Event timeline |
| S3 log files missing | Delivery problem | GetTrailStatus |
| Event history empty | Data events unsupported there | Inspect trail logs |
| Wrong Region | Single-Region coverage | DescribeTrails |
| Unexpected event volume | Selector too broad | Resource scoping |

---

## 17. Production Troubleshooting Best Practices

### Troubleshooting Checklist

1. Identify the AWS account.
2. Confirm the AWS Region.
3. Verify the S3 object operation completed.
4. Determine whether the operation is a management or data event.
5. Identify the relevant CloudTrail trail.
6. Check `IsLogging`.
7. Inspect the event selectors.
8. Verify `IncludeManagementEvents`.
9. Inspect `DataResources`.
10. Confirm `AWS::S3::Object`.
11. Verify the selected S3 bucket ARN.
12. Inspect `ReadWriteType`.
13. Check whether the operation occurred after selector activation.
14. Verify S3 log delivery.
15. Download the relevant audit log files.
16. Parse the compressed JSON records.
17. Match the exact event name.
18. Match the S3 bucket and object key.
19. Verify the event category.
20. Document the root cause and remediation.
21. Review data-event collection costs.

### Production Investigation Workflow

```text
S3 Object Activity Missing
          |
          v
Verify API Operation
          |
          v
Identify Event Category
          |
          v
Inspect CloudTrail Trail
          |
          v
Verify Logging State
          |
          v
Inspect Event Selectors
          |
          v
Check AWS::S3::Object
          |
          v
Verify Bucket ARN Scope
          |
          v
Apply Correct Selector
          |
          v
Generate New API Activity
          |
          v
Download CloudTrail Logs
          |
          v
Verify Exact Data Events
          |
          v
Document Findings
```

### Security Recommendations

- Record data events for sensitive S3 buckets.
- Scope selectors to relevant buckets and prefixes.
- Preserve management-event coverage when updating selectors.
- Monitor changes to CloudTrail event selectors.
- Protect audit log destinations.
- Enable encryption and appropriate retention.
- Restrict CloudTrail administrative permissions.
- Use multi-Region configurations when broader coverage is required.
- Review the cost implications of high-volume data events.
- Test selector changes before production deployment.

### Operational Recommendations

CloudTrail data-event logging should be configured according to the organization's auditing and security requirements.

For large environments, advanced event selectors can provide more granular filtering by event category, resource type, resource ARN, and event name.

Avoid collecting every S3 object operation without an operational reason, especially in high-volume environments.

---

## 18. AWS Resource Cleanup

**Warning:** Delete only the dedicated Lab 06 trail and buckets.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm:

```text
Project=CloudTrail-Troubleshooting-Lab06
```

### Step 2 — Verify Bucket Ownership

```bash
for BUCKET in "$LOG_BUCKET" "$DATA_BUCKET"
do
  aws s3api get-bucket-tagging \
    --bucket "$BUCKET" \
    --region "$AWS_REGION"
done
```

### Step 3 — Remove S3 Data-Event Collection

```bash
aws cloudtrail put-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --event-selectors file://management-only-selectors.json \
  --region "$AWS_REGION"
```

Verify:

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected:

```text
DataResources = []
```

### Step 4 — Stop Logging

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 5 — Delete the Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Trail Deletion

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

Expected:

```json
[]
```

### Step 7 — Delete Test Data Objects

```bash
aws s3 rm "s3://${DATA_BUCKET}/" \
  --recursive \
  --region "$AWS_REGION"
```

### Step 8 — Delete CloudTrail Audit Log Objects

Preserve any investigation evidence you intend to retain before this step.

```bash
aws s3 rm "s3://${LOG_BUCKET}/" \
  --recursive \
  --region "$AWS_REGION"
```

### Step 9 — Delete Data Bucket

```bash
aws s3api delete-bucket \
  --bucket "$DATA_BUCKET" \
  --region "$AWS_REGION"
```

### Step 10 — Delete Log Bucket

```bash
aws s3api delete-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 11 — Verify Cleanup

```bash
aws s3api head-bucket \
  --bucket "$DATA_BUCKET" \
  --region "$AWS_REGION"
```

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Expected: both dedicated buckets are no longer found.

### Cleanup Summary

| Resource | Expected State |
|---|---|
| CloudTrail trail | Deleted |
| Data-event selector | Removed |
| CloudTrail log bucket | Deleted |
| S3 data bucket | Deleted |
| Test objects | Deleted |
| Existing production trails | Unchanged |
| KMS key | None created |
| EC2 instances | None created |
| VPC resources | None created |

---

## 19. Interview Questions and Answers

### Q1. What are CloudTrail data events?

Data events record supported resource-level API activity, including S3 object operations.

### Q2. Are CloudTrail data events enabled by default?

No. Data-event collection requires configuration.

### Q3. What are management events?

Management events record supported control-plane activity, such as resource configuration changes.

### Q4. What is the difference between PutObject and GetObject?

PutObject uploads an S3 object. GetObject retrieves an S3 object.

### Q5. Why were S3 object events missing in this lab?

The CloudTrail trail was configured to record management events only.

### Q6. What does DataResources=[] mean?

No basic data-event resources are selected in that event selector.

### Q7. Which event selector resource type is used for S3 object events?

`AWS::S3::Object`.

### Q8. How do you configure CloudTrail data events using AWS CLI?

Use `aws cloudtrail put-event-selectors` with an appropriate data resource configuration.

### Q9. Which command retrieves the active selectors?

```bash
aws cloudtrail get-event-selectors \
  --trail-name YOUR_TRAIL_NAME
```

### Q10. Does standard CloudTrail Event history show S3 object data events?

No. Event history provides management events.

### Q11. Why might GetObject be missing while PutObject is recorded?

The event selector may be configured for write events only, or another filter may exclude read operations.

### Q12. Can data events be collected for one S3 bucket?

Yes. Selectors can be scoped to the specified bucket.

### Q13. Are CloudTrail data events billable?

Yes. Data events can generate additional charges.

### Q14. Are data events recorded retroactively?

No. Events occurring before the selector was enabled are not retroactively collected by that trail.

### Q15. What is the difference between basic and advanced event selectors?

Basic selectors support management events and certain data resource types. Advanced selectors support more granular filtering and additional supported event types.

### Q16. Can a trail use both basic and advanced event selectors simultaneously?

No. Configuring one type replaces the other.

### Q17. Why should the CloudTrail logging bucket be separate from the test data bucket?

It isolates audit delivery from the object activity being monitored and helps prevent unnecessary event collection.

### Q18. How do you verify successful data-event logging?

Generate new object operations, download delivered CloudTrail logs, and find the exact events associated with the bucket and object key.

### Q19. How would you investigate missing S3 data events in production?

Check the event category, trail logging status, event selector type, resource ARN, read/write selection, operation timestamp, and destination log delivery.

### Q20. How would you explain this lab in an interview?

I created a dedicated CloudTrail trail and two private S3 buckets.

One bucket stored CloudTrail audit logs, while the other generated test object operations.

Initially, I configured the trail to record management events only.

I generated PutObject and GetObject API operations and investigated why those object-level events were not recorded by the trail.

I discovered that the DataResources field was empty.

I configured an AWS::S3::Object data-event selector, restricted it to the test bucket, and preserved management-event logging.

After enabling the selector, I generated new PutObject and GetObject operations.

I downloaded the CloudTrail log files from S3 and wrote a Python script to locate both events using the exact bucket name and object key.

Finally, I documented the root cause, verified the remediation, removed the data-event selector, and deleted the temporary resources.

---

## 20. Repository Structure

```text
aws-cloudtrail-troubleshooting-labs/
│
├── README.md
│
├── 01-cloudtrail-events-missing/
│   └── README.md
│
├── 02-trail-logging-disabled/
│   └── README.md
│
├── 03-cloudtrail-s3-delivery-failure/
│   └── README.md
│
├── 04-cloudtrail-bucket-policy-error/
│   └── README.md
│
├── 05-cloudtrail-kms-encryption-failure/
│   └── README.md
│
├── 06-data-events-not-recorded/
│   ├── README.md
│   ├── generate-log-bucket-policy.py
│   ├── verify-s3-data-events.py
│   ├── cloudtrail-log-bucket-policy.json
│   ├── management-only-selectors.json
│   ├── correct-data-event-selectors.json
│   ├── lab06-resources.env
│   ├── test-object.txt
│   ├── downloaded-test-object.txt
│   ├── recovery-object.txt
│   ├── downloaded-recovery-object.txt
│   ├── lab06-recovery-object-key.txt
│   ├── lab06-broken-event-selectors.json
│   ├── lab06-restored-event-selectors.json
│   ├── lab06-initial-trail-status.json
│   ├── lab06-before-remediation-status.json
│   ├── lab06-recovered-data-events.json
│   ├── lab06-final-trail-status.json
│   └── evidence/
│       └── cloudtrail-logs/
│
├── 07-multi-region-trail-misconfiguration/
├── 08-investigating-unauthorized-api-calls/
├── 09-cloudtrail-log-integrity-validation/
└── 10-cloudtrail-lake-query-troubleshooting/
```

### File Descriptions

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `generate-log-bucket-policy.py` | Generates the audit bucket policy |
| `verify-s3-data-events.py` | Verifies PutObject and GetObject audit events |
| `cloudtrail-log-bucket-policy.json` | CloudTrail S3 destination permissions |
| `management-only-selectors.json` | Initial configuration without data events |
| `correct-data-event-selectors.json` | Remediated data-event configuration |
| `lab06-resources.env` | Local resource identifiers |
| `test-object.txt` | Initial test object |
| `recovery-object.txt` | Recovery test object |
| `lab06-recovery-object-key.txt` | Exact recovery object key |
| `lab06-broken-event-selectors.json` | Evidence of missing data-event selection |
| `lab06-restored-event-selectors.json` | Evidence of corrected selection |
| `lab06-initial-trail-status.json` | Initial logging status |
| `lab06-before-remediation-status.json` | Status before the selector change |
| `lab06-recovered-data-events.json` | Verified recovery event records |
| `lab06-final-trail-status.json` | Final trail status |
| `evidence/cloudtrail-logs/` | Downloaded audit logs |

### GitHub Evidence Guidelines

Use actual AWS CLI output for all evidence files.

Do not fabricate event IDs, timestamps, bucket names, object keys, or CloudTrail verification results.

Before publishing, review files containing AWS account identifiers, principal ARNs, request source information, and other audit metadata.

Raw CloudTrail logs should remain private unless they have been appropriately sanitized.

The README, reusable Python scripts, selector templates, and redacted verification summaries are suitable for a public portfolio.

### Recommended .gitignore

```gitignore
__pycache__/
*.pyc
.venv/
.env

**/lab06-resources.env
**/evidence/cloudtrail-logs/
**/lab06-recovered-data-events.json
**/lab06-*-status.json
**/lab06-*-selectors.json
**/cloudtrail-log-bucket-policy.json
**/correct-data-event-selectors.json
```

Generated policies and selectors can be reproduced using the documented commands.

Only publish generated configuration or evidence files after reviewing and sanitizing them.

---

## 21. Lessons Learned and Skills Demonstrated

### Lessons Learned

This lab demonstrates that CloudTrail can be actively logging management events while missing important S3 object-level activity.

We created a dedicated CloudTrail trail and two private S3 buckets.

We configured the trail with management-event logging only.

We generated S3 PutObject and GetObject operations and investigated why those events were missing from the trail's audit records.

The investigation revealed that no S3 data resources were selected.

We corrected the event selector to include AWS::S3::Object activity for the dedicated test bucket.

After applying the configuration, we generated new object operations and verified that both events appeared in the delivered CloudTrail S3 logs.

We used Python to parse compressed audit files and identify the exact events by API name, bucket, and object key.

Finally, we removed the data-event selector and deleted the temporary resources.

**Key Lesson:** CloudTrail event coverage depends on event selector configuration. Engineers must understand the difference between management events, data events, and the limitations of standard Event history.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail event selectors
- Management events
- Data events
- AWS::S3::Object
- Amazon S3
- S3 PutObject
- S3 GetObject
- S3 bucket policies
- S3 security configuration
- AWS CLI v2
- Linux Bash
- Python 3
- JSON processing
- GZIP log inspection
- CloudTrail S3 log delivery
- Data-event troubleshooting
- Resource-specific logging
- Cloud audit investigation
- Root cause analysis
- Remediation verification
- AWS cost awareness
- Resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-006 |
| Scenario | CloudTrail Data Events Not Recorded |
| Trail | cloudtrail-lab06-trail |
| Region | us-east-1 |
| Trail Logging | Enabled |
| Initial DataResources | Empty |
| Missing Events | PutObject, GetObject |
| Root Cause | Missing S3 data-event selector |
| Remediation | Configure AWS::S3::Object |
| Selected Resource | Dedicated S3 data bucket |
| Recovery PutObject | Verified in trail logs |
| Recovery GetObject | Verified in trail logs |
| Audit Destination | Dedicated S3 log bucket |
| Cleanup | Trail and buckets deleted |
| Incident Status | Resolved after verification |

**Key Takeaway:** CloudTrail recording must be configured according to the events an organization needs to investigate. Management-event logging alone does not provide complete visibility into S3 object access.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Logging Data Events with CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [Amazon S3 CloudTrail Events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [AWS CLI — PutEventSelectors](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/put-event-selectors.html)
- [AWS CLI — GetEventSelectors](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-event-selectors.html)
- [AWS CLI — GetTrailStatus](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-trail-status.html)
- [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/)