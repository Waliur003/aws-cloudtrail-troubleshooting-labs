# Lab 04 — CloudTrail Bucket Policy Error

## Overview

This lab demonstrates how to investigate and resolve an AWS CloudTrail S3 delivery failure caused by an incorrect Amazon S3 bucket policy.

AWS CloudTrail records supported AWS API activity and delivers selected management and data events to Amazon S3 for security monitoring, auditing, compliance, and incident investigations.

However, a CloudTrail trail can remain enabled while failing to deliver audit logs.

In this lab, we simulate a production incident where CloudTrail cannot deliver management event logs because its destination S3 bucket policy does not grant the required `s3:PutObject` permission.

The CloudTrail trail still exists, logging remains enabled, and the S3 bucket is available.

The problem is caused by an incomplete resource-based policy.

We begin by creating a dedicated CloudTrail trail and a private S3 bucket. We configure the correct bucket policy and verify that CloudTrail can successfully deliver a test management event.

Next, we intentionally replace the bucket policy with a broken version that removes the CloudTrail write permission.

We investigate the incident using AWS CLI by examining trail status, the S3 destination, management event selectors, and the bucket policy.

After identifying the missing permission, we restore the correct policy and generate a fresh management API event.

Finally, we inspect compressed CloudTrail log files using Python, verify the exact recovery event, document the root cause, and delete the temporary AWS resources.

**Troubleshooting workflow:**

CloudTrail Trail Creation → S3 Bucket Configuration → Correct Bucket Policy → Baseline Event Delivery → Remove `s3:PutObject` → S3 Delivery Failure → Policy Investigation → Root Cause Analysis → Restore Permission → Generate Recovery Event → Verify S3 Delivery → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-004 |
| Difficulty | Intermediate to Advanced |
| Primary AWS Service | AWS CloudTrail |
| Supporting Services | Amazon S3, AWS Systems Manager |
| AWS Region | `us-east-1` |
| Environment | WSL2 Ubuntu |
| CLI | AWS CLI v2 |
| Programming | Python 3 |
| Shell | Bash |
| Trail Name | `cloudtrail-lab04-trail` |
| Trail Type | Single-Region |
| Organization Trail | No |
| S3 Destination | Dedicated lab bucket |
| S3 Encryption | SSE-S3 |
| Public Access | Blocked |
| Event Category | Management |
| Event Selectors | Read and write |
| Test API | `PutParameter` |
| Test Event Source | `ssm.amazonaws.com` |
| Correct Policy | `correct-bucket-policy.json` |
| Broken Policy | `broken-bucket-policy.json` |
| Fault Injection | Remove `s3:PutObject` |
| Logging State During Failure | `IsLogging=true` |
| Root Cause | Incomplete S3 bucket policy |
| Remediation | Restore CloudTrail write permission |
| Verification | Recovery event delivered to S3 |
| Cleanup | Delete trail, bucket, and test parameters |

### Objectives

- Understand how CloudTrail delivers logs to S3.
- Configure a secure CloudTrail S3 destination.
- Understand resource-based S3 permissions.
- Learn the CloudTrail service principal.
- Understand `s3:GetBucketAcl` and `s3:PutObject`.
- Understand `aws:SourceArn` restrictions.
- Generate and compare correct and broken policies.
- Simulate a CloudTrail permission failure.
- Inspect CloudTrail delivery status.
- Differentiate active logging from successful delivery.
- Identify the exact missing permission.
- Restore the correct configuration.
- Verify newly delivered CloudTrail log files.
- Analyze GZIP-compressed JSON using Python.
- Perform root cause analysis.
- Document incident evidence.
- Clean up test resources safely.

---

## 2. Production Incident Scenario

### Incident Description

A company uses AWS CloudTrail to monitor administrative activity across its AWS infrastructure.

CloudTrail delivers management-event logs to an Amazon S3 bucket.

The Cloud Security team relies on these log files to investigate configuration changes, identify suspicious operations, and maintain historical audit records.

During a routine audit, engineers discover that the trail is no longer delivering new log files.

The trail's configuration still exists.

`GetTrailStatus` reports that logging is enabled:

```json
{
  "IsLogging": true
}
```

The S3 bucket is also available.

The engineer initially considers several possible causes:

- CloudTrail logging disabled.
- Incorrect S3 destination.
- Missing event selectors.
- CloudTrail delivery delay.
- Incorrect S3 bucket policy.
- KMS encryption failure.

The engineer investigates the S3 bucket policy and discovers that its CloudTrail write statement has been removed.

The policy still permits `s3:GetBucketAcl`, but it no longer allows `s3:PutObject`.

As a result, CloudTrail cannot upload new audit log objects.

The engineer restores the required permission and verifies delivery using a newly generated management event.

### Incident Symptoms

- CloudTrail trail exists.
- Trail logging is enabled.
- Destination S3 bucket exists.
- S3 public access is blocked.
- Management-event selectors are configured.
- Bucket policy contains `s3:GetBucketAcl`.
- Bucket policy is missing `s3:PutObject`.
- S3 delivery is interrupted.
- `LatestDeliveryError` may report an access-related error.
- Previous CloudTrail log objects may still be present.

### Business Impact

- Audit log delivery interruption.
- Incomplete historical security records in S3.
- Reduced incident response visibility.
- Compliance monitoring concerns.
- Delayed investigation of AWS API activity.
- Potentially increased CloudTrail retry-related costs.
- Operational uncertainty about audit logging health.

### Objective

Identify and correct the CloudTrail S3 bucket policy misconfiguration, then verify that the trail can deliver newly recorded management events.

---

## 3. AWS Architecture

### Normal CloudTrail Logging Architecture

```text
                     AWS Account
                          |
                          v
                   AWS API Activity
                          |
             +------------+------------+
             |            |            |
             v            v            v
           AWS CLI      Console       SDK
             |            |            |
             +------------+------------+
                          |
                          v
                     AWS CloudTrail
                          |
                          v
                 cloudtrail-lab04-trail
                          |
                          v
                 IsLogging = true
                          |
                          v
                Management Event Logs
                          |
                          v
                  S3 Bucket Policy
                          |
               +----------+----------+
               |                     |
               v                     v
        s3:GetBucketAcl        s3:PutObject
               |                     |
               +----------+----------+
                          |
                          v
                     Amazon S3
                          |
                          v
                AWSLogs/<account-id>/
                          |
                          v
                 Compressed JSON Logs
```

### Broken Architecture

```text
AWS Management Events
          |
          v
CloudTrail Trail
          |
          v
IsLogging = true
          |
          v
S3 Delivery Attempt
          |
          v
S3 Bucket Policy Evaluation
          |
          v
s3:GetBucketAcl = Allowed
s3:PutObject    = Missing
          |
          v
Write Request Not Authorized
          |
          v
S3 Delivery Failure
          |
          v
Audit Log Delivery Interrupted
```

### Recovered Architecture

```text
AWS Management Events
          |
          v
CloudTrail Trail
          |
          v
IsLogging = true
          |
          v
Corrected S3 Bucket Policy
          |
          v
s3:PutObject = Allowed
          |
          v
Amazon S3
          |
          v
CloudTrail Log Files
          |
          v
Recovery Event Verified
```

### Architecture Components

| Component | Responsibility |
|---|---|
| CloudTrail | Records selected AWS API activity |
| CloudTrail Trail | Configures ongoing log collection and delivery |
| S3 Bucket | Stores audit log files |
| Bucket Policy | Grants CloudTrail destination access |
| CloudTrail Service Principal | Identifies CloudTrail in the S3 policy |
| SSE-S3 | Encrypts stored log objects |
| Parameter Store | Generates test management events |
| AWS CLI | Creates, investigates, and remediates the infrastructure |
| Python | Generates policies and verifies delivered logs |
| Bash | Runs and automates CLI commands |

---

## 4. Understanding CloudTrail S3 Bucket Policies

### What Is an S3 Bucket Policy?

An S3 bucket policy is a resource-based IAM policy that controls access to an Amazon S3 bucket and its objects.

CloudTrail needs authorization through the destination bucket policy to deliver log files.

### What Is the CloudTrail Service Principal?

```text
cloudtrail.amazonaws.com
```

This principal identifies the CloudTrail service when evaluating the S3 bucket policy.

### Required Bucket Permissions

**Permission 1 — `s3:GetBucketAcl`**

Allows CloudTrail to inspect the destination bucket ACL.

**Permission 2 — `s3:PutObject`**

Allows CloudTrail to write compressed audit log objects to S3.

Without the appropriate write permission, log delivery fails.

### What Is `aws:SourceArn`?

`aws:SourceArn` is a condition key that can restrict access to requests originating from a particular CloudTrail trail.

Example:

```text
arn:aws:cloudtrail:us-east-1:ACCOUNT_ID:trail/cloudtrail-lab04-trail
```

This helps ensure that the bucket policy grants access only to the intended trail.

### What Is `s3:x-amz-acl`?

The standard CloudTrail bucket policy includes a condition requiring the `bucket-owner-full-control` ACL value during log object delivery.

Example:

```json
{
  "s3:x-amz-acl": "bucket-owner-full-control"
}
```

### What Is an S3 Resource ARN?

Bucket-level ARN:

```text
arn:aws:s3:::BUCKET_NAME
```

Object-level ARN:

```text
arn:aws:s3:::BUCKET_NAME/AWSLogs/ACCOUNT_ID/*
```

The policy needs the correct ARN type for each operation.

### What Is `IsLogging`?

This field indicates whether the trail is logging.

It does not guarantee successful delivery to S3.

### What Is `LatestDeliveryError`?

This CloudTrail status field reports S3 delivery errors encountered during delivery attempts.

It is useful when troubleshooting invalid destinations or permissions.

### What Is `LatestDeliveryTime`?

The timestamp of the latest successful delivery of CloudTrail log files to the S3 destination.

### CloudTrail Event History vs. Trail Delivery

CloudTrail Event history provides supported recent management events independently of a particular trail.

A trail delivers selected activity to S3.

Therefore, an event appearing in Event history does not prove that a specific trail delivered it successfully.

---

## 5. Prerequisites and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL2 Ubuntu.
- Bash.
- Python 3.
- CloudTrail administrative permissions for lab resources.
- S3 bucket management permissions.
- Systems Manager Parameter Store permissions.
- Git and GitHub.

### Required AWS API Permissions

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

s3:CreateBucket
s3:HeadBucket
s3:PutBucketPolicy
s3:GetBucketPolicy
s3:PutBucketTagging
s3:GetBucketTagging
s3:PutPublicAccessBlock
s3:GetPublicAccessBlock
s3:PutBucketEncryption
s3:GetEncryptionConfiguration
s3:ListBucket
s3:GetObject
s3:DeleteObject
s3:DeleteBucket

ssm:PutParameter
ssm:GetParameter
ssm:DeleteParameter
```

### Safety Rules

- Never modify production CloudTrail bucket policies for this exercise.
- Never stop or delete existing organization trails.
- Use a dedicated, uniquely named lab bucket.
- Verify ownership tags before fault injection.
- Save the correct bucket policy before applying the broken one.
- Keep the permission failure brief.
- Do not log or commit credentials.
- Do not publish raw unredacted CloudTrail records.
- Delete only resources created for the lab.

### Cost Considerations

Possible AWS costs include S3 storage, S3 requests, and additional copies of CloudTrail management events.

CloudTrail may retry failed log deliveries. Keep the fault-injection interval short and clean up the trail after completing verification.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Create the Lab Directory

From the repository root:

```bash
mkdir -p 04-cloudtrail-bucket-policy-error
cd 04-cloudtrail-bucket-policy-error
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

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab04"

export TRAIL_NAME="cloudtrail-lab04-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export UNIQUE_SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export BUCKET_NAME="cloudtrail-lab04-${ACCOUNT_ID}-${UNIQUE_SUFFIX}"

export PARAMETER_PREFIX="/cloudtrail-lab04"
```

### Step 4 — Verify Environment Variables

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$TRAIL_ARN"
echo "$BUCKET_NAME"
```

### Step 5 — Save Resource Identifiers

Create `lab04-resources.env`:

```bash
cat > lab04-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export BUCKET_NAME="$BUCKET_NAME"
export PARAMETER_PREFIX="$PARAMETER_PREFIX"
EOF
```

Restore variables when reopening a terminal:

```bash
source lab04-resources.env
```

### Step 6 — Inspect Existing Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

Confirm that `cloudtrail-lab04-trail` does not already exist.

---

## 7. Create the S3 Log Destination

### Step 1 — Create S3 Bucket

```bash
aws s3api create-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Step 2 — Block Public Access

```bash
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region "$AWS_REGION"
```

### Step 3 — Enable SSE-S3 Encryption

```bash
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --region "$AWS_REGION"
```

### Step 4 — Add Project Tag

```bash
aws s3api put-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Bucket

```bash
aws s3api head-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Security Settings

```bash
aws s3api get-public-access-block \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

```bash
aws s3api get-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Expected Configuration

| Component | Expected State |
|---|---|
| S3 bucket | Available |
| AWS Region | us-east-1 |
| Public access | Blocked |
| Server-side encryption | SSE-S3 |
| Ownership tag | Present |

---

## 8. Generate Correct and Broken Bucket Policies

### Purpose

We create two versions of the S3 bucket policy.

**Correct policy:**

- Allows `s3:GetBucketAcl`.
- Allows `s3:PutObject`.
- Uses the CloudTrail service principal.
- Restricts access using `aws:SourceArn`.

**Broken policy:**

- Allows `s3:GetBucketAcl`.
- Omits `s3:PutObject`.

This creates a controlled permission failure without changing trail configuration.

### Step 1 — Create Policy Generator

Save as `generate-policies.py`:

```python
#!/usr/bin/env python3

import json
import os

bucket = os.environ["BUCKET_NAME"]
account_id = os.environ["ACCOUNT_ID"]
trail_arn = os.environ["TRAIL_ARN"]

correct_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::{bucket}",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": trail_arn
                }
            }
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": (
                f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*"
            ),
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": trail_arn
                }
            }
        }
    ]
}

broken_policy = {
    "Version": "2012-10-17",
    "Statement": [
        correct_policy["Statement"][0]
    ]
}

with open("correct-bucket-policy.json", "w") as file:
    json.dump(correct_policy, file, indent=2)

with open("broken-bucket-policy.json", "w") as file:
    json.dump(broken_policy, file, indent=2)

print("Created correct-bucket-policy.json")
print("Created broken-bucket-policy.json")
```

### Step 2 — Generate Policies

```bash
python3 generate-policies.py
```

Expected:

```text
Created correct-bucket-policy.json
Created broken-bucket-policy.json
```

### Step 3 — Inspect Correct Policy

```bash
python3 -m json.tool correct-bucket-policy.json
```

### Step 4 — Inspect Broken Policy

```bash
python3 -m json.tool broken-bucket-policy.json
```

### Step 5 — Compare Policies

```bash
diff -u \
  correct-bucket-policy.json \
  broken-bucket-policy.json
```

Expected: the broken policy omits the entire `AWSCloudTrailWrite` permission statement.

### Step 6 — Apply Correct Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --policy file://correct-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 7 — Verify Applied Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

---

## 9. Create and Configure the CloudTrail Trail

### Step 1 — Create Trail

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$BUCKET_NAME" \
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

### Step 3 — Configure Management Events

```bash
aws cloudtrail put-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --event-selectors \
    ReadWriteType=All,IncludeManagementEvents=true \
  --region "$AWS_REGION"
```

### Step 4 — Verify Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 5 — Start Logging

```bash
aws cloudtrail start-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Trail Status

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

Delivery fields may initially be absent.

### Step 7 — Verify S3 Destination

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,Region:HomeRegion}' \
  --output table \
  --region "$AWS_REGION"
```

Expected: `cloudtrail-lab04-trail` references the dedicated lab bucket.

---

## 10. Verify Healthy Baseline Delivery

### Step 1 — Generate Baseline Management Event

```bash
export BASELINE_PARAMETER="${PARAMETER_PREFIX}/baseline-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$BASELINE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "healthy-cloudtrail-delivery" \
  --region "$AWS_REGION"
```

### Step 2 — Save Parameter Name

```bash
printf '%s\n' "$BASELINE_PARAMETER" \
  > lab04-baseline-parameter.txt
```

### Step 3 — Inspect S3 Log Objects

```bash
aws s3 ls \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected: `.json.gz` log files after asynchronous delivery.

### Step 4 — Inspect Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 5 — Create Verification Script

Save as `verify-cloudtrail-logs.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import os
import sys

if len(sys.argv) != 4:
    print(
        "Usage: python3 verify-cloudtrail-logs.py "
        "LOG_DIRECTORY PARAMETER_NAME OUTPUT_FILE"
    )
    sys.exit(2)

directory = sys.argv[1]
parameter_name = sys.argv[2]
output_file = sys.argv[3]

matches = []

files = glob.glob(
    os.path.join(directory, "**", "*.json.gz"),
    recursive=True
)

print(f"Scanning {len(files)} CloudTrail files")

for filename in files:
    with gzip.open(filename, "rt") as file:
        data = json.load(file)

    for event in data.get("Records", []):
        request = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "PutParameter"
            and event.get("eventSource") == "ssm.amazonaws.com"
            and request.get("name") == parameter_name
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "eventSource": event.get("eventSource"),
                "awsRegion": event.get("awsRegion"),
                "parameterName": request.get("name"),
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    print("ERROR: Target event not found in downloaded logs")
    sys.exit(1)

print("SUCCESS: Verified CloudTrail event in S3 logs")
```

### Step 6 — Download Baseline Logs

```bash
mkdir -p evidence/baseline-logs

aws s3 cp \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/baseline-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 7 — Verify Exact Baseline Event

```bash
python3 verify-cloudtrail-logs.py \
  evidence/baseline-logs \
  "$BASELINE_PARAMETER" \
  lab04-baseline-s3-evidence.json
```

Expected:

```text
SUCCESS: Verified CloudTrail event in S3 logs
```

If the event has not arrived, inspect delivery status, download the latest files, and run the verification again.

### Step 8 — Save Healthy Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab04-before-failure-status.json
```

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  > lab04-before-bucket-policy.json
```

### Baseline Summary

| Component | Expected |
|---|---|
| Trail | Exists |
| IsLogging | true |
| S3 bucket | Available |
| Bucket policy | Correct |
| GetBucketAcl | Allowed |
| PutObject | Allowed |
| Baseline management event | Created |
| Baseline S3 delivery | Verified |

Do not proceed to fault injection until the baseline event is found in S3.

---

## 11. Fault Injection — Remove CloudTrail Write Permission

### Safety Check

Verify ownership of both the trail and bucket.

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

```bash
aws s3api get-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Confirm that both belong to:

```text
CloudTrail-Troubleshooting-Lab04
```

### Step 1 — Apply Broken Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --policy file://broken-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 2 — Verify Applied Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

The resulting policy permits `s3:GetBucketAcl` but does not grant CloudTrail `s3:PutObject`.

### Step 3 — Save Broken Policy Evidence

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  > lab04-broken-bucket-policy.json
```

### Step 4 — Generate Failure-Period Event

```bash
export FAILURE_PARAMETER="${PARAMETER_PREFIX}/failure-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$FAILURE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "bucket-policy-error" \
  --region "$AWS_REGION"
```

### Step 5 — Save Parameter Name

```bash
printf '%s\n' "$FAILURE_PARAMETER" \
  > lab04-failure-parameter.txt
```

### Step 6 — Check Trail Delivery Status

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

The `LatestDeliveryError` field may report an S3 authorization failure after CloudTrail attempts delivery.

The exact AWS error message and timing depend on service behavior.

### Step 7 — Save Failure Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab04-delivery-failure-status.json
```

### Broken-State Summary

| Component | Expected State |
|---|---|
| Trail | Exists |
| IsLogging | true |
| S3 bucket | Exists |
| Event selectors | Configured |
| GetBucketAcl | Allowed |
| PutObject | Missing |
| Audit delivery | Failing after attempted delivery |
| LatestDeliveryError | May report permission error |
| Root cause | Bucket policy misconfiguration |

Previously delivered S3 objects may still be present. Their existence does not prove that delivery succeeded after applying the broken policy.

---

<WritingBlock id="58315" variant="document"># Lab 04 — README.md (Sections 12–21)

## 12. Investigate the S3 Delivery Failure

### Step 1 — Verify Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,Region:HomeRegion}' \
  --output table \
  --region "$AWS_REGION"
```

Expected: the trail still points to the correct Lab 04 S3 bucket.

### Step 2 — Confirm the Bucket Exists

```bash
aws s3api head-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Expected: successful response.

This rules out the missing-bucket problem demonstrated in Lab 03.

### Step 3 — Verify Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected: read and write management events are configured.

### Step 4 — Inspect Trail Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION"
```

Focus on:

```text
IsLogging
LatestDeliveryTime
LatestDeliveryError
```

### Step 5 — Compare Bucket Policies

```bash
diff -u \
  correct-bucket-policy.json \
  broken-bucket-policy.json
```

The most important finding is that the broken policy omits the `AWSCloudTrailWrite` statement.

### Step 6 — Inspect the Applied Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Verify the missing `s3:PutObject` permission.

### Step 7 — Inspect CloudTrail Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab04-event-history-during-failure.json
```

CloudTrail Event history is separate from the dedicated trail's S3 delivery.

The test operation may appear in Event history even while its delivery to the trail's S3 destination is failing.

### Investigation Matrix

| Investigation | Finding |
|---|---|
| Trail exists | Yes |
| Trail logging | Enabled |
| Destination bucket | Exists |
| Event selectors | Correct |
| S3 encryption | SSE-S3 |
| Bucket public access | Blocked |
| Bucket policy | Incomplete |
| CloudTrail write permission | Missing |
| S3 delivery | Failing |
| Root cause | Missing `s3:PutObject` |

### Investigation Conclusion

The failure is caused by the S3 bucket policy rather than disabled CloudTrail logging, a missing S3 bucket, or incorrect event selectors.

---

## 13. Root Cause Analysis

### Root Cause

The destination bucket policy was replaced with an incomplete policy.

The correct policy contained two important permissions:

```text
s3:GetBucketAcl
s3:PutObject
```

The broken policy retained only:

```text
s3:GetBucketAcl
```

As a result, CloudTrail could inspect the destination bucket ACL but did not have the required bucket-policy authorization to write new log objects.

The trail continued to report `IsLogging=true`, but its S3 delivery pipeline was interrupted.

### Root Cause Flow

```text
AWS API Activity
       |
       v
CloudTrail Trail
       |
       v
IsLogging = true
       |
       v
Management Event Collection
       |
       v
S3 Delivery Attempt
       |
       v
S3 Bucket Policy Evaluation
       |
       v
Missing s3:PutObject Permission
       |
       v
Write Request Not Authorized
       |
       v
CloudTrail Delivery Failure
       |
       v
Audit Log Delivery Interrupted
```

### Five Whys Analysis

**Why 1 — Why were new audit files not delivered?**

CloudTrail could not write log objects to S3.

**Why 2 — Why couldn't CloudTrail write objects?**

The bucket policy was missing `s3:PutObject`.

**Why 3 — Why was the permission missing?**

The correct bucket policy was replaced with an incomplete version.

**Why 4 — Why was the trail still shown as enabled?**

CloudTrail logging state and successful S3 delivery are separate operational conditions.

**Why 5 — How can this incident be prevented?**

Use validated infrastructure configurations, restrict bucket-policy changes, monitor audit delivery failures, and verify log delivery after changes.

### Root Cause Summary

| Component | Finding |
|---|---|
| Incident | INC-CT-004 |
| Service | AWS CloudTrail |
| Destination | Amazon S3 |
| Logging State | Enabled |
| Bucket Availability | Healthy |
| Fault | Removed `s3:PutObject` |
| Root Cause | Incomplete S3 bucket policy |
| Remediation | Restore CloudTrail write permission |
| Verification | New event delivered to S3 |

---

## 14. Remediation — Restore the Correct S3 Policy

### Step 1 — Review the Correct Policy

```bash
python3 -m json.tool correct-bucket-policy.json
```

Verify that the policy has:

- `cloudtrail.amazonaws.com` service principal.
- `s3:GetBucketAcl` on the bucket.
- `s3:PutObject` on the expected log object path.
- `aws:SourceArn` restriction.
- `s3:x-amz-acl` condition.

### Step 2 — Restore the Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --policy file://correct-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 3 — Verify the Restored Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Expected: both required CloudTrail permission statements are present.

### Step 4 — Save Remediation Evidence

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  > lab04-restored-bucket-policy.json
```

### Step 5 — Verify Logging Is Still Enabled

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

We do not need to restart trail logging because it was not stopped.

### Remediation Comparison

| Configuration | Broken | Recovered |
|---|---|---|
| Trail logging | Enabled | Enabled |
| S3 destination | Available | Available |
| Bucket policy | Incomplete | Correct |
| GetBucketAcl | Allowed | Allowed |
| PutObject | Missing | Allowed |
| Delivery | Failing | Ready for verification |

---

## 15. Verify S3 Delivery Recovery

### Step 1 — Generate a Fresh Recovery Event

```bash
export RECOVERY_PARAMETER="${PARAMETER_PREFIX}/recovery-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$RECOVERY_PARAMETER" \
  --type String \
  --tier Standard \
  --value "cloudtrail-delivery-restored" \
  --region "$AWS_REGION"
```

### Step 2 — Save the Resource Name

```bash
printf '%s\n' "$RECOVERY_PARAMETER" \
  > lab04-recovery-parameter.txt
```

### Step 3 — Inspect Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

The latest successful delivery time should eventually advance once new logs are delivered.

A previously reported error may remain in the status output, so verify the actual log files before declaring recovery.

### Step 4 — List S3 Log Objects

```bash
aws s3 ls \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected: new `.json.gz` CloudTrail log files after successful delivery.

### Step 5 — Download Recovery Logs

```bash
mkdir -p evidence/recovery-logs

aws s3 cp \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/recovery-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Exact Recovery Event

```bash
python3 verify-cloudtrail-logs.py \
  evidence/recovery-logs \
  "$RECOVERY_PARAMETER" \
  lab04-recovery-s3-evidence.json
```

Expected after delivery:

```text
SUCCESS: Verified CloudTrail event in S3 logs
```

If the event isn't found, inspect delivery status and download the newest CloudTrail log objects before retrying.

### Step 7 — Inspect Recovery Evidence

```bash
python3 -m json.tool lab04-recovery-s3-evidence.json
```

Check:

| Event Field | Expected |
|---|---|
| eventName | PutParameter |
| eventSource | ssm.amazonaws.com |
| awsRegion | us-east-1 |
| parameterName | Recovery parameter |
| eventID | Present |
| eventTime | After remediation |
| sourceFile | Downloaded CloudTrail log |

### Step 8 — Save Final Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab04-final-trail-status.json
```

### Before-and-After Verification

| Investigation | Baseline | Broken | Recovered |
|---|---|---|---|
| Trail exists | Yes | Yes | Yes |
| IsLogging | true | true | true |
| S3 bucket exists | Yes | Yes | Yes |
| GetBucketAcl | Allowed | Allowed | Allowed |
| PutObject | Allowed | Missing | Allowed |
| Policy | Correct | Broken | Restored |
| Log delivery | Working | Failing | Working |
| Exact test event in S3 | Baseline verified | Not expected during failure | Recovery verified |

### Final Success Criteria

The incident is resolved when:

1. The correct bucket policy is restored.
2. The trail reports `IsLogging=true`.
3. The recovery `PutParameter` call succeeds.
4. New CloudTrail log objects arrive in S3.
5. The Python verification script identifies the exact recovery event.
6. The findings and evidence are documented.

---

## 16. Other CloudTrail Bucket Policy Failure Scenarios

The missing `s3:PutObject` permission is the primary issue in this lab, but several other policy errors can interrupt CloudTrail delivery.

### Scenario A — Missing GetBucketAcl

CloudTrail cannot perform the expected bucket ACL check.

### Scenario B — Incorrect S3 Object ARN

The `s3:PutObject` resource ARN does not match the actual destination path.

Example of an incorrect path:

```text
arn:aws:s3:::BUCKET_NAME/IncorrectPrefix/*
```

### Scenario C — Incorrect SourceArn

The policy restricts access to a different trail ARN.

The CloudTrail service request does not match the condition.

### Scenario D — Wrong Service Principal

The policy grants access to the wrong service.

For CloudTrail, the expected principal is:

```text
cloudtrail.amazonaws.com
```

### Scenario E — Explicit Deny

A deny statement can override an otherwise valid allow statement.

### Scenario F — Incorrect S3 Key Prefix

The bucket policy permits one prefix, while the trail is configured to deliver log files under another prefix.

### Scenario G — KMS Encryption Permissions

The S3 policy may be correct, but CloudTrail cannot use the configured KMS key.

This is investigated separately in Lab 05.

### Troubleshooting Matrix

| Symptom | Possible Cause | Investigation |
|---|---|---|
| GetBucketAcl failure | Missing ACL permission | Bucket policy |
| PutObject failure | Missing write permission | Bucket policy |
| AccessDenied | Explicit deny or missing allow | Policy evaluation |
| Invalid source ARN | Wrong trail ARN | `aws:SourceArn` |
| Wrong destination path | Incorrect object ARN | Resource statement |
| S3 bucket missing | Deleted bucket | HeadBucket |
| IsLogging=false | Trail stopped | GetTrailStatus |
| KMS error | Encryption configuration | KMS policy and trail settings |

---

## 17. Production Troubleshooting Best Practices

### Troubleshooting Checklist

1. Confirm the AWS account.
2. Confirm the AWS Region.
3. Identify the affected CloudTrail trail.
4. Verify the trail exists.
5. Check `IsLogging`.
6. Inspect the destination bucket name.
7. Confirm the S3 bucket exists.
8. Retrieve the bucket policy.
9. Verify the CloudTrail service principal.
10. Verify `s3:GetBucketAcl`.
11. Verify `s3:PutObject`.
12. Check the object resource ARN.
13. Check `aws:SourceArn`.
14. Check the ACL condition.
15. Review explicit deny statements.
16. Inspect `LatestDeliveryError`.
17. Review management-event selectors.
18. Compare working and broken configurations.
19. Restore the required permission.
20. Generate a fresh management event.
21. Verify the event in delivered S3 logs.
22. Document root cause and remediation.
23. Clean up temporary resources.

### Recommended Production Investigation Workflow

```text
CloudTrail S3 Logs Missing
          |
          v
Verify Trail Logging State
          |
          v
Inspect S3 Destination
          |
          v
Confirm Bucket Exists
          |
          v
Retrieve Bucket Policy
          |
          v
Verify Service Principal
          |
          v
Inspect GetBucketAcl Permission
          |
          v
Inspect PutObject Permission
          |
          v
Verify Resource and Conditions
          |
          v
Identify Policy Misconfiguration
          |
          v
Restore Correct Policy
          |
          v
Generate Fresh Management Event
          |
          v
Verify Event in S3
          |
          v
Document Incident
```

### Security Recommendations

- Restrict CloudTrail S3 write permissions to the intended trail.
- Block public access to audit buckets.
- Use encryption for audit log storage.
- Restrict who can modify bucket policies.
- Monitor changes to audit infrastructure.
- Preserve important audit logs.
- Use S3 Versioning or Object Lock where appropriate.
- Enable CloudTrail log file integrity validation when required.
- Avoid excessive permissions such as broad wildcard principals.
- Protect production trails from unauthorized modification.

### Operational Recommendations

Use infrastructure as code and policy reviews to reduce configuration drift.

Monitor CloudTrail delivery errors and unexpected changes to S3 bucket policies.

After modifying audit infrastructure, verify end-to-end log delivery rather than only checking configuration values.

---

## 18. AWS Resource Cleanup

**Warning:** Delete only the dedicated Lab 04 resources.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm the project tag.

### Step 2 — Verify Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Confirm:

```text
Project=CloudTrail-Troubleshooting-Lab04
```

### Step 3 — Stop Lab Logging

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 4 — Delete Lab Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Trail Deletion

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

### Step 6 — Delete Test Parameters

```bash
for FILE in \
  lab04-baseline-parameter.txt \
  lab04-failure-parameter.txt \
  lab04-recovery-parameter.txt
do
  if [[ -f "$FILE" ]]; then
    PARAMETER=$(cat "$FILE")

    case "$PARAMETER" in
      /cloudtrail-lab04/*)
        aws ssm delete-parameter \
          --name "$PARAMETER" \
          --region "$AWS_REGION"
        ;;
      *)
        echo "Skipping unexpected resource: $PARAMETER"
        ;;
    esac
  fi
done
```

### Step 7 — Delete Lab S3 Objects

```bash
aws s3 rm "s3://${BUCKET_NAME}/" \
  --recursive \
  --region "$AWS_REGION"
```

Execute only after confirming the bucket is the dedicated Lab 04 bucket.

### Step 8 — Delete the Bucket

```bash
aws s3api delete-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Step 9 — Verify Bucket Deletion

```bash
aws s3api head-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Expected: bucket not found.

### Cleanup Summary

| Resource | Expected State |
|---|---|
| Dedicated CloudTrail trail | Deleted |
| Lab S3 bucket | Deleted |
| Baseline parameter | Deleted |
| Failure parameter | Deleted |
| Recovery parameter | Deleted |
| Existing production trails | Unchanged |
| Existing audit buckets | Unchanged |
| EC2 instances | None created |
| KMS keys | None created |
| VPC resources | None created |

---

## 19. Interview Questions and Answers

### Q1. What causes CloudTrail S3 bucket policy errors?

Missing permissions, incorrect resource ARNs, incorrect principals, mismatched condition keys, or explicit deny statements.

### Q2. What permissions does CloudTrail normally require in an S3 bucket policy?

` s3:GetBucketAcl ` and ` s3:PutObject `.

### Q3. What is the CloudTrail service principal?

`cloudtrail.amazonaws.com`.

### Q4. Why is `aws:SourceArn` important?

It restricts access to requests associated with an expected trail.

### Q5. What is the purpose of `s3:x-amz-acl`?

It checks the expected ACL value on CloudTrail object-delivery requests.

### Q6. What does `IsLogging=true` mean?

The trail is enabled for logging. It does not guarantee successful S3 delivery.

### Q7. How do you identify CloudTrail delivery problems?

Use `GetTrailStatus` to inspect logging state, delivery timestamps, and reported S3 errors.

### Q8. How do you inspect the S3 bucket policy?

```bash
aws s3api get-bucket-policy \
  --bucket YOUR_BUCKET_NAME
```

### Q9. How do you restore a correct policy?

Use `PutBucketPolicy` with a validated policy document.

### Q10. Can CloudTrail Event history work while trail delivery fails?

Yes. Event history is independent of the dedicated trail's S3 delivery.

### Q11. Why should engineers verify a fresh event in S3?

Because successful configuration does not guarantee that the complete logging pipeline works.

### Q12. What is the difference between Lab 03 and Lab 04?

Lab 03 investigates a deleted S3 destination. Lab 04 investigates an existing S3 destination with insufficient CloudTrail permissions.

### Q13. How do you prevent CloudTrail bucket policy misconfigurations?

Use policy reviews, infrastructure as code, least privilege, monitoring, and verification after changes.

### Q14. Can an explicit deny override an allow?

Yes. An applicable explicit deny overrides an allow.

### Q15. How would you describe this lab in an interview?

I created a dedicated CloudTrail trail with a private, encrypted S3 bucket and a restricted bucket policy.

I verified that the trail was enabled and successfully delivered a management event.

Then I intentionally removed the `s3:PutObject` permission from the bucket policy.

CloudTrail remained enabled, but its destination policy no longer authorized new log delivery.

I investigated the failure using GetTrailStatus, DescribeTrails, and GetBucketPolicy.

After comparing the healthy and broken policies, I identified the missing write permission as the root cause.

I restored the correct policy and generated a new management event.

Finally, I used Python to inspect downloaded CloudTrail JSON logs and verify that the recovery event reached the S3 bucket.

I documented the before-and-after evidence and deleted the temporary resources.

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
│   ├── README.md
│   ├── generate-policies.py
│   ├── verify-cloudtrail-logs.py
│   ├── correct-bucket-policy.json
│   ├── broken-bucket-policy.json
│   ├── lab04-resources.env
│   ├── lab04-baseline-parameter.txt
│   ├── lab04-failure-parameter.txt
│   ├── lab04-recovery-parameter.txt
│   ├── lab04-before-failure-status.json
│   ├── lab04-before-bucket-policy.json
│   ├── lab04-baseline-s3-evidence.json
│   ├── lab04-broken-bucket-policy.json
│   ├── lab04-delivery-failure-status.json
│   ├── lab04-event-history-during-failure.json
│   ├── lab04-restored-bucket-policy.json
│   ├── lab04-recovery-s3-evidence.json
│   ├── lab04-final-trail-status.json
│   │
│   └── evidence/
│       ├── baseline-logs/
│       └── recovery-logs/
│
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
| `README.md` | Complete troubleshooting documentation |
| `generate-policies.py` | Generates correct and broken policies |
| `verify-cloudtrail-logs.py` | Verifies exact events in S3 logs |
| `correct-bucket-policy.json` | Healthy policy |
| `broken-bucket-policy.json` | Intentionally misconfigured policy |
| `lab04-resources.env` | Local resource identifiers |
| `lab04-baseline-parameter.txt` | Baseline test resource |
| `lab04-failure-parameter.txt` | Fault-period resource |
| `lab04-recovery-parameter.txt` | Recovery test resource |
| `lab04-before-failure-status.json` | Healthy trail status |
| `lab04-before-bucket-policy.json` | Original policy evidence |
| `lab04-baseline-s3-evidence.json` | Verified baseline event |
| `lab04-broken-bucket-policy.json` | Misconfigured policy evidence |
| `lab04-delivery-failure-status.json` | Fault-period status |
| `lab04-event-history-during-failure.json` | Event history investigation |
| `lab04-restored-bucket-policy.json` | Remediated policy evidence |
| `lab04-recovery-s3-evidence.json` | Verified recovery event |
| `lab04-final-trail-status.json` | Final trail status |
| `evidence/` | Downloaded baseline and recovery logs |

### GitHub Evidence Guidelines

Use actual AWS CLI responses for all evidence.

Do not invent delivery errors, event IDs, timestamps, or verification results.

Raw CloudTrail records can contain AWS account IDs, principal ARNs, source IP addresses, user agents, and request details.

Review files carefully before publishing.

For a public portfolio, prefer the README, Python scripts, generic policy examples, and redacted evidence summaries.

### Recommended `.gitignore`

```gitignore
__pycache__/
*.pyc
.venv/
.env
**/lab04-resources.env
**/evidence/baseline-logs/
**/evidence/recovery-logs/
```

---

## 21. Lessons Learned and Skills Demonstrated

### Lessons Learned

This lab demonstrates how a CloudTrail S3 delivery pipeline can fail even when the trail remains enabled and the destination bucket is available.

We created a dedicated CloudTrail trail and configured a secure S3 destination.

We enabled management-event logging and verified successful baseline delivery.

Next, we intentionally removed the CloudTrail `s3:PutObject` permission from the bucket policy.

The trail remained active, but the bucket policy was no longer sufficient for CloudTrail log delivery.

We investigated the problem using AWS CLI and compared the healthy and broken policies.

The investigation identified the missing write permission as the root cause.

We restored the original bucket policy and generated a fresh management event.

We then used a Python script to search the compressed CloudTrail JSON logs and verify delivery.

Finally, we documented the root cause, remediation, and recovery, then removed the temporary AWS resources.

**Key Lesson:** CloudTrail logging state, S3 bucket availability, and successful log delivery are different operational checks. A complete investigation must verify the bucket policy and confirm that actual audit events reach the destination.

### Skills Demonstrated

- AWS CloudTrail
- Amazon S3
- S3 bucket policy configuration
- Resource-based IAM policies
- CloudTrail service principals
- `s3:GetBucketAcl`
- `s3:PutObject`
- IAM condition keys
- `aws:SourceArn`
- `s3:x-amz-acl`
- AWS CLI v2
- Linux Bash
- Python 3
- JSON parsing
- GZIP log inspection
- CloudTrail management events
- S3 delivery troubleshooting
- Security configuration analysis
- Fault injection
- Root cause analysis
- Remediation verification
- Audit log investigation
- AWS resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-004 |
| Scenario | CloudTrail Bucket Policy Error |
| Trail | cloudtrail-lab04-trail |
| Region | us-east-1 |
| Trail Type | Single-Region |
| S3 Destination | Dedicated private bucket |
| Logging During Failure | Enabled |
| Bucket During Failure | Available |
| Broken Permission | Missing `s3:PutObject` |
| Root Cause | Incomplete bucket policy |
| Remediation | Restore write permission |
| Recovery Test | PutParameter |
| Recovery Evidence | Event found in S3 logs |
| Cleanup | Trail, bucket, and test parameters deleted |
| Incident Status | Resolved after delivery verification |

**Key Takeaway:** CloudTrail S3 delivery depends on correctly configured resource-based permissions. Cloud Engineers and Cloud Security Engineers must understand how service principals, bucket resource ARNs, and IAM condition keys affect audit log delivery.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail S3 Bucket Policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- [CloudTrail Troubleshooting](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-troubleshooting.html)
- [AWS CLI — GetTrailStatus](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-trail-status.html)
- [AWS CLI — DescribeTrails](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/describe-trails.html)
- [AWS CLI — GetBucketPolicy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [AWS CLI — PutBucketPolicy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
- [AWS CLI — DeleteTrail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/delete-trail.html)