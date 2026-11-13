# Lab 03 — CloudTrail S3 Delivery Failure

## Overview

This lab demonstrates how to troubleshoot an AWS CloudTrail trail that is actively logging but cannot deliver audit log files to its configured Amazon S3 destination.

AWS CloudTrail is an important service for recording AWS API activity, investigating security incidents, and maintaining audit logs.

Organizations commonly configure CloudTrail trails to deliver management and data events to Amazon S3 for long-term storage and security analysis.

However, an active CloudTrail trail does not always guarantee successful log delivery.

In this lab, we simulate a production incident where CloudTrail continues running, but its configured S3 destination bucket is missing.

We begin by creating a dedicated CloudTrail trail, an encrypted private S3 bucket, and a restricted bucket policy.

We configure management-event logging and generate test API activity using AWS Systems Manager Parameter Store.

After verifying normal S3 log delivery, we intentionally delete the dedicated lab S3 bucket while leaving the CloudTrail trail active.

The trail continues to report `IsLogging=true`, but CloudTrail cannot deliver new log files to the missing destination.

We investigate the trail configuration, S3 bucket availability, event selectors, delivery timestamps, and delivery errors.

After identifying the missing S3 bucket as the root cause, we create a replacement bucket, configure the required CloudTrail permissions, and update the trail using `UpdateTrail`.

We then generate a fresh management API event and verify that the event appears in the replacement S3 bucket.

Finally, we save the incident evidence and remove all temporary AWS resources.

**Troubleshooting Workflow:**

CloudTrail Trail Creation → Secure S3 Bucket → Bucket Policy Configuration → Management Event Logging → Baseline Delivery Verification → Delete S3 Destination → Delivery Failure → AWS CLI Investigation → Root Cause Analysis → Create Replacement S3 Bucket → UpdateTrail → Recovery Event Generation → S3 Delivery Verification → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-003 |
| Difficulty | Intermediate to Advanced |
| Primary AWS Service | AWS CloudTrail |
| Supporting Services | Amazon S3, AWS Systems Manager |
| AWS Region | `us-east-1` |
| Local Environment | WSL Ubuntu |
| Interface | AWS CLI v2 |
| Scripting Languages | Bash, Python 3 |
| Trail Name | `cloudtrail-lab03-trail` |
| Trail Type | Single-Region |
| Organization Trail | No |
| Multi-Region Trail | No |
| Original S3 Bucket | Unique generated bucket |
| Recovery S3 Bucket | Separate unique generated bucket |
| S3 Encryption | SSE-S3 |
| Public Access | Blocked |
| Log File Validation | Disabled for this lab |
| Event Category | Management events |
| Management Event Type | Read and write |
| Test API Operation | `PutParameter` |
| Intentional Fault | Delete original S3 destination |
| Logging State During Failure | `IsLogging=true` |
| Expected Delivery State | S3 delivery failure |
| Root Cause | Missing destination bucket |
| Remediation | Create new bucket and update trail |
| Recovery API | `UpdateTrail` |
| Verification | Find new management event in S3 |
| Cleanup | Delete trail, S3 buckets, and test parameters |

### Lab Objectives

- Understand CloudTrail S3 delivery.
- Create a private S3 bucket.
- Configure S3 server-side encryption.
- Create a restricted CloudTrail bucket policy.
- Create and configure a CloudTrail trail.
- Configure management-event selectors.
- Generate real AWS management API activity.
- Verify successful baseline log delivery.
- Simulate an unavailable S3 log destination.
- Distinguish trail logging from log delivery.
- Investigate `LatestDeliveryError`.
- Inspect CloudTrail destination configuration.
- Identify S3 delivery failures.
- Restore a valid S3 destination.
- Update a CloudTrail trail.
- Verify delivery of a new management event.
- Analyze compressed CloudTrail JSON files.
- Perform root cause analysis.
- Document recovery evidence.
- Clean up temporary AWS resources.

---

## 2. Production Incident Scenario

### Incident Description

A company uses AWS CloudTrail to record management API operations in its cloud environment.

CloudTrail delivers audit logs to an Amazon S3 bucket for security monitoring and investigation.

The Cloud Security team expects management events to be delivered continuously.

During a routine audit, engineers discover that new CloudTrail log files are no longer arriving in the designated S3 bucket.

The engineer checks the CloudTrail trail status.

The trail reports that logging is enabled.

However, delivery to the S3 destination is failing.

Initially, the team considers several possible causes:

- Trail logging may have been disabled.
- The S3 bucket may be inaccessible.
- The bucket policy may be incorrect.
- Event selectors may not include the required operations.
- The S3 destination may have been deleted.
- CloudTrail delivery may be delayed.

The engineer investigates the trail configuration and discovers that the original destination bucket no longer exists.

Although the trail is still active, it continues referencing the missing S3 bucket.

This creates an audit log delivery interruption.

The engineer provisions a replacement S3 bucket, configures its security settings and CloudTrail permissions, and updates the trail destination.

After the change, a new management event is generated.

The engineer verifies that the event appears in the replacement S3 bucket.

### Incident Symptoms

- CloudTrail trail exists.
- Trail logging remains enabled.
- `IsLogging=true`.
- Management-event selectors are configured.
- Original S3 destination is missing.
- CloudTrail cannot deliver logs to the configured bucket.
- `LatestDeliveryError` may report an S3 delivery problem.
- The latest successful delivery timestamp may become stale.
- CloudTrail Event history remains available independently.
- Audit log delivery resumes after destination recovery.

### Business Impact

An S3 delivery failure can cause:

- Interruptions to centralized audit log collection.
- Missing or delayed security evidence.
- Reduced visibility into AWS API activity.
- Problems with compliance monitoring.
- Delays during security investigations.
- Incomplete audit records in the configured destination.
- Increased operational risk.
- Potential retry-related costs.

### Objective

Identify the cause of the CloudTrail S3 delivery failure, restore a valid destination, and verify that a newly generated management event is successfully delivered.

---

## 3. AWS Architecture

### Normal CloudTrail S3 Delivery Architecture

```text
                       AWS Account
                            |
                            v
                      AWS API Activity
                            |
                +-----------+-----------+
                |           |           |
                v           v           v
             AWS CLI     Console       SDK
                |           |           |
                +-----------+-----------+
                            |
                            v
                      AWS CloudTrail
                            |
                            v
                     Lab-Owned Trail
                   cloudtrail-lab03-trail
                            |
                            v
                  Management Event Selector
                            |
                            v
                      IsLogging = true
                            |
                            v
                    CloudTrail Delivery
                            |
                            v
                       Amazon S3
                            |
                            v
                 AWSLogs/<account-id>/
                            |
                            v
                    Compressed JSON Logs
                            |
                            v
                    Security Investigation
```

### Architecture Before Fault Injection

```text
AWS Management API Calls
          |
          v
CloudTrail Trail
          |
          v
IsLogging = true
          |
          v
Management Events Selected
          |
          v
Original S3 Bucket
          |
          v
CloudTrail Log Files
          |
          v
Successful Audit Delivery
```

### Broken Architecture

```text
AWS Management API Calls
          |
          v
CloudTrail Trail
          |
          v
IsLogging = true
          |
          v
Delivery Attempt
          |
          v
Original S3 Bucket Deleted
          |
          v
Destination Unavailable
          |
          v
S3 Delivery Failure
          |
          v
LatestDeliveryError
          |
          v
Audit Log Delivery Interrupted
```

### Architecture After Remediation

```text
AWS Management API Calls
          |
          v
CloudTrail Trail
          |
          v
UpdateTrail
          |
          v
Replacement S3 Bucket
          |
          v
Restricted Bucket Policy
          |
          v
CloudTrail Log Delivery
          |
          v
Compressed JSON Logs
          |
          v
Recovery Event Verified
```

### Architecture Components

| Component | Purpose |
|---|---|
| AWS CloudTrail | Records selected AWS API activity |
| CloudTrail Trail | Configures ongoing audit logging |
| Amazon S3 | Stores CloudTrail audit logs |
| Original S3 Bucket | Initial destination used for fault injection |
| Recovery S3 Bucket | New destination used to restore delivery |
| S3 Bucket Policy | Authorizes CloudTrail to deliver logs |
| SSE-S3 | Encrypts stored audit files |
| Systems Manager Parameter Store | Generates test API events |
| AWS CLI | Investigates and remediates the incident |
| Python | Generates bucket policies and examines logs |
| Bash | Configures resources and automates commands |
| JSON Evidence | Stores incident investigation results |

---

## 4. Understanding CloudTrail S3 Delivery

### What Is CloudTrail S3 Delivery?

A CloudTrail trail delivers selected AWS API activity to a configured Amazon S3 bucket.

CloudTrail writes compressed JSON log files containing event records.

The destination is specified in the trail's `S3BucketName` setting.

### What Does IsLogging Mean?

`IsLogging` indicates whether the trail is actively logging.

```text
IsLogging = true   → Logging is enabled
IsLogging = false  → Logging is stopped
```

However, `IsLogging=true` does not guarantee successful S3 delivery.

### What Is LatestDeliveryError?

`LatestDeliveryError` is a field returned by `GetTrailStatus`.

It reports an S3 log delivery error experienced by CloudTrail.

The exact error depends on the delivery problem.

A missing or inaccessible bucket may cause a delivery error to be reported after CloudTrail attempts delivery.

### What Is LatestDeliveryTime?

`LatestDeliveryTime` identifies the most recent successful delivery timestamp for log files sent to S3.

It helps engineers determine whether delivery is progressing.

### What Is S3BucketName?

`S3BucketName` identifies the S3 destination configured for a CloudTrail trail.

It can be inspected using `DescribeTrails`.

### What Is UpdateTrail?

`UpdateTrail` changes configuration settings on an existing trail.

In this lab, we use it to replace the original S3 destination with a new bucket.

### What Is a CloudTrail Bucket Policy?

A CloudTrail destination bucket must authorize the CloudTrail service to perform the necessary S3 operations.

Required permissions commonly include:

- `s3:GetBucketAcl`
- `s3:PutObject`

The policy should restrict access using the expected CloudTrail trail ARN.

### What Is the CloudTrail Service Principal?

The service principal is:

`cloudtrail.amazonaws.com`

It represents the AWS CloudTrail service in resource-based permissions.

### What Is the AWSLogs Directory?

CloudTrail commonly stores delivered log files under a path such as:

```text
AWSLogs/
  <account-id>/
    CloudTrail/
      <region>/
        <year>/
          <month>/
            <day>/
              <log-files>.json.gz
```

### What Is the Difference Between Event History and Trail Delivery?

CloudTrail Event history provides recent supported management events independently of a particular trail.

A trail delivers selected events to an S3 destination.

An S3 delivery failure does not automatically mean that CloudTrail Event history is unavailable.

---

## 5. Prerequisites and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL Ubuntu.
- Bash.
- Python 3.
- CloudTrail permissions.
- Amazon S3 permissions.
- Systems Manager permissions.
- Git and GitHub.

### AWS Permissions

```text
sts:GetCallerIdentity

cloudtrail:CreateTrail
cloudtrail:DescribeTrails
cloudtrail:GetTrailStatus
cloudtrail:GetEventSelectors
cloudtrail:PutEventSelectors
cloudtrail:StartLogging
cloudtrail:StopLogging
cloudtrail:UpdateTrail
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
s3:ListBucket
s3:GetObject
s3:DeleteObject
s3:DeleteBucket

ssm:PutParameter
ssm:GetParameter
ssm:DeleteParameter
```

### Security Rules

- Use only the dedicated Lab 03 trail.
- Never delete production audit buckets.
- Never modify organization trails.
- Keep the test S3 buckets private.
- Enable bucket encryption.
- Restrict CloudTrail S3 permissions.
- Verify tags before deleting resources.
- Use synthetic parameter values.
- Avoid publishing raw CloudTrail account activity.
- Save necessary evidence before fault injection.
- Delete the lab resources after testing.

### Cost Considerations

Potential AWS charges include:

- S3 storage.
- S3 API requests.
- Additional copies of CloudTrail management events.
- CloudTrail delivery retries.

Keep the simulated delivery failure brief.

CloudTrail can retry failed delivery attempts, and prolonged delivery failures may create additional charges.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Navigate to Repository

```bash
cd ~/aws-cloudtrail-troubleshooting-labs
```

### Step 2 — Create Lab Directory

```bash
mkdir -p 03-cloudtrail-s3-delivery-failure

cd 03-cloudtrail-s3-delivery-failure
```

### Step 3 — Verify AWS CLI

```bash
aws --version
aws sts get-caller-identity
```

### Step 4 — Configure Variables

```bash
export AWS_REGION="us-east-1"
export AWS_PAGER=""

export ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text)

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab03"

export TRAIL_NAME="cloudtrail-lab03-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export UNIQUE_SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export ORIGINAL_BUCKET="cloudtrail-lab03-original-${ACCOUNT_ID}-${UNIQUE_SUFFIX}"

export RECOVERY_BUCKET="cloudtrail-lab03-recovery-${ACCOUNT_ID}-${UNIQUE_SUFFIX}"

export PARAMETER_PREFIX="/cloudtrail-lab03"
```

### Step 5 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$ORIGINAL_BUCKET"
echo "$RECOVERY_BUCKET"
```

### Step 6 — Save Resource Information

Create `lab03-resources.env`:

```bash
cat > lab03-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export ORIGINAL_BUCKET="$ORIGINAL_BUCKET"
export RECOVERY_BUCKET="$RECOVERY_BUCKET"
export PARAMETER_PREFIX="$PARAMETER_PREFIX"
EOF
```

Restore the variables in another terminal session using:

```bash
source lab03-resources.env
```

### Step 7 — Inspect Existing Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

Confirm that the chosen lab trail name does not identify an existing production or organization trail.

---

## 7. Create the Original S3 Bucket

### Step 1 — Create Bucket

```bash
aws s3api create-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

### Step 2 — Block Public Access

```bash
aws s3api put-public-access-block \
  --bucket "$ORIGINAL_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region "$AWS_REGION"
```

### Step 3 — Enable SSE-S3

```bash
aws s3api put-bucket-encryption \
  --bucket "$ORIGINAL_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --region "$AWS_REGION"
```

### Step 4 — Tag Bucket

```bash
aws s3api put-bucket-tagging \
  --bucket "$ORIGINAL_BUCKET" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Bucket

```bash
aws s3api head-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Encryption

```bash
aws s3api get-bucket-encryption \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

### Step 7 — Verify Public Access Block

```bash
aws s3api get-public-access-block \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

### Expected Configuration

| Item | Expected |
|---|---|
| Bucket | Available |
| Region | us-east-1 |
| Public Access | Blocked |
| Encryption | SSE-S3 |
| Project Tag | Present |

---

## 8. Configure CloudTrail S3 Permissions

### Purpose

CloudTrail needs permission to check the destination bucket and write audit log files.

We use a Python script to generate a bucket policy for either the original bucket or the replacement bucket.

### Step 1 — Create Policy Generator

Save as `generate-bucket-policy.py`:

```python
#!/usr/bin/env python3

import json
import os
import sys

if len(sys.argv) != 3:
    print(
        "Usage: python3 generate-bucket-policy.py "
        "BUCKET_NAME OUTPUT_FILE"
    )
    sys.exit(1)

bucket = sys.argv[1]
output_file = sys.argv[2]

account_id = os.environ["ACCOUNT_ID"]
trail_arn = os.environ["TRAIL_ARN"]

policy = {
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

with open(output_file, "w") as file:
    json.dump(policy, file, indent=2)

print(f"Generated policy: {output_file}")
```

### Step 2 — Generate Original Policy

```bash
python3 generate-bucket-policy.py \
  "$ORIGINAL_BUCKET" \
  original-bucket-policy.json
```

### Step 3 — Inspect Policy

```bash
python3 -m json.tool original-bucket-policy.json
```

### Step 4 — Apply Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$ORIGINAL_BUCKET" \
  --policy file://original-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 5 — Verify Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$ORIGINAL_BUCKET" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

### Expected Permissions

| Permission | Purpose |
|---|---|
| `s3:GetBucketAcl` | Allows CloudTrail bucket ACL inspection |
| `s3:PutObject` | Allows CloudTrail log delivery |
| `aws:SourceArn` | Restricts access to the lab trail |
| `s3:x-amz-acl` | Applies required object ACL condition |

**Important:** The bucket policy remains correctly configured during this lab. Lab 04 focuses specifically on bucket-policy failures.

---

## 9. Create and Start the CloudTrail Trail

### Step 1 — Create Trail

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$ORIGINAL_BUCKET" \
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

### Step 4 — Start Logging

```bash
aws cloudtrail start-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,Region:HomeRegion,MultiRegion:IsMultiRegionTrail}' \
  --output table \
  --region "$AWS_REGION"
```

### Step 6 — Verify Logging Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

`IsLogging=true`

### Step 7 — Save Initial Evidence

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-initial-trail.json
```

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-initial-status.json
```

---

## 10. Verify Successful Baseline Log Delivery

### Step 1 — Generate Baseline Management Event

```bash
export BASELINE_PARAMETER="${PARAMETER_PREFIX}/baseline-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$BASELINE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "baseline-success" \
  --region "$AWS_REGION"
```

### Step 2 — Save Parameter Name

```bash
printf '%s\n' "$BASELINE_PARAMETER" > lab03-baseline-parameter.txt
```

### Step 3 — Verify Trail Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 4 — List Delivered S3 Logs

```bash
aws s3 ls \
  "s3://${ORIGINAL_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected: compressed JSON log files after CloudTrail delivery.

### Step 5 — Download Baseline Logs

```bash
mkdir -p evidence/baseline-logs
```

```bash
aws s3 cp \
  "s3://${ORIGINAL_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/baseline-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Downloaded Files

```bash
find evidence/baseline-logs -type f -name "*.json.gz"
```

### Step 7 — Save Baseline Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-before-failure-status.json
```

### Baseline Verification

| Component | Expected |
|---|---|
| Trail | Available |
| IsLogging | true |
| Original S3 Bucket | Available |
| S3 Bucket Policy | Valid |
| Management Events | Configured |
| Baseline API Call | Successful |
| CloudTrail S3 Log Delivery | Successful |
| Local Log Evidence | Preserved |

**Important:** Confirm that baseline delivery has succeeded before deleting the original destination.

---

## 11. Fault Injection — Delete the S3 Destination

### Safety Warning

This phase intentionally deletes the disposable Lab 03 S3 bucket while the dedicated trail remains enabled.

Never perform these steps against a production or shared CloudTrail log bucket.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

### Step 2 — Verify Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

Both resources must be associated with:

`CloudTrail-Troubleshooting-Lab03`

### Step 3 — Confirm Bucket Name

```bash
echo "$ORIGINAL_BUCKET"
```

Verify that it begins with:

`cloudtrail-lab03-original-`

### Step 4 — Delete Original Bucket Objects

```bash
aws s3 rm "s3://${ORIGINAL_BUCKET}/" \
  --recursive \
  --region "$AWS_REGION"
```

The original log files are removed from the disposable bucket.

The local baseline copies remain available.

### Step 5 — Delete Original Bucket

```bash
aws s3api delete-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

If the bucket isn't empty, check for remaining lab-generated objects before retrying.

CloudTrail may deliver an additional file while deletion is in progress.

### Step 6 — Verify Bucket Is Missing

```bash
aws s3api head-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

Expected: a not-found response.

A generic access-denied response does not conclusively prove deletion.

### Step 7 — Verify Logging Remains Active

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

`IsLogging=true`

### Step 8 — Generate a Test Event During Failure

```bash
export FAILURE_PARAMETER="${PARAMETER_PREFIX}/failure-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$FAILURE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "generated-during-s3-failure" \
  --region "$AWS_REGION"
```

### Step 9 — Save Failure Parameter

```bash
printf '%s\n' "$FAILURE_PARAMETER" > lab03-failure-parameter.txt
```

### Step 10 — Inspect Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION"
```

CloudTrail may report a delivery error after attempting to write to the missing bucket.

The exact error message depends on AWS service behavior.

### Step 11 — Save Failure Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-delivery-failure-status.json
```

### Expected Fault State

| Component | Expected |
|---|---|
| CloudTrail Trail | Exists |
| IsLogging | true |
| Management Events | Configured |
| Original S3 Bucket | Missing |
| S3 Delivery | Failing |
| LatestDeliveryError | May report failure |
| Root Cause | Missing S3 destination |

---

## 12. Investigate CloudTrail S3 Delivery Failure

### Step 1 — Inspect Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,Region:HomeRegion}' \
  --output json \
  --region "$AWS_REGION"
```

Expected: the trail still references the deleted original bucket.

### Step 2 — Inspect Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION"
```

Check:

```text
IsLogging
LatestDeliveryTime
LatestDeliveryError
```

### Step 3 — Inspect Management Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected: management-event collection remains configured.

### Step 4 — Verify S3 Bucket Availability

```bash
aws s3api head-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

Expected: the destination is unavailable because the lab bucket was deleted.

### Step 5 — Investigate Delivery Error

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

A delivery error may become visible after CloudTrail attempts delivery.

Do not invent an error string if the service has not yet reported one.

### Step 6 — Verify Event History Separately

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab03-event-history-during-failure.json
```

CloudTrail Event history operates independently from the trail's S3 delivery.

Therefore, an API event appearing in Event history does not prove successful log delivery to the trail's destination.

### Investigation Matrix

| Investigation | Expected Finding |
|---|---|
| Trail Exists | Yes |
| IsLogging | true |
| S3 Destination Configured | Yes |
| S3 Destination Exists | No |
| Event Selectors | Configured |
| S3 Delivery | Failing |
| Event History | Independently available |
| Root Cause | Destination bucket deleted |

---

## 13. Root Cause Analysis

### Root Cause

The CloudTrail trail could not deliver new audit log files because its configured S3 destination bucket was deleted.

The trail continued to report:

`IsLogging=true`

This confirmed that logging remained enabled.

However, the S3 bucket referenced by the trail no longer existed.

CloudTrail therefore could not complete normal delivery to the configured destination.

The problem was not caused by disabled trail logging or missing management-event selectors.

The root cause was the unavailable S3 destination.

### Root Cause Flow

```text
CloudTrail Trail Created
          |
          v
Logging Enabled
          |
          v
Original S3 Bucket Configured
          |
          v
Baseline Delivery Successful
          |
          v
Original S3 Bucket Deleted
          |
          v
Trail Still References Old Bucket
          |
          v
CloudTrail Delivery Attempt
          |
          v
Destination Unavailable
          |
          v
S3 Delivery Failure
          |
          v
Audit Log Delivery Interrupted
```

### Five Whys

1. **Why were CloudTrail logs missing from S3?** The trail could not deliver them.
2. **Why couldn't CloudTrail deliver the logs?** The destination bucket was unavailable.
3. **Why was the bucket unavailable?** It had been deleted.
4. **Why did CloudTrail continue using the deleted bucket?** Its destination configuration still referenced that bucket.
5. **How was the problem resolved?** A new bucket was configured, and the trail destination was updated.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-003 |
| AWS Service | CloudTrail |
| Supporting Service | Amazon S3 |
| Logging Status | Enabled |
| Fault Injection | Delete original bucket |
| Failed Component | S3 log destination |
| Root Cause | Destination bucket missing |
| Remediation | Create replacement bucket |
| Recovery API | UpdateTrail |
| Verification | Fresh event delivered to S3 |

**Key Lesson:** A CloudTrail trail reporting `IsLogging=true` does not guarantee successful audit log delivery. Engineers must check the configured S3 destination, delivery status, and actual log objects.

---

## 14. Remediation — Create Replacement S3 Bucket

### Step 1 — Create Recovery Bucket

```bash
aws s3api create-bucket \
  --bucket "$RECOVERY_BUCKET" \
  --region "$AWS_REGION"
```

### Step 2 — Block Public Access

```bash
aws s3api put-public-access-block \
  --bucket "$RECOVERY_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region "$AWS_REGION"
```

### Step 3 — Enable SSE-S3

```bash
aws s3api put-bucket-encryption \
  --bucket "$RECOVERY_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --region "$AWS_REGION"
```

### Step 4 — Tag Recovery Bucket

```bash
aws s3api put-bucket-tagging \
  --bucket "$RECOVERY_BUCKET" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 5 — Generate Recovery Bucket Policy

```bash
python3 generate-bucket-policy.py \
  "$RECOVERY_BUCKET" \
  recovery-bucket-policy.json
```

### Step 6 — Inspect Recovery Policy

```bash
python3 -m json.tool recovery-bucket-policy.json
```

### Step 7 — Apply Recovery Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$RECOVERY_BUCKET" \
  --policy file://recovery-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 8 — Verify Recovery Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$RECOVERY_BUCKET" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

### Expected Recovery Bucket Configuration

| Component | Expected |
|---|---|
| New S3 Bucket | Available |
| Region | us-east-1 |
| Public Access | Blocked |
| Encryption | SSE-S3 |
| CloudTrail Permissions | Configured |
| Source ARN Restriction | Correct |
| Project Tag | Present |

---

## 15. Update Trail and Verify Recovery

### Step 1 — Update S3 Destination

```bash
aws cloudtrail update-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$RECOVERY_BUCKET" \
  --region "$AWS_REGION"
```

### Step 2 — Verify Updated Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,Region:HomeRegion}' \
  --output table \
  --region "$AWS_REGION"
```

Expected: the new recovery bucket is configured.

### Step 3 — Verify Logging Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

`IsLogging=true`

### Step 4 — Save Updated Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-after-remediation-trail.json
```

### Step 5 — Save Updated Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-after-remediation-status.json
```

### Step 6 — Generate Recovery Management Event

```bash
export RECOVERY_PARAMETER="${PARAMETER_PREFIX}/recovery-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$RECOVERY_PARAMETER" \
  --type String \
  --tier Standard \
  --value "s3-delivery-restored" \
  --region "$AWS_REGION"
```

### Step 7 — Save Recovery Parameter Name

```bash
printf '%s\n' "$RECOVERY_PARAMETER" > lab03-recovery-parameter.txt
```

### Step 8 — Inspect Recovery S3 Logs

```bash
aws s3 ls \
  "s3://${RECOVERY_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

CloudTrail delivery is asynchronous.

A newly generated event may not appear immediately.

### Step 9 — Check Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

A newer successful delivery timestamp supports recovery.

An older delivery error may remain in historical status fields, so actual S3 event verification is important.

### Step 10 — Download Recovery Logs

```bash
mkdir -p evidence/recovery-logs
```

```bash
aws s3 cp \
  "s3://${RECOVERY_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/recovery-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 11 — Create S3 Delivery Verification Script

Save as `verify-s3-delivery.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 4:
    print(
        "Usage: python3 verify-s3-delivery.py "
        "LOG_DIR PARAMETER_NAME OUTPUT_FILE"
    )
    sys.exit(2)

log_dir = sys.argv[1]
target_name = sys.argv[2]
output_file = sys.argv[3]

matches = []

for filename in glob.glob(
    f"{log_dir}/**/*.json.gz",
    recursive=True
):
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        request = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "PutParameter"
            and request.get("name") == target_name
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "awsRegion": event.get("awsRegion"),
                "parameterName": target_name,
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    print("Target event not yet found in S3 logs")
    sys.exit(1)

print("SUCCESS: Target CloudTrail event found in S3")
```

### Step 12 — Run Verification

```bash
python3 verify-s3-delivery.py \
  evidence/recovery-logs \
  "$RECOVERY_PARAMETER" \
  lab03-recovery-s3-evidence.json
```

Expected after successful delivery:

```text
SUCCESS: Target CloudTrail event found in S3
```

### Step 13 — Inspect Recovery Evidence

```bash
python3 -m json.tool lab03-recovery-s3-evidence.json
```

### Step 14 — Save Final Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab03-final-status.json
```

### Before and After Comparison

| Investigation | Before Failure | During Failure | After Recovery |
|---|---|---|---|
| Trail Exists | Yes | Yes | Yes |
| IsLogging | true | true | true |
| S3 Destination | Original bucket | Missing bucket | Recovery bucket |
| Event Selectors | Configured | Configured | Configured |
| Log Delivery | Working | Failing | Working |
| Latest Delivery | Successful | Stale or error | New successful delivery |
| Recovery Event in S3 | Not applicable | Not applicable | Verified |
| Root Cause | None | Missing destination | Corrected |
| Incident | Healthy | Active | Resolved |

**Recovery is confirmed when a fresh management event generated after remediation is found in the replacement CloudTrail S3 destination.**

---

## README.md — Final Sections (16–21)

Append the following sections immediately after Section 15 in the same `README.md` file.

<WritingBlock id="63822" variant="document">## 16. Understanding CloudTrail Delivery Failure Scenarios

CloudTrail S3 delivery failures can occur for several reasons.

Understanding these possibilities helps engineers avoid changing the wrong configuration.

### Scenario A — S3 Bucket Deleted

The destination bucket no longer exists.

Investigation:

```bash
aws s3api head-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

Remediation: Restore a valid S3 destination and update the trail if necessary.

### Scenario B — Incorrect Bucket Policy

The bucket exists, but CloudTrail does not have permission to deliver log objects.

Investigation:

```bash
aws s3api get-bucket-policy \
  --bucket "$RECOVERY_BUCKET" \
  --region "$AWS_REGION"
```

Remediation: Correct the CloudTrail bucket policy.

### Scenario C — Trail Logging Disabled

The trail reports:

`IsLogging=false`

Investigation:

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Remediation: Restart logging after confirming the change is authorized.

### Scenario D — KMS Encryption Failure

The trail uses an AWS KMS key that does not permit the operations CloudTrail requires.

Investigation:

- Inspect the trail encryption configuration.
- Verify the KMS key exists and is enabled.
- Review the key policy and permissions.
- Check CloudTrail delivery errors.

Remediation: Restore the required KMS permissions without granting excessive access.

### Scenario E — Incorrect Event Selectors

The trail is active and delivering logs, but the desired event category is not selected.

Investigation:

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Remediation: Configure the required event selectors.

### Scenario F — Delivery Delay

CloudTrail log delivery is asynchronous.

A recently generated event might not immediately appear in S3.

Investigation:

- Inspect the latest successful delivery time.
- Check delivery errors.
- Review log objects.
- Verify the exact event after delivery.

### Troubleshooting Comparison

| Symptom | Possible Cause | Investigation |
|---|---|---|
| `IsLogging=false` | Logging stopped | GetTrailStatus |
| `IsLogging=true`, no S3 delivery | Destination failure | GetTrailStatus |
| S3 bucket not found | Bucket deleted | HeadBucket |
| S3 access denied | Bucket policy issue | GetBucketPolicy |
| KMS-related error | Encryption permissions | KMS key policy |
| Selected events missing | Event selector configuration | GetEventSelectors |
| Recent event missing | Delivery delay | Timestamp and S3 inspection |
| Wrong S3 destination | Trail configuration | DescribeTrails |

---

## 17. Production Troubleshooting Best Practices

### CloudTrail S3 Delivery Troubleshooting Checklist

1. Identify the affected CloudTrail trail.
2. Confirm the AWS account and Region.
3. Verify that the trail exists.
4. Check `IsLogging`.
5. Inspect the configured S3 destination.
6. Verify that the bucket exists.
7. Inspect the bucket policy.
8. Verify the CloudTrail service principal.
9. Check required S3 permissions.
10. Inspect `LatestDeliveryError`.
11. Check `LatestDeliveryTime`.
12. Verify management-event selectors.
13. Investigate KMS encryption if configured.
14. Confirm the relevant API events occurred.
15. Identify the root cause.
16. Create or restore a valid S3 destination.
17. Apply the required access policy.
18. Update the trail configuration if needed.
19. Generate a fresh management event.
20. Confirm actual S3 log delivery.
21. Save before-and-after evidence.
22. Remove temporary test resources.

### Production Investigation Workflow

```text
CloudTrail S3 Logs Missing
            |
            v
Verify AWS Account and Region
            |
            v
Inspect CloudTrail Trail
            |
            v
Check IsLogging
            |
            v
Inspect S3 Destination
            |
            v
Verify Bucket Availability
            |
            v
Inspect Bucket Policy
            |
            v
Check Delivery Errors
            |
            v
Identify Root Cause
            |
            v
Apply Remediation
            |
            v
Generate Fresh API Event
            |
            v
Verify S3 Delivery
            |
            v
Document Incident
```

### Security Recommendations

- Protect CloudTrail destination buckets against accidental deletion.
- Use restricted S3 bucket policies.
- Block public access to audit logs.
- Enable appropriate server-side encryption.
- Restrict modification of production trails.
- Protect audit log retention settings.
- Consider S3 Versioning and Object Lock where required.
- Enable CloudTrail log file integrity validation when appropriate.
- Monitor unexpected changes to CloudTrail destinations.
- Apply least-privilege access to security logs.

### Operational Recommendations

- Monitor CloudTrail logging status.
- Monitor delivery errors.
- Review the latest delivery timestamps.
- Test configuration changes in isolated environments.
- Maintain deployment rollback procedures.
- Preserve incident evidence.
- Avoid changing multiple components before identifying the failure.
- Verify the complete delivery pipeline after remediation.

### Important Production Consideration

Deleting an audit bucket can permanently remove audit records if no additional protected copies exist.

This exercise uses a disposable S3 bucket only.

Production recovery should prioritize evidence preservation and approved recovery procedures.

---

## 18. AWS Resource Cleanup

**Warning:** Confirm all resources belong to Lab 03 before deleting them.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm:

`Project=CloudTrail-Troubleshooting-Lab03`

### Step 2 — Stop Lab Trail Logging

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 3 — Delete Lab Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Deleting the trail stops further delivery attempts by that trail.

### Step 4 — Verify Trail Deletion

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

### Step 5 — Delete Temporary SSM Parameters

```bash
for FILE in \
  lab03-baseline-parameter.txt \
  lab03-failure-parameter.txt \
  lab03-recovery-parameter.txt
do
  if [[ -f "$FILE" ]]; then
    PARAMETER=$(cat "$FILE")

    case "$PARAMETER" in
      /cloudtrail-lab03/*)
        aws ssm delete-parameter \
          --name "$PARAMETER" \
          --region "$AWS_REGION"
        ;;
      *)
        echo "Skipping unexpected parameter: $PARAMETER"
        ;;
    esac
  fi
done
```

### Step 6 — Verify Recovery Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$RECOVERY_BUCKET" \
  --region "$AWS_REGION"
```

Confirm the Lab 03 project tag.

### Step 7 — Delete Recovery Bucket Objects

```bash
aws s3 rm "s3://${RECOVERY_BUCKET}/" \
  --recursive \
  --region "$AWS_REGION"
```

Run this command only against the verified disposable bucket.

### Step 8 — Delete Recovery Bucket

```bash
aws s3api delete-bucket \
  --bucket "$RECOVERY_BUCKET" \
  --region "$AWS_REGION"
```

### Step 9 — Verify Recovery Bucket Deletion

```bash
aws s3api head-bucket \
  --bucket "$RECOVERY_BUCKET" \
  --region "$AWS_REGION"
```

Expected: bucket not found.

### Step 10 — Verify Original Bucket Remains Deleted

```bash
aws s3api head-bucket \
  --bucket "$ORIGINAL_BUCKET" \
  --region "$AWS_REGION"
```

Expected: original bucket not found.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| CloudTrail Lab Trail | Deleted |
| Original S3 Bucket | Deleted during fault injection |
| Recovery S3 Bucket | Deleted |
| Baseline SSM Parameter | Deleted |
| Failure SSM Parameter | Deleted |
| Recovery SSM Parameter | Deleted |
| Production Trails | Unchanged |
| CloudTrail Event History | Retained normally |
| EC2 Instances | None created |
| KMS Keys | None created |
| VPC Resources | None created |

---

## 19. Interview Questions and Answers

### Q1. What causes CloudTrail S3 delivery failures?

Possible causes include a missing S3 bucket, incorrect bucket permissions, encryption configuration problems, or an invalid destination configuration.

### Q2. What does IsLogging=true indicate?

It indicates the trail is enabled for logging, but it does not guarantee successful delivery to S3.

### Q3. Which command shows CloudTrail delivery errors?

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

### Q4. What is LatestDeliveryError?

A CloudTrail status field that reports an S3 log delivery error.

### Q5. What is LatestDeliveryTime?

The timestamp of the latest successful CloudTrail log file delivery to S3.

### Q6. How do you identify a trail's S3 destination?

Use:

```bash
aws cloudtrail describe-trails
```

### Q7. How do you verify whether the bucket exists?

```bash
aws s3api head-bucket \
  --bucket YOUR_BUCKET_NAME
```

Interpret 403 and 404 responses carefully because access restrictions can prevent definitive conclusions.

### Q8. How do you update a CloudTrail S3 destination?

```bash
aws cloudtrail update-trail \
  --name YOUR_TRAIL_NAME \
  --s3-bucket-name YOUR_NEW_BUCKET
```

### Q9. Why does CloudTrail require an S3 bucket policy?

The policy grants the CloudTrail service permission to check the bucket and deliver audit log objects.

### Q10. What permissions does CloudTrail commonly require?

`s3:GetBucketAcl` and `s3:PutObject`, restricted with appropriate conditions.

### Q11. Does stopping a trail delete the existing S3 logs?

No. Existing S3 objects remain unless independently deleted.

### Q12. Does an S3 delivery failure stop Event history?

No. Event history remains independent from the trail's S3 destination.

### Q13. Why verify a fresh event in S3 after remediation?

Because successful trail configuration does not conclusively prove the audit event was delivered.

### Q14. How can delivery failures affect cloud security?

They can interrupt centralized audit collection and create gaps in the evidence available for investigations.

### Q15. How would you explain this lab in an interview?

I created a dedicated CloudTrail trail with a private, encrypted S3 bucket and configured the required CloudTrail permissions.

After verifying normal log delivery, I intentionally deleted the disposable destination bucket while keeping the trail enabled.

I investigated CloudTrail using GetTrailStatus and DescribeTrails.

The trail still reported IsLogging=true, but its S3 destination was unavailable.

I identified the missing destination bucket as the root cause.

I created a replacement S3 bucket, configured the required bucket policy, and updated the trail using UpdateTrail.

I then generated a new Systems Manager PutParameter event.

Using Python, I examined the compressed CloudTrail JSON logs and verified that the recovery event was delivered to the replacement bucket.

Finally, I documented the findings and deleted the temporary AWS resources.

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
│   ├── README.md
│   ├── generate-bucket-policy.py
│   ├── verify-s3-delivery.py
│   ├── original-bucket-policy.json
│   ├── recovery-bucket-policy.json
│   ├── lab03-resources.env
│   ├── lab03-baseline-parameter.txt
│   ├── lab03-failure-parameter.txt
│   ├── lab03-recovery-parameter.txt
│   ├── lab03-initial-trail.json
│   ├── lab03-initial-status.json
│   ├── lab03-before-failure-status.json
│   ├── lab03-delivery-failure-status.json
│   ├── lab03-event-history-during-failure.json
│   ├── lab03-after-remediation-trail.json
│   ├── lab03-after-remediation-status.json
│   ├── lab03-recovery-s3-evidence.json
│   ├── lab03-final-status.json
│   │
│   └── evidence/
│       ├── baseline-logs/
│       └── recovery-logs/
│
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
| `README.md` | Complete troubleshooting documentation |
| `generate-bucket-policy.py` | Generates restricted CloudTrail bucket policies |
| `verify-s3-delivery.py` | Verifies exact events in S3 log files |
| `original-bucket-policy.json` | Initial bucket policy |
| `recovery-bucket-policy.json` | Replacement bucket policy |
| `lab03-resources.env` | Stores local resource identifiers |
| `lab03-baseline-parameter.txt` | Baseline test parameter name |
| `lab03-failure-parameter.txt` | Failure-period test parameter name |
| `lab03-recovery-parameter.txt` | Recovery test parameter name |
| `lab03-initial-trail.json` | Initial trail configuration |
| `lab03-initial-status.json` | Initial trail status |
| `lab03-before-failure-status.json` | Healthy delivery status |
| `lab03-delivery-failure-status.json` | Broken-state investigation |
| `lab03-event-history-during-failure.json` | Event history investigation |
| `lab03-after-remediation-trail.json` | Updated trail destination |
| `lab03-after-remediation-status.json` | Recovery logging status |
| `lab03-recovery-s3-evidence.json` | Verified S3 recovery event |
| `lab03-final-status.json` | Final trail delivery status |
| `evidence/` | Local CloudTrail log evidence |

### Evidence Guidelines

Use actual AWS CLI responses.

Do not fabricate delivery errors, event timestamps, CloudTrail event IDs, or S3 log files.

Raw CloudTrail logs may contain:

- AWS account IDs.
- IAM principal ARNs.
- Source IP addresses.
- API request information.
- Resource identifiers.

Review and redact sensitive fields before publishing them.

Do not publish unredacted CloudTrail logs from a real AWS environment.

### Suggested Git Ignore Entries

```gitignore
__pycache__/
*.pyc
.venv/
.env
**/lab03-resources.env
**/evidence/baseline-logs/
**/evidence/recovery-logs/
```

---

## 21. Lessons Learned and Skills Demonstrated

### Lessons Learned

This lab demonstrates how a CloudTrail trail can remain active while audit log delivery to Amazon S3 fails.

We created a dedicated CloudTrail trail and secured its destination S3 bucket.

We configured a valid bucket policy and enabled management-event collection.

After verifying normal delivery, we intentionally removed the disposable S3 destination.

The CloudTrail trail continued to report IsLogging=true, but the configured bucket was no longer available.

We investigated the issue using AWS CLI by checking the trail configuration, delivery status, management-event selectors, and S3 bucket availability.

The investigation identified the deleted destination bucket as the root cause.

We created a replacement S3 bucket with encryption, blocked public access, and the correct CloudTrail permissions.

We then updated the existing trail to use the replacement bucket.

To verify recovery, we generated a new management API event and searched the downloaded compressed CloudTrail log files using Python.

After confirming that the recovery event was delivered to S3, we documented the incident and deleted the lab resources.

**Key Lesson:** CloudTrail's active logging state and successful S3 delivery are different operational conditions. Engineers must verify the configured destination, delivery errors, and newly delivered log events before concluding that the audit logging pipeline is healthy.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail trail configuration
- CloudTrail S3 log delivery
- Amazon S3
- S3 bucket creation
- S3 bucket policy troubleshooting
- S3 server-side encryption
- S3 public access protection
- AWS CloudTrail UpdateTrail
- AWS CloudTrail GetTrailStatus
- AWS CloudTrail DescribeTrails
- CloudTrail management events
- CloudTrail event selectors
- AWS Systems Manager Parameter Store
- AWS CLI v2
- Linux Bash
- Python 3
- JSON processing
- GZIP audit log analysis
- AWS resource tagging
- Production-style fault injection
- Root cause analysis
- Incident recovery verification
- AWS resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-003 |
| Scenario | CloudTrail S3 Delivery Failure |
| Trail | cloudtrail-lab03-trail |
| Region | us-east-1 |
| Trail Type | Single-Region |
| IsLogging During Failure | true |
| Original Destination | Deleted lab bucket |
| Fault | S3 destination unavailable |
| Root Cause | Missing S3 bucket |
| Remediation | New S3 bucket + UpdateTrail |
| Recovery Destination | Replacement lab bucket |
| Management Events | Enabled |
| Verification API | PutParameter |
| Recovery Evidence | New event found in S3 logs |
| Cleanup | Trail, buckets, and parameters deleted |
| Incident Status | Resolved after verification |

**Key Takeaway:** Successful CloudTrail logging depends on both an active trail and a working destination. Cloud Engineers and Cloud Security Engineers should investigate `IsLogging`, `LatestDeliveryTime`, `LatestDeliveryError`, S3 availability, bucket permissions, and actual delivered events to diagnose audit pipeline failures.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Troubleshooting](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-troubleshooting.html)
- [CloudTrail S3 Bucket Policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- [AWS CLI — GetTrailStatus](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-trail-status.html)
- [AWS CLI — DescribeTrails](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/describe-trails.html)
- [AWS CLI — UpdateTrail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
- [AWS CLI — DeleteTrail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/delete-trail.html)
- [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/)