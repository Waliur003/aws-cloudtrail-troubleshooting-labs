# Lab 02 — CloudTrail Trail Logging Disabled

## Overview

This lab demonstrates how to investigate and resolve an AWS CloudTrail trail that has stopped recording new audit activity because logging was disabled.

AWS CloudTrail is an important security and auditing service that records supported AWS API operations. Organizations use CloudTrail to investigate account activity, monitor configuration changes, support incident response, and maintain audit records.

In this lab, we simulate a production incident where a dedicated CloudTrail trail stops logging AWS management events.

The trail configuration still exists, and its Amazon S3 destination bucket is available. However, the CloudTrail `GetTrailStatus` API reports:

```json
{
  "IsLogging": false
}
```

This indicates that logging is stopped for the trail.

We create a dedicated CloudTrail trail and a private S3 bucket. We configure the appropriate CloudTrail bucket policy, enable management-event logging, and generate test API activity using AWS Systems Manager Parameter Store.

After establishing the working logging configuration, we intentionally stop the trail using the `StopLogging` API.

We then investigate the trail configuration, logging status, event selectors, S3 destination, and CloudTrail Event history.

The investigation identifies the stopped logging state as the root cause.

We restore logging using `StartLogging`, generate a fresh management event, and verify that CloudTrail delivers the event to the designated S3 bucket.

Finally, we save troubleshooting evidence and delete the temporary CloudTrail, S3, and Parameter Store resources.

**Troubleshooting Workflow:**

CloudTrail Trail Creation → S3 Destination Configuration → Logging Enabled → Management Event Generation → StopLogging → IsLogging=false → Incident Investigation → Root Cause Analysis → StartLogging → Recovery Event Generation → S3 Delivery Verification → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-002 |
| Difficulty | Intermediate |
| Primary Service | AWS CloudTrail |
| Supporting Services | Amazon S3, AWS Systems Manager |
| AWS Region | `us-east-1` |
| Local Environment | WSL Ubuntu |
| Interface | AWS CLI v2 |
| Scripting Languages | Bash, Python 3 |
| Trail Name | `cloudtrail-lab02-trail` |
| Trail Type | Single-Region |
| Organization Trail | No |
| Multi-Region Trail | No |
| S3 Bucket | Unique generated lab bucket |
| S3 Encryption | SSE-S3 |
| Public Access | Blocked |
| Management Events | Read and write |
| Data Events | Not configured |
| Test API Operation | `PutParameter` |
| Fault Injection | `StopLogging` |
| Initial Logging Status | `true` |
| Broken Logging Status | `false` |
| Recovered Logging Status | `true` |
| Root Cause | CloudTrail logging disabled |
| Remediation | `StartLogging` |
| Verification | `GetTrailStatus` and delivered S3 log |
| Cleanup | Delete lab trail, parameters, and bucket |

### Lab Objectives

- Understand the difference between a CloudTrail trail and Event history.
- Create a dedicated CloudTrail S3 destination.
- Configure a restricted CloudTrail bucket policy.
- Create a single-Region CloudTrail trail.
- Configure management-event selectors.
- Start and stop CloudTrail logging.
- Investigate the `IsLogging` field.
- Inspect logging and delivery timestamps.
- Generate real management API events.
- Understand CloudTrail S3 delivery behavior.
- Troubleshoot a stopped trail.
- Restore logging using AWS CLI.
- Verify delivery of a new management event.
- Analyze compressed CloudTrail JSON log files.
- Document incident evidence.
- Safely remove temporary AWS resources.

---

## 2. Production Incident Scenario

### Incident Description

A company uses AWS CloudTrail to record important AWS management API operations.

CloudTrail delivers its audit logs to a private Amazon S3 bucket so that security and operations engineers can investigate account activity.

The Cloud Security team expects the trail to remain active continuously.

During a routine audit, the team discovers that the trail is no longer actively recording new events.

The trail still exists in the AWS account.

Its Amazon S3 bucket is available, and the management event selectors remain correctly configured.

However, `GetTrailStatus` reports that logging is disabled.

The team initially considers several possible causes, including S3 delivery failures, bucket policy errors, or missing event selectors.

An engineer investigates the trail configuration and discovers that the trail was stopped using CloudTrail's logging controls.

The engineer confirms that the main issue is the logging state rather than a missing S3 bucket or incorrect event selector.

The engineer restarts the trail, generates a new management event, and verifies that the event is delivered to Amazon S3.

### Incident Symptoms

- CloudTrail trail exists.
- Destination S3 bucket exists.
- Management event selectors are configured.
- `IsLogging` returns `false`.
- A stop-logging timestamp is present.
- New events are not collected by the stopped trail.
- Existing audit log files may still exist in S3.
- CloudTrail Event history remains available.
- Audit coverage through the trail is interrupted.

### Business Impact

- Gaps in ongoing audit log collection.
- Reduced security visibility.
- Potentially incomplete incident investigations.
- Missing historical evidence in the dedicated trail.
- Compliance and governance concerns.
- Delayed detection of suspicious AWS operations.
- Increased risk of inaccurate audit conclusions.

### Objective

Identify why the CloudTrail trail stopped logging, restore the active logging state, and verify that a new AWS management event is delivered to the S3 destination.

---

## 3. AWS Architecture

### Normal CloudTrail Architecture

```text
                     AWS Account
                          |
                          v
                   AWS API Activity
                          |
            +-------------+-------------+
            |             |             |
            v             v             v
         AWS CLI      AWS Console     AWS SDK
            |             |             |
            +-------------+-------------+
                          |
                          v
                    AWS CloudTrail
                          |
                          v
                    Lab-Owned Trail
                  cloudtrail-lab02-trail
                          |
                          v
                Management Event Selectors
                          |
                          v
                    IsLogging = true
                          |
                          v
                  CloudTrail Log Delivery
                          |
                          v
                     Amazon S3
                          |
                          v
                   AWSLogs/<account>/
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
Event Collection Active
          |
          v
CloudTrail Log Delivery
          |
          v
Private S3 Audit Bucket
```

### Broken Architecture

```text
AWS Management API Calls
          |
          v
CloudTrail Trail
          |
          v
StopLogging Called
          |
          v
IsLogging = false
          |
          v
Trail Logging Stopped
          |
          v
No New Trail Collection
          |
          v
Audit Coverage Gap
```

### Architecture After Remediation

```text
AWS Management API Calls
          |
          v
CloudTrail Trail
          |
          v
StartLogging Called
          |
          v
IsLogging = true
          |
          v
New Events Collected
          |
          v
CloudTrail Delivery Resumes
          |
          v
Amazon S3 Audit Bucket
          |
          v
Recovery Event Verified
```

### Architecture Components

| Component | Purpose |
|---|---|
| AWS CloudTrail | Records selected AWS API activity |
| CloudTrail Trail | Controls ongoing event collection and S3 delivery |
| Amazon S3 | Stores delivered audit log files |
| S3 Bucket Policy | Authorizes CloudTrail log delivery |
| S3 SSE-S3 | Encrypts stored log objects |
| Systems Manager Parameter Store | Generates test management API events |
| AWS CLI | Creates, inspects, stops, and restores trail logging |
| Python | Searches downloaded CloudTrail JSON files |
| WSL Ubuntu | Local troubleshooting environment |

---

## 4. Understanding CloudTrail Logging

### What Is a CloudTrail Trail?

A CloudTrail trail is a configuration that records selected AWS events and delivers them to an Amazon S3 bucket.

A trail can collect management events and, when explicitly configured, supported data events.

### What Is CloudTrail Event History?

CloudTrail Event history provides access to the previous 90 days of supported management events in an AWS Region.

Event history does not require a trail.

Stopping a trail does not stop CloudTrail Event history.

### What Is IsLogging?

`IsLogging` is a field returned by `GetTrailStatus`.

It indicates whether the specified trail is currently logging.

```text
IsLogging = true   → Trail logging is active
IsLogging = false  → Trail logging is stopped
```

### What Is StartLogging?

`StartLogging` enables logging for an existing CloudTrail trail.

Example:

```bash
aws cloudtrail start-logging \
  --name cloudtrail-lab02-trail \
  --region us-east-1
```

### What Is StopLogging?

`StopLogging` stops event logging for an existing trail.

Example:

```bash
aws cloudtrail stop-logging \
  --name cloudtrail-lab02-trail \
  --region us-east-1
```

This command should never be used against a production security trail for testing.

### What Is GetTrailStatus?

`GetTrailStatus` returns information about the trail's logging and delivery state.

Important fields include:

| Field | Purpose |
|---|---|
| `IsLogging` | Whether trail logging is active |
| `StartLoggingTime` | Most recent logging start timestamp |
| `StopLoggingTime` | Most recent logging stop timestamp |
| `LatestDeliveryTime` | Latest successful S3 log delivery timestamp |
| `LatestDeliveryError` | Most recently reported S3 delivery error |

### What Is an Event Selector?

An event selector determines which event categories and operations a trail collects.

This lab configures management events for both read and write operations.

### What Is a Management Event?

Management events represent supported control-plane API activity.

In this lab, creating a Parameter Store parameter generates a `PutParameter` management event.

### What Is CloudTrail S3 Delivery?

CloudTrail delivers recorded events to an S3 destination as compressed JSON log files.

The delivery process is asynchronous.

A newly generated event may not appear immediately in the destination bucket.

### Can S3 Objects Arrive After Logging Is Stopped?

Yes.

CloudTrail may finish delivering previously collected events after the trail has been stopped.

Therefore, an S3 object created after `StopLogging` does not necessarily mean that logging remained active.

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
- Systems Manager Parameter Store permissions.
- Git and GitHub.

### Important AWS Permissions

```text
sts:GetCallerIdentity

cloudtrail:CreateTrail
cloudtrail:DescribeTrails
cloudtrail:ListTrails
cloudtrail:GetTrailStatus
cloudtrail:GetEventSelectors
cloudtrail:PutEventSelectors
cloudtrail:StartLogging
cloudtrail:StopLogging
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

- Use only the dedicated lab trail.
- Do not stop existing production trails.
- Do not modify organization trails.
- Keep the S3 bucket private.
- Use restricted CloudTrail bucket permissions.
- Do not publish credentials in test parameters.
- Do not delete unrelated S3 buckets.
- Verify tags before destructive operations.
- Redact sensitive CloudTrail records before publishing.
- Remove lab resources after testing.

### Cost Considerations

This lab can incur small charges for S3 storage and requests.

Additional copies of CloudTrail management events can also incur charges depending on other logging configurations in the account.

The lab does not create EC2 instances, RDS databases, or KMS keys.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Navigate to the Repository

```bash
cd ~/aws-cloudtrail-troubleshooting-labs
```

### Step 2 — Create the Lab Directory

```bash
mkdir -p 02-trail-logging-disabled
cd 02-trail-logging-disabled
```

### Step 3 — Verify AWS CLI

```bash
aws --version
aws sts get-caller-identity
```

### Step 4 — Configure Environment Variables

```bash
export AWS_REGION="us-east-1"
export AWS_PAGER=""

export ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text)

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab02"

export TRAIL_NAME="cloudtrail-lab02-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export BUCKET_NAME="cloudtrail-lab02-${ACCOUNT_ID}-$(date -u +%Y%m%d%H%M%S)"

export PARAMETER_PREFIX="/cloudtrail-lab02"
```

### Step 5 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$TRAIL_ARN"
echo "$BUCKET_NAME"
```

### Step 6 — Save Resource Identifiers

Create `lab02-resources.env`:

```bash
cat > lab02-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export BUCKET_NAME="$BUCKET_NAME"
export PARAMETER_PREFIX="$PARAMETER_PREFIX"
export PROJECT_TAG="$PROJECT_TAG"
EOF
```

To restore these variables in another terminal session:

```bash
source lab02-resources.env
```

### Step 7 — Inspect Existing Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

Confirm that the lab trail name does not identify any existing production trail.

---

## 7. Create and Secure the S3 Log Bucket

### Step 1 — Create Bucket

```bash
aws s3api create-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

For `us-east-1`, no LocationConstraint is required.

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

### Step 6 — Verify Encryption

```bash
aws s3api get-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Step 7 — Verify Public Access Block

```bash
aws s3api get-public-access-block \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Expected Configuration

| Setting | Expected |
|---|---|
| Bucket | Exists |
| AWS Region | us-east-1 |
| Public Access | Blocked |
| Encryption | SSE-S3 |
| Project Tag | Present |

---

## 8. Configure CloudTrail S3 Bucket Policy

### Purpose

CloudTrail requires permission to check the bucket ACL and deliver audit log objects.

The bucket policy must authorize the CloudTrail service principal.

The policy also restricts access to the dedicated trail using `aws:SourceArn`.

### Step 1 — Generate Policy

Create `cloudtrail-bucket-policy.json`:

```bash
python3 - <<'PY'
import json
import os

bucket = os.environ["BUCKET_NAME"]
account = os.environ["ACCOUNT_ID"]
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
                f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*"
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

with open("cloudtrail-bucket-policy.json", "w") as file:
    json.dump(policy, file, indent=2)

print("CloudTrail S3 bucket policy generated")
PY
```

### Step 2 — Inspect Policy

```bash
python3 -m json.tool cloudtrail-bucket-policy.json
```

### Step 3 — Apply Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --policy file://cloudtrail-bucket-policy.json \
  --region "$AWS_REGION"
```

### Step 4 — Verify Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

### Expected Findings

- CloudTrail service principal is authorized.
- Bucket ACL inspection is permitted.
- Log object delivery is permitted.
- Object writes are restricted to the expected account path.
- The expected trail ARN is used as a condition.

**Security Note:** The bucket policy should not allow unrestricted public or cross-account writes.

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

### Step 3 — Verify Trail

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected:

| Setting | Expected |
|---|---|
| Trail Name | cloudtrail-lab02-trail |
| S3 Bucket | Dedicated lab bucket |
| Home Region | us-east-1 |
| Multi-Region | false |
| Organization Trail | false |

### Step 4 — Configure Management Events

```bash
aws cloudtrail put-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --event-selectors \
    ReadWriteType=All,IncludeManagementEvents=true \
  --region "$AWS_REGION"
```

### Step 5 — Verify Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected: read and write management events are enabled.

### Step 6 — Start Trail Logging

```bash
aws cloudtrail start-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 7 — Verify Logging Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,StartLoggingTime:StartLoggingTime,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

`IsLogging = true`

Delivery timestamps may not appear immediately.

### Step 8 — Save Initial Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab02-initial-trail-status.json
```

---

## 10. Verify Normal CloudTrail Logging

### Step 1 — Generate Baseline API Activity

```bash
export BASELINE_PARAMETER="${PARAMETER_PREFIX}/baseline-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$BASELINE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "baseline-event" \
  --region "$AWS_REGION"
```

### Step 2 — Save Parameter Name

```bash
printf '%s\n' "$BASELINE_PARAMETER" > lab02-baseline-parameter.txt
```

### Step 3 — Verify Parameter Creation

```bash
aws ssm get-parameter \
  --name "$BASELINE_PARAMETER" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 4 — Inspect S3 Delivery

```bash
aws s3 ls \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected: compressed CloudTrail log objects after asynchronous delivery.

### Step 5 — Check Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 6 — Save Baseline Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab02-before-stop-status.json
```

### Baseline Findings

| Component | Expected |
|---|---|
| Trail | Exists |
| S3 Bucket | Exists |
| Management Events | Enabled |
| IsLogging | true |
| Test API Operation | Successful |
| S3 Delivery | Working after asynchronous delivery |

---

## 11. Fault Injection — Stop Trail Logging

### Safety Check

Before stopping logging, confirm that the target trail belongs to this lab.

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

The trail must have:

`Project=CloudTrail-Troubleshooting-Lab02`

### Step 1 — Stop Logging

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 2 — Check Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,StopLoggingTime:StopLoggingTime,LatestDeliveryTime:LatestDeliveryTime}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

`IsLogging = false`

### Step 3 — Save Broken-State Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab02-logging-disabled.json
```

### Step 4 — Generate an Event While Logging Is Stopped

```bash
export STOPPED_PARAMETER="${PARAMETER_PREFIX}/while-stopped-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$STOPPED_PARAMETER" \
  --type String \
  --tier Standard \
  --value "created-while-trail-stopped" \
  --region "$AWS_REGION"
```

### Step 5 — Save Parameter Name

```bash
printf '%s\n' "$STOPPED_PARAMETER" > lab02-stopped-parameter.txt
```

### Step 6 — Check Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 50 \
  --output json \
  --region "$AWS_REGION" \
  > lab02-event-history-while-stopped.json
```

CloudTrail Event history remains available even when the dedicated trail is stopped.

The test event may require a short availability delay before it appears.

### Expected Fault State

| Component | Expected |
|---|---|
| Trail Configuration | Exists |
| S3 Destination | Available |
| Event Selectors | Configured |
| IsLogging | false |
| New Trail Collection | Stopped |
| Event History | Still available |
| Root Cause | Logging disabled |

### Important Delivery Note

CloudTrail may deliver log files collected before the trail was stopped.

Therefore, newly appearing S3 objects are not automatically proof that the trail continued recording events during the stopped period.

The strongest immediate evidence of the fault is the `IsLogging=false` status.

---

## 12. Investigate Trail Status and Delivery

### Step 1 — Inspect Full Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION"
```

Focus on:

```text
IsLogging
StartLoggingTime
StopLoggingTime
LatestDeliveryTime
LatestDeliveryError
```

### Step 2 — Inspect Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Verify that the trail still exists and references the expected S3 bucket.

### Step 3 — Inspect Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Expected: management events remain configured.

### Step 4 — Verify S3 Availability

```bash
aws s3api head-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Expected: success.

### Step 5 — Inspect Delivery Errors

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,DeliveryError:LatestDeliveryError,LatestDeliveryTime:LatestDeliveryTime}' \
  --output json \
  --region "$AWS_REGION"
```

### Investigation Results

| Investigation | Expected Finding |
|---|---|
| Trail Exists | Yes |
| Trail Region | us-east-1 |
| S3 Bucket | Available |
| Bucket Policy | Configured |
| Management Events | Enabled |
| IsLogging | false |
| Logging Stop Timestamp | Present |
| Root Cause | Logging explicitly stopped |

### Investigation Conclusion

The trail exists and its destination configuration is intact, but its logging state is disabled.

This is different from a CloudTrail S3 delivery failure caused by an invalid bucket policy or unavailable destination.

---

## 13. Root Cause Analysis

### Root Cause

The CloudTrail trail stopped recording new events because logging was disabled.

The lab intentionally executed the `StopLogging` API against the dedicated trail.

After this operation, `GetTrailStatus` returned:

```json
{
  "IsLogging": false
}
```

The trail and S3 bucket continued to exist.

The event selectors also remained configured.

However, the trail was not actively collecting new events.

The incident was caused by the logging state, not by missing infrastructure.

### Root Cause Flow

```text
CloudTrail Trail Created
          |
          v
Logging Enabled
          |
          v
Management Events Collected
          |
          v
StopLogging API Called
          |
          v
IsLogging = false
          |
          v
Trail Collection Stopped
          |
          v
Audit Coverage Interrupted
          |
          v
Cloud Security Investigation
          |
          v
Stopped Logging Identified
```

### Five Whys

1. **Why was the trail not recording new events?** Logging was disabled.
2. **Why was logging disabled?** The trail was stopped using the StopLogging API.
3. **Why did the trail stop recording new events?** Its active logging state was false.
4. **Why was the issue initially confusing?** The trail and S3 bucket still existed.
5. **How was the issue resolved?** Logging was restarted and new S3 event delivery was verified.

### Root Cause Summary

| Component | Finding |
|---|---|
| Incident | INC-CT-002 |
| Service | CloudTrail |
| Trail | cloudtrail-lab02-trail |
| Fault | StopLogging |
| Broken Status | IsLogging=false |
| Trail Configuration | Present |
| S3 Destination | Present |
| Event Selectors | Configured |
| Root Cause | Logging stopped |
| Remediation | StartLogging |
| Recovery Verification | New management event delivered to S3 |

**Key Lesson:** A CloudTrail trail can exist with a valid S3 destination and event selectors while logging is disabled. Engineers must verify the active logging state rather than assuming the trail is healthy because its configuration exists.

---

## 14. Remediation — Restart CloudTrail Logging

### Step 1 — Start Logging

```bash
aws cloudtrail start-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 2 — Verify Logging Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,StartLoggingTime:StartLoggingTime,StopLoggingTime:StopLoggingTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

`IsLogging = true`

### Step 3 — Save After-Remediation Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab02-after-remediation.json
```

### Step 4 — Generate a Recovery API Event

```bash
export RECOVERY_PARAMETER="${PARAMETER_PREFIX}/recovery-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$RECOVERY_PARAMETER" \
  --type String \
  --tier Standard \
  --value "logging-restored" \
  --region "$AWS_REGION"
```

### Step 5 — Save Recovery Parameter Name

```bash
printf '%s\n' "$RECOVERY_PARAMETER" > lab02-recovery-parameter.txt
```

### Step 6 — Verify Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab02-recovery-event-history.json
```

The API event may take several minutes to appear.

### Important Verification Difference

Finding the event in Event history does not prove that the trail delivered it to S3.

Event history and trail delivery are separate capabilities.

The next section verifies actual delivery.

---

## 15. Verify Recovery Event Delivery to S3

### Step 1 — Inspect S3 Logs

```bash
aws s3 ls \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected: one or more compressed `.json.gz` log files after delivery.

### Step 2 — Check Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Verify:

- IsLogging is true.
- Delivery timestamps indicate successful delivery.
- There is no current delivery error.

### Step 3 — Create Local Log Directory

```bash
mkdir -p downloaded-cloudtrail-logs
```

### Step 4 — Download Compressed Logs

```bash
aws s3 cp \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  downloaded-cloudtrail-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 5 — Create S3 Log Verification Script

Save as `verify-s3-delivery.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 2:
    print("Usage: python3 verify-s3-delivery.py PARAMETER_NAME")
    sys.exit(2)

target = sys.argv[1]
matches = []

for filename in glob.glob(
    "downloaded-cloudtrail-logs/**/*.json.gz",
    recursive=True
):
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        request = event.get("requestParameters") or {}

        if (
            event.get("eventName") == "PutParameter"
            and request.get("name") == target
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "awsRegion": event.get("awsRegion"),
                "parameterName": request.get("name"),
                "sourceFile": filename
            })

with open("lab02-recovery-s3-evidence.json", "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    print("Recovery event not yet found in downloaded S3 logs")
    sys.exit(1)

print("SUCCESS: Recovery event found in delivered CloudTrail S3 log")
```

### Step 6 — Execute Verification Script

```bash
python3 verify-s3-delivery.py "$RECOVERY_PARAMETER"
```

Expected after successful delivery:

```text
SUCCESS: Recovery event found in delivered CloudTrail S3 log
```

### Step 7 — Inspect Evidence

```bash
python3 -m json.tool lab02-recovery-s3-evidence.json
```

### Step 8 — Save Final Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab02-final-trail-status.json
```

### Final Verification Matrix

| Check | Expected Result |
|---|---|
| Trail Exists | Yes |
| S3 Bucket Exists | Yes |
| IsLogging | true |
| Management Events | Enabled |
| Recovery API Operation | Successful |
| Recovery Event in Event History | Available |
| S3 Log Delivery | Working |
| Recovery Event in S3 | Verified |
| Root Cause | Corrected |

### Before and After

| Investigation | Before Remediation | After Remediation |
|---|---|---|
| Trail | Exists | Exists |
| S3 Destination | Exists | Exists |
| Logging Status | false | true |
| Event Selectors | Configured | Configured |
| Trail Recording | Stopped | Active |
| New API Events | Not collected by stopped trail | Collected |
| S3 Delivery of Recovery Event | Not applicable | Verified |
| Incident | Active | Resolved after verification |

**Recovery is confirmed only when the trail reports `IsLogging=true` and the newly generated management event is found in a delivered S3 log file.**

---

<WritingBlock id="72645" variant="document"># Lab 02 — Additional Documentation

## 16. Understanding Trail Logging vs. Event History

CloudTrail Event history and CloudTrail trail delivery serve different purposes.

### CloudTrail Event History

Event history provides a rolling 90-day view of supported management events.

It does not require creating a trail and remains available even when an individual trail is stopped.

### CloudTrail Trail

A trail delivers selected events to a configured S3 bucket.

A trail must have logging enabled to collect ongoing activity.

### Comparison

| Feature | CloudTrail Event History | CloudTrail Trail |
|---|---|---|
| Requires trail creation | No | Yes |
| Management events | Yes | Configurable |
| Data events | Not available through Event history | Supported when selected |
| Retention | 90-day rolling history | Depends on S3 lifecycle |
| S3 delivery | No | Yes |
| Affected by StopLogging | No | Yes |
| Long-term auditing | Limited | Supported through retained logs |

### Important Investigation Detail

If a trail is stopped, engineers may still find API operations in Event history.

This does not mean the stopped trail was collecting those events.

Similarly, the appearance of S3 objects after logging was stopped does not automatically demonstrate new event collection, because delivery of previously recorded data can be delayed.

### Why This Matters

Engineers need to distinguish between:

- Events appearing in Event history.
- Events being recorded by a particular trail.
- Events being successfully delivered to S3.
- Historical log files remaining in S3.

Each represents a different part of the audit logging system.

---

## 17. Production Troubleshooting Best Practices

### CloudTrail Logging Troubleshooting Checklist

1. Identify the affected CloudTrail trail.
2. Verify the AWS account and Region.
3. Confirm the trail exists.
4. Check whether it is an organization trail.
5. Inspect the trail's logging status.
6. Verify `IsLogging`.
7. Review the latest logging start and stop times.
8. Inspect the S3 destination.
9. Verify the bucket exists.
10. Check the bucket policy.
11. Inspect management event selectors.
12. Review the latest delivery timestamp.
13. Inspect delivery errors.
14. Compare Event history with trail delivery.
15. Identify whether the trail was stopped.
16. Document the root cause.
17. Restart logging when authorized.
18. Generate a new management event.
19. Verify delivery to S3.
20. Preserve evidence and document findings.

### Common CloudTrail Logging Problems

| Symptom | Possible Cause | Investigation |
|---|---|---|
| `IsLogging=false` | Trail stopped | GetTrailStatus |
| Trail not found | Incorrect name or Region | DescribeTrails |
| S3 logs missing | Trail logging stopped | GetTrailStatus |
| S3 logs missing | Delivery permissions | Bucket policy |
| S3 delivery error | Incorrect S3 configuration | LatestDeliveryError |
| Management events missing | Incorrect event selectors | GetEventSelectors |
| Data events missing | Data event collection not configured | Event selectors |
| Recent event missing | Delivery delay | Event history and timestamps |
| Unexpected audit gap | Logging interrupted | Start/stop timestamps |
| Event history works but trail is stopped | Separate CloudTrail capabilities | Compare status and delivery |

### Production Recommendations

- Use multi-Region trails when broad regional coverage is required.
- Protect production CloudTrail trails from unauthorized configuration changes.
- Monitor trail logging status.
- Investigate unexpected `StopLogging` events.
- Restrict CloudTrail administrative permissions.
- Use secure S3 destination policies.
- Apply appropriate S3 log retention.
- Enable log file integrity validation when required.
- Monitor CloudTrail delivery failures.
- Maintain incident response procedures for audit logging interruptions.

### Security Monitoring

A production environment can monitor CloudTrail management events such as:

```text
StopLogging
StartLogging
DeleteTrail
UpdateTrail
PutEventSelectors
```

These operations can indicate legitimate maintenance or potentially unauthorized changes to audit logging.

Each event should be evaluated in context.

### Operational Prevention

Organizations can reduce audit logging interruptions by implementing preventive controls, change monitoring, and automated checks.

Examples include AWS Config evaluations, monitoring for CloudTrail configuration changes, and organizational controls that restrict who can stop or delete security trails.

---

## 18. AWS Resource Cleanup

**Warning:** Delete only the temporary CloudTrail trail and S3 bucket created specifically for Lab 02.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm:

`Project=CloudTrail-Troubleshooting-Lab02`

### Step 2 — Stop the Lab Trail

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 3 — Delete the Lab Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 4 — Verify Trail Deletion

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

Expected: no matching trail.

### Step 5 — Delete Temporary Parameters

```bash
for FILE in \
  lab02-baseline-parameter.txt \
  lab02-stopped-parameter.txt \
  lab02-recovery-parameter.txt
do
  if [ -f "$FILE" ]; then
    PARAMETER=$(cat "$FILE")

    case "$PARAMETER" in
      /cloudtrail-lab02/*)
        aws ssm delete-parameter \
          --name "$PARAMETER" \
          --region "$AWS_REGION"
        ;;
      *)
        echo "Skipping unexpected parameter name: $PARAMETER"
        ;;
    esac
  fi
done
```

### Step 6 — Verify S3 Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Confirm the Lab 02 project tag.

### Step 7 — Delete Lab S3 Objects

```bash
aws s3 rm "s3://${BUCKET_NAME}/" \
  --recursive \
  --region "$AWS_REGION"
```

Only run this against the verified disposable lab bucket.

### Step 8 — Delete Lab S3 Bucket

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

Expected: a not-found error.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| Lab CloudTrail Trail | Deleted |
| Lab S3 Bucket | Deleted |
| Delivered S3 Log Objects | Deleted |
| Baseline SSM Parameter | Deleted |
| Stopped-Period SSM Parameter | Deleted |
| Recovery SSM Parameter | Deleted |
| Production Trails | Unchanged |
| Event History | Retained normally |
| EC2 Instances | None created |
| KMS Keys | None created |
| VPC Resources | None created |

---

## 19. Interview Questions and Answers

### Q1. What does `IsLogging=false` mean?

It indicates that the CloudTrail trail is not currently logging AWS events.

### Q2. How do you check CloudTrail logging status?

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

### Q3. How do you restart a stopped trail?

```bash
aws cloudtrail start-logging \
  --name YOUR_TRAIL_NAME
```

### Q4. What does StopLogging do?

It stops event logging for an existing CloudTrail trail without deleting the trail configuration.

### Q5. Does stopping a trail delete previously delivered S3 logs?

No. Previously delivered log objects remain in the S3 bucket unless separately deleted.

### Q6. Does stopping a trail disable CloudTrail Event history?

No. Event history operates independently of individual trails.

### Q7. What does LatestDeliveryTime indicate?

It identifies the latest successful CloudTrail log file delivery to the configured S3 destination.

### Q8. What does LatestDeliveryError indicate?

It reports a CloudTrail S3 log delivery error when one has occurred.

### Q9. Can CloudTrail deliver S3 log objects after StopLogging?

Yes. Previously recorded events may still be delivered asynchronously.

### Q10. Why should engineers inspect event selectors?

Event selectors determine which event categories and resources a trail records.

### Q11. Why is an S3 bucket policy required?

CloudTrail needs authorization to access the destination bucket and deliver log objects.

### Q12. Does IsLogging=true guarantee successful S3 delivery?

No. It confirms the active logging state, but engineers should also inspect delivery errors and verify actual S3 log objects.

### Q13. How can you verify that logging has recovered?

Restart the trail, verify `IsLogging=true`, generate a fresh management event, and confirm that event appears in a delivered S3 log file.

### Q14. Why should security teams monitor StopLogging?

An unexpected StopLogging operation may create an audit coverage gap and could indicate unauthorized modification of security logging.

### Q15. How would you explain this lab in an interview?

I created a dedicated CloudTrail trail with a private S3 bucket and configured the required bucket policy.

I enabled management-event collection and started logging.

After verifying the initial trail configuration, I intentionally stopped logging using AWS CLI.

I investigated the issue with GetTrailStatus and found that IsLogging was false.

I also checked the S3 destination, event selectors, and delivery status to distinguish stopped logging from an S3 permission failure.

I restarted logging using StartLogging.

To verify recovery, I created a new Systems Manager Parameter Store parameter and checked that its PutParameter event was delivered to the CloudTrail S3 bucket.

I used Python to inspect the compressed CloudTrail log files and identify the exact recovery event.

Finally, I documented the before-and-after evidence and deleted the temporary AWS resources.

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
│   ├── README.md
│   ├── cloudtrail-bucket-policy.json
│   ├── verify-s3-delivery.py
│   ├── lab02-resources.env
│   ├── lab02-baseline-parameter.txt
│   ├── lab02-stopped-parameter.txt
│   ├── lab02-recovery-parameter.txt
│   ├── lab02-initial-trail-status.json
│   ├── lab02-before-stop-status.json
│   ├── lab02-logging-disabled.json
│   ├── lab02-event-history-while-stopped.json
│   ├── lab02-after-remediation.json
│   ├── lab02-recovery-event-history.json
│   ├── lab02-recovery-s3-evidence.json
│   ├── lab02-final-trail-status.json
│   └── downloaded-cloudtrail-logs/
│
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
| `cloudtrail-bucket-policy.json` | Configures restricted CloudTrail S3 delivery |
| `verify-s3-delivery.py` | Verifies recovery event in compressed S3 logs |
| `lab02-resources.env` | Stores lab resource identifiers |
| `lab02-baseline-parameter.txt` | Records baseline test parameter name |
| `lab02-stopped-parameter.txt` | Records stopped-period test parameter |
| `lab02-recovery-parameter.txt` | Records recovery test parameter |
| `lab02-initial-trail-status.json` | Initial trail status |
| `lab02-before-stop-status.json` | Healthy baseline configuration |
| `lab02-logging-disabled.json` | Broken logging state |
| `lab02-event-history-while-stopped.json` | Event history investigation |
| `lab02-after-remediation.json` | Logging state after restoration |
| `lab02-recovery-event-history.json` | Recovery event history results |
| `lab02-recovery-s3-evidence.json` | Verified recovery event from S3 |
| `lab02-final-trail-status.json` | Final trail status |
| `downloaded-cloudtrail-logs/` | Local copies of delivered log files |

### Evidence Guidelines

Use actual AWS CLI output for all evidence.

Do not fabricate event IDs, delivery timestamps, trail statuses, or verification results.

Review CloudTrail records for AWS account IDs, identity ARNs, IP addresses, and request information before sharing them publicly.

For a public portfolio, sanitized configuration files, investigation scripts, and a redacted recovery-event summary are usually sufficient.

Do not commit entire unredacted CloudTrail audit logs.

### Suggested Git Ignore Entries

```gitignore
__pycache__/
*.pyc
.venv/
.env
downloaded-cloudtrail-logs/
```

---

## 21. Lessons Learned and Skills Demonstrated

### Lessons Learned

This lab demonstrates how AWS CloudTrail logging can be interrupted even when the trail configuration and S3 destination remain available.

We created a dedicated CloudTrail trail with a private S3 bucket.

We configured a bucket policy authorizing the CloudTrail service to deliver audit logs.

We enabled management-event collection and started logging.

We generated a test management event using AWS Systems Manager Parameter Store.

After establishing the baseline logging configuration, we intentionally stopped the trail using StopLogging.

The trail remained configured, but GetTrailStatus reported IsLogging=false.

We investigated the trail configuration, event selectors, S3 destination, and delivery status.

This allowed us to identify the stopped logging state as the root cause.

We restored logging using StartLogging and verified that IsLogging returned true.

We then generated a fresh management event and checked the CloudTrail S3 destination.

To verify the complete logging pipeline, we created a Python script that searched downloaded compressed CloudTrail log files for the exact recovery event.

Finally, we documented the investigation findings and deleted the temporary AWS resources.

**Key Lesson:** A CloudTrail trail existing in an AWS account does not mean it is actively logging. Engineers must verify the trail's logging state and confirm that newly recorded events are successfully delivered to the configured destination.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail trail creation
- CloudTrail StartLogging
- CloudTrail StopLogging
- CloudTrail GetTrailStatus
- CloudTrail event selectors
- Management event auditing
- CloudTrail Event history
- Amazon S3
- S3 bucket policy configuration
- S3 public access protection
- SSE-S3 encryption
- AWS Systems Manager Parameter Store
- AWS CLI v2
- WSL Ubuntu
- Linux Bash
- Python JSON processing
- GZIP log analysis
- AWS audit log delivery verification
- CloudTrail delivery diagnostics
- Incident investigation
- Root cause analysis
- Remediation verification
- AWS resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-002 |
| Scenario | Trail Logging Disabled |
| Trail | cloudtrail-lab02-trail |
| Trail Type | Single-Region |
| Region | us-east-1 |
| S3 Destination | Dedicated private lab bucket |
| Management Events | Enabled |
| Initial Status | IsLogging=true |
| Broken Status | IsLogging=false |
| Fault Injection | StopLogging |
| Root Cause | Logging disabled |
| Remediation | StartLogging |
| Recovery Status | IsLogging=true |
| Verification Event | PutParameter |
| S3 Delivery | Recovery event located in delivered log |
| Evidence | Before-and-after CLI results |
| Cleanup | Trail, parameters, and bucket deleted |
| Incident Status | Resolved after delivery verification |

**Key Takeaway:** CloudTrail is essential for AWS audit visibility, but logging reliability depends on more than trail creation. Cloud Engineers and Cloud Security Engineers should understand trail status, event selectors, S3 delivery, and how to verify that logging actually resumes after an interruption.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Trail Management](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html)
- [CloudTrail S3 Bucket Policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- [AWS CLI — CreateTrail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/create-trail.html)
- [AWS CLI — GetTrailStatus](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-trail-status.html)
- [AWS CLI — StartLogging](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/start-logging.html)
- [AWS CLI — StopLogging](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/stop-logging.html)
- [AWS CLI — DeleteTrail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/delete-trail.html)