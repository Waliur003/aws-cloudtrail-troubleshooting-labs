# Lab 07 — CloudTrail Multi-Region Trail Misconfiguration

**AWS CloudTrail Troubleshooting Labs | Cloud Engineering & Cloud Security Engineering**

## Overview

This lab demonstrates how to investigate and resolve missing AWS CloudTrail audit logs caused by a single-Region trail configuration.

AWS CloudTrail records supported AWS API activity and helps organizations monitor account operations, investigate security incidents, and maintain audit records.

However, CloudTrail trails can be configured for either a single AWS Region or multiple Regions.

A single-Region trail collects selected events only from its configured Region. This can create an audit coverage gap when an organization also operates resources in other AWS Regions.

In this lab, we simulate a production incident where a CloudTrail trail records management events from `us-east-1` but does not record expected events from `us-west-2`.

We begin by creating a dedicated CloudTrail trail in `us-east-1` with a private S3 destination.

The trail is intentionally configured with `IsMultiRegionTrail=false`.

We generate management API events using AWS Systems Manager Parameter Store in both `us-east-1` and `us-west-2`.

We verify that the operations appear in their respective regional CloudTrail Event histories, but only the `us-east-1` activity is collected by our dedicated single-Region trail.

We then inspect the trail configuration and identify the regional scope as the root cause.

To resolve the issue, we update the existing trail using `UpdateTrail` with the `--is-multi-region-trail` option.

After verifying the updated configuration, we generate new management events in both Regions.

We download the delivered CloudTrail log files from the S3 destination and use Python to verify the exact events from both Regions.

Finally, we document the incident findings and clean up the temporary AWS resources.

**Troubleshooting workflow:**

Single-Region Trail Creation → Management Event Logging → Generate Events in Two Regions → Detect Missing Regional Logs → Investigate Trail Configuration → Identify IsMultiRegionTrail=false → UpdateTrail → Enable Multi-Region Coverage → Generate New Regional Events → Verify S3 Delivery → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-007 |
| Lab Name | CloudTrail Multi-Region Trail Misconfiguration |
| Difficulty | Intermediate to Advanced |
| Primary Service | AWS CloudTrail |
| Supporting Services | Amazon S3, AWS Systems Manager |
| Operating Environment | WSL2 Ubuntu |
| Interface | AWS CLI v2 |
| Languages | Bash, Python 3 |
| Trail Name | `cloudtrail-lab07-trail` |
| Home Region | `us-east-1` |
| Secondary Region | `us-west-2` |
| Initial Trail Type | Single-Region |
| Recovered Trail Type | Multi-Region |
| Initial IsMultiRegionTrail | false |
| Recovered IsMultiRegionTrail | true |
| Organization Trail | No |
| S3 Destination | Dedicated private S3 bucket |
| Bucket Encryption | SSE-S3 |
| Public Access | Blocked |
| Event Category | Management events |
| Event Selectors | Read and write |
| Data Events | Disabled |
| Test API | `ssm:PutParameter` |
| Fault Injection | Single-Region trail configuration |
| Root Cause | Incomplete regional audit coverage |
| Remediation API | `UpdateTrail` |
| Recovery Verification | Management events from two Regions in S3 |
| Cleanup | Delete trail, S3 bucket, and four test parameters |

### Lab Objectives

- Understand CloudTrail single-Region and multi-Region trails.
- Learn the meaning of a trail's home Region.
- Understand replicated CloudTrail configurations.
- Create a private S3 audit destination.
- Configure CloudTrail management events.
- Generate real AWS API activity in two Regions.
- Investigate regional Event history.
- Identify missing regional audit coverage.
- Inspect `IsMultiRegionTrail`.
- Update an existing trail to multi-Region.
- Verify configuration propagation.
- Understand Region-specific S3 log prefixes.
- Parse compressed CloudTrail JSON files.
- Verify exact events in multiple Regions.
- Perform root cause analysis.
- Document remediation and recovery.
- Safely remove temporary AWS resources.

---

## 2. Production Incident Scenario

### Incident Description

A company operates AWS infrastructure in multiple Regions.

Its main production environment is hosted in `us-east-1`, but engineers also deploy workloads in `us-west-2`.

The Cloud Security team relies on AWS CloudTrail for API auditing and security investigations.

During an investigation, the team needs to determine which users performed management operations in `us-west-2`.

The engineer searches the centralized CloudTrail S3 logs but cannot find the expected regional activity.

The trail still exists and reports that logging is enabled.

The S3 bucket is available, and audit files are arriving for `us-east-1`.

The engineer initially considers several possible causes:

- CloudTrail logging disabled.
- Incorrect management-event selectors.
- Failed S3 delivery.
- Incorrect AWS Region.
- Missing CloudTrail permissions.
- Single-Region trail configuration.

The engineer compares Event history across the two Regions.

The expected management operations appear in their respective regional Event histories.

However, the dedicated CloudTrail trail only delivers logs from its home Region.

Further investigation reveals:

```json
{
  "IsMultiRegionTrail": false
}
```

This confirms that the trail was configured for only one AWS Region.

The engineer updates the trail to multi-Region without deleting or recreating it.

After the change, the engineer generates new management events in both Regions and verifies that CloudTrail delivers them to the same S3 destination under separate regional prefixes.

### Incident Symptoms

- CloudTrail trail exists.
- `IsLogging=true`.
- Management-event selectors are configured.
- S3 delivery works for `us-east-1`.
- Expected `us-west-2` audit records are missing from the dedicated trail.
- Event history in `us-west-2` still contains supported management events.
- `IsMultiRegionTrail=false`.
- No dedicated trail coverage exists in the secondary Region.
- Regional coverage is restored after updating the trail.

### Business Impact

- Incomplete AWS API auditing across Regions.
- Reduced visibility into secondary-region activity.
- Potentially missing evidence during investigations.
- Difficulty detecting unauthorized regional operations.
- Inaccurate compliance and audit reports.
- Delayed incident response.
- Misleading assumptions about organization-wide monitoring.
- Security gaps when resources are deployed outside the primary Region.

### Objective

Identify the regional configuration issue, convert the dedicated trail to multi-Region logging, and confirm successful delivery of new management events from both Regions.

---

## 3. AWS Architecture

### Broken Architecture — Single-Region Trail

```text
                     AWS Account
                          |
             +------------+------------+
             |                         |
             v                         v
         us-east-1                 us-west-2
             |                         |
             v                         v
       PutParameter               PutParameter
             |                         |
             v                         v
       CloudTrail Event History   CloudTrail Event History
             |                         |
             v                         |
      Single-Region Trail              |
             |                         |
             v                         |
     IsMultiRegionTrail=false          |
             |                         |
             v                         v
       Events Collected          Not Collected
             |
             v
       Amazon S3 Log Bucket
             |
             v
       us-east-1 Logs Only
```

### Recovered Architecture — Multi-Region Trail

```text
                     AWS Account
                          |
             +------------+------------+
             |                         |
             v                         v
         us-east-1                 us-west-2
             |                         |
             v                         v
       PutParameter               PutParameter
             |                         |
             +------------+------------+
                          |
                          v
                   CloudTrail Trail
                          |
                          v
                IsMultiRegionTrail=true
                          |
                          v
                  Management Events
                          |
                          v
                   Amazon S3 Bucket
                          |
             +------------+------------+
             |                         |
             v                         v
      CloudTrail/us-east-1/     CloudTrail/us-west-2/
             |                         |
             +------------+------------+
                          |
                          v
                 Python Log Verification
```

### AWS Components

| Component | Purpose |
|---|---|
| AWS CloudTrail | Collects selected management events |
| CloudTrail Trail | Configures the regional coverage |
| Trail Home Region | Region where trail configuration is managed |
| Multi-Region Trail | Collects events across enabled AWS Regions |
| Shadow Trails | Replicated regional trail configurations |
| Amazon S3 | Stores delivered audit logs |
| Systems Manager Parameter Store | Generates regional API events |
| AWS CLI | Creates, investigates, and updates infrastructure |
| Python | Verifies events in CloudTrail logs |
| Bash | Runs the troubleshooting workflow |

---

## 4. Understanding CloudTrail Regional Coverage

### What Is an AWS Region?

An AWS Region is a geographic area containing AWS infrastructure.

AWS services and resources can operate in multiple Regions.

Examples:

```text
us-east-1
us-west-2
eu-west-1
ap-southeast-1
```

### What Is a Single-Region Trail?

A single-Region CloudTrail trail records selected events in its configured home Region.

Its `IsMultiRegionTrail` setting is:

```text
false
```

### What Is a Multi-Region Trail?

A multi-Region trail records selected events across all enabled AWS Regions in the account.

Its `IsMultiRegionTrail` setting is:

```text
true
```

### What Is the Home Region?

The home Region is the AWS Region where a trail was created.

Trail configuration updates must be made from the home Region.

For this lab:

```text
Home Region = us-east-1
```

### What Are Shadow Trails?

When a trail becomes multi-Region, CloudTrail replicates its configuration to other enabled Regions.

These regional copies are commonly called shadow trails.

They are managed through the original trail.

### What Does IsMultiRegionTrail Mean?

```text
IsMultiRegionTrail=false
    → Single-Region coverage

IsMultiRegionTrail=true
    → All enabled AWS Regions
```

### What Is UpdateTrail?

`UpdateTrail` changes an existing CloudTrail trail's configuration.

For this lab:

```bash
aws cloudtrail update-trail \
  --name cloudtrail-lab07-trail \
  --is-multi-region-trail \
  --region us-east-1
```

### Does a Multi-Region Trail Require Multiple S3 Buckets?

No.

A multi-Region trail can deliver audit logs from multiple Regions into one S3 bucket.

CloudTrail organizes the files using separate regional prefixes.

### What Is CloudTrail Event History?

Event history provides recent supported management events within a Region.

It does not depend on the existence of a particular CloudTrail trail.

Therefore, an API operation can appear in Event history even if the dedicated trail does not cover that Region.

### Can a Trail Record Historical Events After Changing Scope?

A trail does not retroactively collect events from Regions it did not previously cover.

Generate new API activity after updating the trail to verify the recovery.

### Important Production Consideration

A multi-Region trail covers all enabled Regions, not merely the two Regions tested in this lab.

This helps reduce audit coverage gaps, but may also increase log volume and costs.

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
- Systems Manager permissions in two Regions.
- Git and GitHub.

### Required Permissions

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

ec2:DescribeRegions
```

### Safety Rules

- Use a dedicated lab trail.
- Never modify an existing production or organization trail.
- Use only the dedicated S3 bucket.
- Keep the bucket private.
- Use synthetic Parameter Store values.
- Verify ownership tags before changing or deleting resources.
- Update the trail from its home Region.
- Do not publish unredacted CloudTrail events.
- Remove temporary parameters from both AWS Regions.
- Delete the dedicated trail after testing.

### Cost Considerations

Potential charges include S3 storage, S3 API requests, and additional management-event copies.

A multi-Region trail collects management events across enabled Regions, so keep the test limited and delete the trail after completing verification.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Navigate to Repository

```bash
cd ~/aws-cloudtrail-troubleshooting-labs
```

### Step 2 — Create Lab Directory

```bash
mkdir -p 07-multi-region-trail-misconfiguration

cd 07-multi-region-trail-misconfiguration
```

### Step 3 — Verify AWS CLI

```bash
aws --version
aws sts get-caller-identity
```

### Step 4 — Configure Environment Variables

```bash
export AWS_REGION="us-east-1"
export SECONDARY_REGION="us-west-2"
export AWS_PAGER=""

export ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text)

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab07"

export TRAIL_NAME="cloudtrail-lab07-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export LOG_BUCKET="cloudtrail-lab07-${ACCOUNT_ID}-${SUFFIX}"

export PARAMETER_PREFIX="/cloudtrail-lab07"
```

### Step 5 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$SECONDARY_REGION"
echo "$TRAIL_NAME"
echo "$TRAIL_ARN"
echo "$LOG_BUCKET"
```

### Step 6 — Save Resource Information

Create `lab07-resources.env`:

```bash
cat > lab07-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export SECONDARY_REGION="$SECONDARY_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export LOG_BUCKET="$LOG_BUCKET"
export PARAMETER_PREFIX="$PARAMETER_PREFIX"
EOF
```

Restore variables in another terminal session:

```bash
source lab07-resources.env
```

### Step 7 — Verify Secondary Region

```bash
aws ec2 describe-regions \
  --region "$AWS_REGION" \
  --query "Regions[?RegionName=='${SECONDARY_REGION}'].{Region:RegionName,Status:OptInStatus}" \
  --output table
```

### Step 8 — Inspect Existing Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

```bash
aws cloudtrail list-trails \
  --region "$SECONDARY_REGION" \
  --output table
```

Confirm that the dedicated lab trail name does not conflict with existing resources.

---

## 7. Create and Secure the S3 Log Bucket

### Step 1 — Create Bucket

```bash
aws s3api create-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 2 — Block Public Access

```bash
aws s3api put-public-access-block \
  --bucket "$LOG_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region "$AWS_REGION"
```

### Step 3 — Enable SSE-S3

```bash
aws s3api put-bucket-encryption \
  --bucket "$LOG_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --region "$AWS_REGION"
```

### Step 4 — Tag Bucket

```bash
aws s3api put-bucket-tagging \
  --bucket "$LOG_BUCKET" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Bucket

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Encryption

```bash
aws s3api get-bucket-encryption \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Expected Configuration

| Setting | Expected |
|---|---|
| Bucket | Available |
| Region | us-east-1 |
| Public access | Blocked |
| Encryption | SSE-S3 |
| Project tag | Present |

---

## 8. Configure the CloudTrail S3 Bucket Policy

### Purpose

CloudTrail needs permission to inspect the destination bucket ACL and upload log files.

A multi-Region trail can use the same S3 destination and the home-Region trail ARN.

### Step 1 — Create Policy Generator

Save as `generate-s3-policy.py`:

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

with open("cloudtrail-s3-policy.json", "w") as file:
    json.dump(policy, file, indent=2)

print("CloudTrail bucket policy generated")
```

### Step 2 — Generate Policy

```bash
python3 generate-s3-policy.py
```

### Step 3 — Inspect Policy

```bash
python3 -m json.tool cloudtrail-s3-policy.json
```

### Step 4 — Apply Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$LOG_BUCKET" \
  --policy file://cloudtrail-s3-policy.json \
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

Verify that CloudTrail has:

```text
s3:GetBucketAcl
s3:PutObject
```

The policy remains unchanged during this lab.

---

## 9. Create the Single-Region CloudTrail Trail

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

The `--no-is-multi-region-trail` option intentionally creates the regional coverage problem.

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
  --query 'trailList[].{Name:Name,HomeRegion:HomeRegion,MultiRegion:IsMultiRegionTrail,S3Bucket:S3BucketName}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
HomeRegion = us-east-1
MultiRegion = false
```

### Step 6 — Verify Logging

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

### Step 7 — Save Initial Evidence

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab07-single-region-trail.json
```

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab07-initial-status.json
```

---

## 10. Generate Baseline Events in Two Regions

### Step 1 — Generate Unique Parameter Names

```bash
export BASELINE_ID="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export BASELINE_EAST_PARAMETER="${PARAMETER_PREFIX}/baseline-east-${BASELINE_ID}"

export BASELINE_WEST_PARAMETER="${PARAMETER_PREFIX}/baseline-west-${BASELINE_ID}"
```

### Step 2 — Generate East Region Event

```bash
aws ssm put-parameter \
  --name "$BASELINE_EAST_PARAMETER" \
  --type String \
  --tier Standard \
  --value "single-region-east-test" \
  --region "$AWS_REGION"
```

### Step 3 — Generate West Region Event

```bash
aws ssm put-parameter \
  --name "$BASELINE_WEST_PARAMETER" \
  --type String \
  --tier Standard \
  --value "single-region-west-test" \
  --region "$SECONDARY_REGION"
```

### Step 4 — Save Baseline Parameter Names

```bash
cat > lab07-baseline-parameters.env <<EOF
export BASELINE_EAST_PARAMETER="$BASELINE_EAST_PARAMETER"
export BASELINE_WEST_PARAMETER="$BASELINE_WEST_PARAMETER"
EOF
```

### Step 5 — Verify East Parameter

```bash
aws ssm get-parameter \
  --name "$BASELINE_EAST_PARAMETER" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 6 — Verify West Parameter

```bash
aws ssm get-parameter \
  --name "$BASELINE_WEST_PARAMETER" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$SECONDARY_REGION"
```

Both operations should succeed.

### Baseline Operations

| Region | API Operation | Expected |
|---|---|---|
| us-east-1 | PutParameter | Successful |
| us-west-2 | PutParameter | Successful |
| East trail collection | Management event | Selected |
| West trail collection | Management event | Outside trail scope |

---

<WritingBlock id="73185" variant="document">## 11. Investigate the Regional Coverage Gap

### Step 1 — Query East Region Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab07-east-event-history.json
```

### Step 2 — Query West Region Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$SECONDARY_REGION" \
  > lab07-west-event-history.json
```

Event history may take several minutes to display newly generated operations.

### Step 3 — Create the Event History Verification Script

Save as `verify-event-history.py`:

```python
#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 3:
    print(
        "Usage: python3 verify-event-history.py "
        "EVENT_HISTORY_JSON PARAMETER_NAME"
    )
    sys.exit(2)

filename, parameter_name = sys.argv[1:]

with open(filename) as file:
    document = json.load(file)

matches = []

for item in document.get("Events", []):
    raw_event = item.get("CloudTrailEvent")

    if not raw_event:
        continue

    event = json.loads(raw_event)
    request = event.get("requestParameters") or {}

    if (
        event.get("eventName") == "PutParameter"
        and event.get("eventSource") == "ssm.amazonaws.com"
        and request.get("name") == parameter_name
    ):
        matches.append({
            "eventID": event.get("eventID"),
            "eventTime": event.get("eventTime"),
            "awsRegion": event.get("awsRegion"),
            "eventName": event.get("eventName"),
            "parameterName": parameter_name
        })

print(json.dumps(matches, indent=2))

if not matches:
    sys.exit("Target event not found in Event history")

print("SUCCESS: Matching Event history record found")
```

### Step 4 — Verify the East Event

```bash
python3 verify-event-history.py \
  lab07-east-event-history.json \
  "$BASELINE_EAST_PARAMETER"
```

### Step 5 — Verify the West Event

```bash
python3 verify-event-history.py \
  lab07-west-event-history.json \
  "$BASELINE_WEST_PARAMETER"
```

Expected: the matching operations become visible in their respective regional Event histories.

### Step 6 — Verify Trail Scope

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,HomeRegion:HomeRegion,IsMultiRegionTrail:IsMultiRegionTrail}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
IsMultiRegionTrail = false
```

### Step 7 — Inspect West Region Trail List

```bash
aws cloudtrail list-trails \
  --region "$SECONDARY_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

Expected: no matching Lab 07 trail in `us-west-2`.

### Step 8 — Inspect East Region Audit Files

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected after delivery: compressed CloudTrail log files.

### Step 9 — Inspect West Region Audit Files

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${SECONDARY_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected before remediation: no log files generated by the dedicated trail for `us-west-2`.

### Step 10 — Save Investigation Evidence

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab07-before-remediation.json
```

### Investigation Matrix

| Investigation | us-east-1 | us-west-2 |
|---|---|---|
| API operation successful | Yes | Yes |
| Event history records operation | Yes | Yes |
| Dedicated trail covers Region | Yes | No |
| Dedicated trail delivers regional logs | Yes | No |
| Root cause | Single-Region configuration | Coverage gap |

### Investigation Conclusion

The expected West Region management events exist in regional Event history.

However, the dedicated CloudTrail trail was configured for `us-east-1` only.

This explains why the secondary Region's events were missing from the trail's S3 audit logs.

---

## 12. Root Cause Analysis

### Root Cause

The CloudTrail trail was created with:

```bash
--no-is-multi-region-trail
```

As a result, its configuration included:

```json
{
  "IsMultiRegionTrail": false
}
```

The company expected audit coverage across more than one Region.

However, the trail collected selected management events only from `us-east-1`.

The `us-west-2` events were outside its collection scope.

The problem was not caused by missing S3 permissions, disabled logging, or unsuccessful API operations.

### Root Cause Diagram

```text
CloudTrail Trail Created
          |
          v
Home Region = us-east-1
          |
          v
IsMultiRegionTrail = false
          |
          v
Single-Region Audit Coverage
          |
          +--------------------------+
          |                          |
          v                          v
us-east-1 Activity            us-west-2 Activity
          |                          |
          v                          v
Collected by Trail            Not Collected
          |                          |
          v                          v
S3 Audit Logs                 Regional Audit Gap
```

### Five Whys

**Why 1 — Why were West Region events missing from the dedicated trail logs?**

The trail did not cover the West Region.

**Why 2 — Why didn't the trail cover that Region?**

It was configured as a single-Region trail.

**Why 3 — Why was the configuration insufficient?**

The organization's audit requirements included multiple AWS Regions.

**Why 4 — Why did Event history still show the West Region operation?**

Event history operates independently from the dedicated trail.

**Why 5 — How was the issue resolved?**

The existing trail was updated to multi-Region logging, and new events were verified from both Regions.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-007 |
| AWS Service | CloudTrail |
| Home Region | us-east-1 |
| Missing Coverage | us-west-2 |
| Fault | Single-Region trail |
| Root Cause | `IsMultiRegionTrail=false` |
| Remediation | Enable multi-Region trail |
| AWS API | UpdateTrail |
| Verification | Events from both Regions delivered to S3 |

---

## 13. Remediation — Convert to Multi-Region

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm:

```text
Project=CloudTrail-Troubleshooting-Lab07
```

### Step 2 — Update the Trail

```bash
aws cloudtrail update-trail \
  --name "$TRAIL_NAME" \
  --is-multi-region-trail \
  --region "$AWS_REGION"
```

This command updates the existing trail without stopping or recreating it.

The update must be performed in the home Region.

### Step 3 — Verify Updated Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,HomeRegion:HomeRegion,MultiRegion:IsMultiRegionTrail,S3Bucket:S3BucketName}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
HomeRegion = us-east-1
MultiRegion = true
```

### Step 4 — Verify West Region Replication

```bash
aws cloudtrail list-trails \
  --region "$SECONDARY_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

Expected after configuration propagation: the Lab 07 trail is visible in the West Region.

### Step 5 — Verify Logging Status

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

### Step 6 — Verify Event Selectors

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

Confirm that management events remain enabled.

### Step 7 — Save Recovery Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab07-multi-region-trail.json
```

### Remediation Summary

| Setting | Before | After |
|---|---|---|
| Home Region | us-east-1 | us-east-1 |
| Multi-Region | false | true |
| Trail logging | Enabled | Enabled |
| East coverage | Enabled | Enabled |
| West coverage | Missing | Enabled |
| S3 destination | Same bucket | Same bucket |
| Management events | Enabled | Enabled |

**Important:** A multi-Region trail collects selected activity from all enabled Regions in the account, not only the two Regions used for this exercise.

---

## 14. Generate New Management Events in Both Regions

### Step 1 — Generate Recovery Parameter Names

```bash
export RECOVERY_ID="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export RECOVERY_EAST_PARAMETER="${PARAMETER_PREFIX}/recovery-east-${RECOVERY_ID}"

export RECOVERY_WEST_PARAMETER="${PARAMETER_PREFIX}/recovery-west-${RECOVERY_ID}"
```

### Step 2 — Generate East Region Event

```bash
aws ssm put-parameter \
  --name "$RECOVERY_EAST_PARAMETER" \
  --type String \
  --tier Standard \
  --value "multi-region-east-recovery" \
  --region "$AWS_REGION"
```

### Step 3 — Generate West Region Event

After the trail configuration has propagated to the West Region:

```bash
aws ssm put-parameter \
  --name "$RECOVERY_WEST_PARAMETER" \
  --type String \
  --tier Standard \
  --value "multi-region-west-recovery" \
  --region "$SECONDARY_REGION"
```

### Step 4 — Save Recovery Parameter Names

```bash
cat > lab07-recovery-parameters.env <<EOF
export RECOVERY_EAST_PARAMETER="$RECOVERY_EAST_PARAMETER"
export RECOVERY_WEST_PARAMETER="$RECOVERY_WEST_PARAMETER"
EOF
```

### Step 5 — Verify East Parameter

```bash
aws ssm get-parameter \
  --name "$RECOVERY_EAST_PARAMETER" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 6 — Verify West Parameter

```bash
aws ssm get-parameter \
  --name "$RECOVERY_WEST_PARAMETER" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$SECONDARY_REGION"
```

### Recovery Operations

| Region | API Operation | Expected Result |
|---|---|---|
| us-east-1 | PutParameter | Successful |
| us-west-2 | PutParameter | Successful |
| East trail coverage | Management event | Selected |
| West trail coverage | Management event | Selected |

---

## 15. Verify Multi-Region CloudTrail S3 Delivery

### Step 1 — Inspect East Region Logs

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

### Step 2 — Inspect West Region Logs

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${SECONDARY_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected after successful delivery: CloudTrail log files under both regional prefixes.

### Expected S3 Structure

```text
s3://YOUR_LOG_BUCKET/
└── AWSLogs/
    └── ACCOUNT_ID/
        └── CloudTrail/
            ├── us-east-1/
            │   └── YYYY/MM/DD/
            │       └── audit-files.json.gz
            │
            └── us-west-2/
                └── YYYY/MM/DD/
                    └── audit-files.json.gz
```

### Step 3 — Inspect Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

The presence of delivery timestamps supports successful logging, but we still need to inspect the actual event records.

### Step 4 — Download East Region Logs

```bash
mkdir -p evidence/us-east-1

aws s3 cp \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/us-east-1/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 5 — Download West Region Logs

```bash
mkdir -p evidence/us-west-2

aws s3 cp \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${SECONDARY_REGION}/" \
  evidence/us-west-2/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 6 — Create Multi-Region Verification Script

Save as `verify-multi-region-events.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import os
import sys

if len(sys.argv) != 6:
    print(
        "Usage: python3 verify-multi-region-events.py "
        "EAST_LOG_DIR WEST_LOG_DIR "
        "EAST_PARAMETER WEST_PARAMETER OUTPUT_FILE"
    )
    sys.exit(2)

east_dir, west_dir, east_param, west_param, output_file = sys.argv[1:]

targets = [
    {
        "region": "us-east-1",
        "directory": east_dir,
        "parameter": east_param
    },
    {
        "region": "us-west-2",
        "directory": west_dir,
        "parameter": west_param
    }
]

evidence = []

for target in targets:
    files = glob.glob(
        os.path.join(target["directory"], "**", "*.json.gz"),
        recursive=True
    )

    print(
        f"Checking {target['region']}: "
        f"{len(files)} log files"
    )

    for filename in files:
        with gzip.open(filename, "rt") as file:
            document = json.load(file)

        for event in document.get("Records", []):
            request = event.get("requestParameters") or {}

            if (
                event.get("eventName") == "PutParameter"
                and event.get("eventSource") == "ssm.amazonaws.com"
                and event.get("awsRegion") == target["region"]
                and request.get("name") == target["parameter"]
            ):
                evidence.append({
                    "eventID": event.get("eventID"),
                    "eventTime": event.get("eventTime"),
                    "eventName": event.get("eventName"),
                    "eventSource": event.get("eventSource"),
                    "awsRegion": event.get("awsRegion"),
                    "parameterName": request.get("name"),
                    "sourceFile": filename
                })

with open(output_file, "w") as file:
    json.dump(evidence, file, indent=2)

print(json.dumps(evidence, indent=2))

verified_regions = {
    item["awsRegion"] for item in evidence
}

expected_regions = {"us-east-1", "us-west-2"}

missing = expected_regions - verified_regions

if missing:
    print(
        "ERROR: Missing verified regions:",
        ", ".join(sorted(missing))
    )
    sys.exit(1)

print("SUCCESS: Management events verified in both Regions")
```

### Step 7 — Run Verification

```bash
python3 verify-multi-region-events.py \
  evidence/us-east-1 \
  evidence/us-west-2 \
  "$RECOVERY_EAST_PARAMETER" \
  "$RECOVERY_WEST_PARAMETER" \
  lab07-verified-multi-region-events.json
```

Expected after both events have been delivered:

```text
SUCCESS: Management events verified in both Regions
```

If an event is missing, verify that the trail has propagated to the target Region, check delivery status, download newer log objects, and rerun the script.

### Step 8 — Inspect Evidence

```bash
python3 -m json.tool lab07-verified-multi-region-events.json
```

Confirm that the output includes:

- A matching PutParameter event from `us-east-1`.
- A matching PutParameter event from `us-west-2`.
- Correct parameter names.
- Correct event source.
- Actual CloudTrail event IDs.
- Source log filenames.

### Step 9 — Save Final Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab07-final-trail-status.json
```

### Final Verification Matrix

| Check | Before Remediation | After Remediation |
|---|---|---|
| Trail exists | Yes | Yes |
| IsLogging | true | true |
| IsMultiRegionTrail | false | true |
| Home Region | us-east-1 | us-east-1 |
| East management events | Recorded | Recorded |
| West management events | Not covered by trail | Recorded |
| East S3 log files | Present | Present |
| West S3 log files | Absent | Present |
| Exact East recovery event | Not applicable | Verified |
| Exact West recovery event | Not applicable | Verified |
| Root cause | Single-Region configuration | Corrected |

**Recovery is confirmed only when new management events from both Regions are found in the dedicated CloudTrail S3 audit logs.**

---

<WritingBlock id="73186" variant="document">## 16. Other Multi-Region CloudTrail Troubleshooting Scenarios

### Scenario A — Trail Created in the Wrong Region

An engineer investigates a different Region from the trail's home Region and assumes the trail is missing.

**Investigation:** Check `HomeRegion` using `DescribeTrails`.

### Scenario B — Trail Remains Single-Region

The trail only records activity from one Region.

**Investigation:** Check `IsMultiRegionTrail`.

### Scenario C — Management Events Disabled

The trail covers multiple Regions, but the expected event category is not selected.

**Investigation:** Check `GetEventSelectors`.

### Scenario D — Trail Configuration Not Yet Propagated

An updated multi-Region trail may not immediately appear in every applicable Region.

**Investigation:** Check the trail list in the secondary Region and confirm the update has propagated.

### Scenario E — Incorrect S3 Log Prefix

An engineer checks only the `us-east-1` prefix and overlooks audit records under the `us-west-2` prefix.

**Investigation:** Examine the correct Region-specific S3 directory.

### Scenario F — S3 Delivery Failure

The multi-Region configuration is correct, but CloudTrail encounters a delivery error.

**Investigation:** Check `GetTrailStatus`, the S3 bucket, and its policy.

### Scenario G — Opt-In Region Not Enabled

A trail cannot collect normal account activity from an opt-in Region that has not been enabled.

**Investigation:** Check the account's Region opt-in status.

### Scenario H — Event Occurred Before Remediation

The event occurred while the dedicated trail only covered its original Region.

**Investigation:** Compare the API operation timestamp with the trail update time.

### Troubleshooting Matrix

| Symptom | Possible Cause | Investigation |
|---|---|---|
| Events missing from one Region | Single-Region trail | DescribeTrails |
| IsMultiRegionTrail=false | Regional coverage disabled | UpdateTrail |
| Trail absent from secondary Region | Replication or scope | ListTrails |
| Management events missing | Event selector issue | GetEventSelectors |
| S3 logs absent | Delivery problem | GetTrailStatus |
| Wrong audit log directory | Incorrect Region prefix | S3 list |
| UpdateTrail fails | Wrong home Region | Verify HomeRegion |
| Older events still missing | No retroactive collection | Event timeline |

---

## 17. Production Troubleshooting Best Practices

### Investigation Checklist

1. Verify the AWS account.
2. Identify the affected AWS Region.
3. Confirm the API operation completed.
4. Inspect Event history in the relevant Region.
5. Identify the CloudTrail trail.
6. Verify the trail's home Region.
7. Check `IsLogging`.
8. Inspect `IsMultiRegionTrail`.
9. Verify management-event selectors.
10. Check trail visibility in the secondary Region.
11. Verify S3 bucket availability.
12. Inspect delivery errors.
13. Examine Region-specific S3 log prefixes.
14. Identify the root cause.
15. Apply the correct multi-Region configuration.
16. Verify the configuration has propagated.
17. Generate fresh management events.
18. Download the relevant audit log files.
19. Verify exact events in both Regions.
20. Document the incident and remediation.

### Production Investigation Flow

```text
Regional Audit Logs Missing
          |
          v
Identify the Affected Region
          |
          v
Verify API Operation
          |
          v
Inspect Regional Event History
          |
          v
Identify CloudTrail Trail
          |
          v
Check IsLogging
          |
          v
Check IsMultiRegionTrail
          |
          v
Verify Home Region
          |
          v
Review Event Selectors
          |
          v
Update Trail to Multi-Region
          |
          v
Verify Regional Replication
          |
          v
Generate Fresh API Events
          |
          v
Verify Regional S3 Logs
          |
          v
Document Recovery
```

### Security Recommendations

- Use multi-Region trails where broad regional auditing is required.
- Monitor CloudTrail configuration changes.
- Restrict who can create, modify, stop, or delete trails.
- Protect S3 audit destinations.
- Use encryption for audit logs.
- Enable log file integrity validation when appropriate.
- Apply appropriate retention policies.
- Monitor regional audit gaps.
- Regularly verify regional event collection.
- Avoid relying on one Region's Event history as evidence of account-wide trail coverage.

### Operational Recommendations

Maintain CloudTrail configuration using infrastructure as code when possible.

Document the expected home Region and regional coverage.

After changing trail settings, verify both the updated configuration and actual delivery of new events.

Do not consider a multi-Region trail healthy solely because `IsMultiRegionTrail=true`.

End-to-end event verification provides stronger evidence.

---

## 18. AWS Resource Cleanup

**Warning:** Delete only the resources created for Lab 07.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm:

```text
Project=CloudTrail-Troubleshooting-Lab07
```

### Step 2 — Verify S3 Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Confirm the same project tag.

### Step 3 — Stop the Lab Trail

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 4 — Delete the Lab Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

The deletion must be performed from the trail's home Region.

Deleting the multi-Region trail also removes its associated replicated regional configurations.

### Step 5 — Verify Trail Deletion in East Region

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

### Step 6 — Verify Trail Deletion in West Region

```bash
aws cloudtrail list-trails \
  --region "$SECONDARY_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

Expected after propagation:

```json
[]
```

### Step 7 — Restore Test Parameter Variables

```bash
source lab07-baseline-parameters.env

source lab07-recovery-parameters.env
```

### Step 8 — Delete East Region Parameters

```bash
for PARAMETER in \
  "$BASELINE_EAST_PARAMETER" \
  "$RECOVERY_EAST_PARAMETER"
do
  case "$PARAMETER" in
    /cloudtrail-lab07/*)
      aws ssm delete-parameter \
        --name "$PARAMETER" \
        --region "$AWS_REGION"
      ;;
    *)
      echo "Skipping unexpected parameter: $PARAMETER"
      ;;
  esac
done
```

### Step 9 — Delete West Region Parameters

```bash
for PARAMETER in \
  "$BASELINE_WEST_PARAMETER" \
  "$RECOVERY_WEST_PARAMETER"
do
  case "$PARAMETER" in
    /cloudtrail-lab07/*)
      aws ssm delete-parameter \
        --name "$PARAMETER" \
        --region "$SECONDARY_REGION"
      ;;
    *)
      echo "Skipping unexpected parameter: $PARAMETER"
      ;;
  esac
done
```

### Step 10 — Delete S3 Log Objects

Preserve any required investigation evidence before deleting the objects.

```bash
aws s3 rm "s3://${LOG_BUCKET}/" \
  --recursive \
  --region "$AWS_REGION"
```

### Step 11 — Delete S3 Bucket

```bash
aws s3api delete-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 12 — Verify Bucket Deletion

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Expected: the bucket is no longer found.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| Lab CloudTrail trail | Deleted |
| Regional shadow trails | Removed |
| S3 log bucket | Deleted |
| East baseline parameter | Deleted |
| West baseline parameter | Deleted |
| East recovery parameter | Deleted |
| West recovery parameter | Deleted |
| Production trails | Unchanged |
| KMS keys | None created |
| EC2 instances | None created |
| VPC resources | None created |

---

## 19. Interview Questions and Answers

### Q1. What is the difference between a single-Region trail and a multi-Region trail?

A single-Region trail records selected events in one Region. A multi-Region trail covers all enabled AWS Regions in the account.

### Q2. What does IsMultiRegionTrail=false mean?

The trail is configured for a single AWS Region.

### Q3. How do you convert a trail to multi-Region?

Use:

```bash
aws cloudtrail update-trail \
  --name YOUR_TRAIL_NAME \
  --is-multi-region-trail \
  --region YOUR_HOME_REGION
```

### Q4. What is the home Region of a CloudTrail trail?

The Region where the trail was created and where its configuration is managed.

### Q5. What are CloudTrail shadow trails?

Replicated trail configurations that CloudTrail creates in other enabled Regions for a multi-Region trail.

### Q6. Does a multi-Region trail need multiple S3 buckets?

No. It can deliver audit logs from multiple Regions to a single S3 destination.

### Q7. How are multi-Region logs organized in S3?

Under Region-specific prefixes such as:

```text
AWSLogs/ACCOUNT_ID/CloudTrail/us-east-1/
AWSLogs/ACCOUNT_ID/CloudTrail/us-west-2/
```

### Q8. Does CloudTrail Event history depend on a multi-Region trail?

No. Event history provides regional supported management-event history independently of a particular trail.

### Q9. Why can Event history show an event that the dedicated trail does not contain?

The event may have occurred outside the trail's configured regional scope.

### Q10. Can old missing events be backfilled after enabling multi-Region?

No. The trail does not retroactively collect events it previously excluded.

### Q11. Why must UpdateTrail be run from the home Region?

AWS CloudTrail manages the trail's primary configuration from its home Region.

### Q12. What happens when UpdateTrail is called from the wrong Region?

The operation may return `InvalidHomeRegionException`.

### Q13. How do you verify multi-Region recovery?

Generate new management events in two Regions and verify their delivery in the corresponding S3 audit log prefixes.

### Q14. Why are multi-Region trails useful for security?

They help prevent audit gaps when workloads or users perform API operations outside the primary Region.

### Q15. Does IsMultiRegionTrail=true guarantee all desired events are recorded?

No. Event selectors, logging status, delivery configuration, and the set of enabled Regions must also be considered.

### Q16. What is the difference between Labs 06 and 07?

Lab 06 investigates missing S3 data-event selection.

Lab 07 investigates missing regional coverage.

### Q17. What AWS CLI command shows trail configuration?

`aws cloudtrail describe-trails`.

### Q18. What AWS CLI command shows trail logging status?

`aws cloudtrail get-trail-status`.

### Q19. Can a multi-Region trail record data events?

Yes, when the appropriate data-event selectors are configured.

### Q20. How would you explain this lab in an interview?

I created a dedicated single-Region CloudTrail trail in us-east-1 and configured management-event logging to a private S3 bucket.

I generated AWS Systems Manager API events in us-east-1 and us-west-2.

The operations appeared in their respective regional Event histories, but the dedicated trail only delivered events from us-east-1.

I investigated the trail configuration and discovered that IsMultiRegionTrail was false.

I identified the single-Region configuration as the cause of the missing regional audit coverage.

I updated the existing trail using UpdateTrail with the multi-Region option.

After verifying that the new configuration was active, I generated fresh management events in both Regions.

I downloaded the resulting CloudTrail S3 log files and used Python to verify the exact events from both Regions.

Finally, I documented the incident, deleted the temporary trail and S3 bucket, and removed the test parameters from both Regions.

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
│   └── README.md
│
├── 07-multi-region-trail-misconfiguration/
│   ├── README.md
│   ├── generate-s3-policy.py
│   ├── verify-event-history.py
│   ├── verify-multi-region-events.py
│   ├── cloudtrail-s3-policy.json
│   ├── lab07-resources.env
│   ├── lab07-baseline-parameters.env
│   ├── lab07-recovery-parameters.env
│   ├── lab07-single-region-trail.json
│   ├── lab07-initial-status.json
│   ├── lab07-east-event-history.json
│   ├── lab07-west-event-history.json
│   ├── lab07-before-remediation.json
│   ├── lab07-multi-region-trail.json
│   ├── lab07-verified-multi-region-events.json
│   ├── lab07-final-trail-status.json
│   │
│   └── evidence/
│       ├── us-east-1/
│       └── us-west-2/
│
├── 08-investigating-unauthorized-api-calls/
├── 09-cloudtrail-log-integrity-validation/
└── 10-cloudtrail-lake-query-troubleshooting/
```

### File Descriptions

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `generate-s3-policy.py` | Generates the CloudTrail bucket policy |
| `verify-event-history.py` | Verifies events in regional Event history |
| `verify-multi-region-events.py` | Verifies the exact events from two Regions in S3 |
| `cloudtrail-s3-policy.json` | S3 delivery permissions |
| `lab07-resources.env` | Local resource identifiers |
| `lab07-baseline-parameters.env` | Baseline SSM parameter names |
| `lab07-recovery-parameters.env` | Recovery SSM parameter names |
| `lab07-single-region-trail.json` | Original trail configuration |
| `lab07-initial-status.json` | Initial logging status |
| `lab07-east-event-history.json` | East Region investigation |
| `lab07-west-event-history.json` | West Region investigation |
| `lab07-before-remediation.json` | Broken-state trail configuration |
| `lab07-multi-region-trail.json` | Updated trail configuration |
| `lab07-verified-multi-region-events.json` | Recovery verification |
| `lab07-final-trail-status.json` | Final trail status |
| `evidence/` | Downloaded regional audit logs |

### GitHub Evidence Guidelines

Use actual AWS CLI responses for all evidence.

Do not fabricate event IDs, timestamps, delivery results, or trail configurations.

CloudTrail records may contain:

- AWS account IDs.
- IAM principal ARNs.
- Source IP addresses.
- API request information.
- Resource identifiers.

Review and sanitize evidence before publishing.

For a public portfolio, the README, reusable Python scripts, sanitized configuration examples, and redacted event summaries are appropriate.

### Recommended .gitignore

```gitignore
__pycache__/
*.pyc
.venv/
.env

**/lab07-resources.env
**/lab07-baseline-parameters.env
**/lab07-recovery-parameters.env
**/cloudtrail-s3-policy.json
**/lab07-*.json
**/evidence/us-east-1/
**/evidence/us-west-2/
```

Generated policy files and raw evidence should remain local unless they have been reviewed and sanitized.

---

## 21. Lessons Learned and Skills Demonstrated

### Lessons Learned

This lab demonstrates how a CloudTrail trail can be enabled and successfully delivering logs while still missing activity from another AWS Region.

We created a dedicated single-Region CloudTrail trail in us-east-1.

We configured a private S3 log destination and enabled read and write management events.

We generated AWS Systems Manager API activity in us-east-1 and us-west-2.

The operations were available in their respective regional Event histories, but the dedicated trail did not cover the West Region.

We investigated the regional configuration and identified IsMultiRegionTrail=false as the root cause.

We updated the existing trail to multi-Region logging without recreating it.

After verifying the new configuration, we generated fresh management events in both Regions.

We downloaded the delivered CloudTrail logs and used Python to locate the exact events from each Region.

Finally, we deleted the dedicated trail and S3 bucket and removed the temporary parameters.

**Key Lesson:** A CloudTrail trail's logging state and event selectors do not guarantee coverage of every AWS Region. Engineers must verify regional scope and actual delivered audit records to ensure the intended coverage.

### Skills Demonstrated

- AWS CloudTrail
- Single-Region trails
- Multi-Region trails
- CloudTrail home Region
- CloudTrail shadow trails
- CloudTrail UpdateTrail
- CloudTrail DescribeTrails
- CloudTrail GetTrailStatus
- Regional CloudTrail Event history
- AWS Systems Manager Parameter Store
- Amazon S3
- S3 log delivery
- CloudTrail regional log prefixes
- AWS CLI v2
- Linux Bash
- Python 3
- JSON parsing
- GZIP audit log analysis
- Cross-Region investigation
- Cloud security monitoring
- Root cause analysis
- Remediation verification
- AWS resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-007 |
| Scenario | CloudTrail Multi-Region Trail Misconfiguration |
| Trail | cloudtrail-lab07-trail |
| Home Region | us-east-1 |
| Secondary Region | us-west-2 |
| Initial Trail Type | Single-Region |
| Recovered Trail Type | Multi-Region |
| Initial IsMultiRegionTrail | false |
| Recovered IsMultiRegionTrail | true |
| Root Cause | Missing regional coverage |
| Remediation | UpdateTrail |
| East Recovery Event | Verified in S3 |
| West Recovery Event | Verified in S3 |
| S3 Destination | Single private bucket |
| Cleanup | Trail, bucket, and parameters deleted |
| Incident Status | Resolved after two-Region verification |

**Key Takeaway:** CloudTrail regional coverage must match an organization's security monitoring requirements. Multi-Region trails reduce the risk of missing API activity from enabled AWS Regions, but engineers must still verify logging state, event selectors, and successful S3 delivery.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Understanding Multi-Region Trails](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html)
- [Receiving CloudTrail Logs from Multiple Regions](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html)
- [Updating a Trail with AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-update-trail.html)
- [AWS CLI — UpdateTrail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
- [AWS CLI — DescribeTrails](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/describe-trails.html)
- [AWS CLI — GetTrailStatus](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-trail-status.html)
- [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/)