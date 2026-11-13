# Lab 09 — CloudTrail Log Integrity Validation

**AWS CloudTrail Troubleshooting Labs | Cloud Security Engineering**

## Overview

This lab demonstrates how to validate the integrity of AWS CloudTrail audit logs using cryptographic hashes, digitally signed digest files, AWS CLI, Amazon S3, and Python.

In production AWS environments, CloudTrail records API activity for security monitoring, compliance, and incident response.

However, successfully delivering audit logs to Amazon S3 does not automatically prove those logs have remained unchanged after delivery.

An audit file could be accidentally modified, replaced, or deleted by an identity with sufficient S3 permissions.

CloudTrail log file integrity validation helps engineers investigate whether delivered log files have been modified or deleted.

When integrity validation is enabled, CloudTrail generates SHA-256 hashes of delivered log files and creates signed digest files referencing those logs. Digest files also contain information that helps establish a chain between consecutive digests.

In this lab, we create a dedicated CloudTrail trail with integrity validation enabled.

We configure a private, versioned S3 destination and generate real AWS management events.

After CloudTrail delivers the audit logs and applicable digest files, we use AWS CLI to perform cryptographic validation.

We then simulate a controlled integrity violation by modifying a local copy of a log file and comparing its SHA-256 hash with the original digest.

An optional fault-injection exercise replaces a disposable CloudTrail S3 log object with modified content while preserving its original version.

We validate the trail again, identify the mismatch, restore the original log contents, and verify recovery.

Finally, we delete the temporary CloudTrail resources and safely clean up all object versions in the dedicated S3 bucket.

**This exercise uses only disposable lab resources. Never alter production audit records to reproduce a security incident.**

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-009 |
| Lab | CloudTrail Log Integrity Validation |
| Difficulty | Advanced |
| Primary Service | AWS CloudTrail |
| Supporting Services | Amazon S3, Systems Manager |
| AWS Region | `us-east-1` |
| Environment | WSL2 Ubuntu |
| Interface | AWS CLI v2 |
| Scripting | Bash, Python 3 |
| Trail | `cloudtrail-lab09-trail` |
| Trail Type | Single-Region |
| Log Destination | Dedicated private S3 bucket |
| Bucket Versioning | Enabled |
| Bucket Encryption | SSE-S3 |
| Public Access | Blocked |
| Management Events | Read and write |
| Data Events | Disabled |
| Integrity Validation | Enabled |
| Hash Algorithm | SHA-256 |
| Digest Signature Algorithm | SHA256withRSA |
| Test API | `ssm:PutParameter` |
| Primary Validation | `aws cloudtrail validate-logs` |
| Local Investigation | Python SHA-256 comparison |
| Fault Injection | Change disposable delivered log object |
| Remediation | Restore original log contents |
| Cleanup | Delete trail, parameters, all S3 object versions and bucket |

### Objectives

- Understand CloudTrail log file integrity validation.
- Configure a trail with integrity validation enabled.
- Understand signed digest files.
- Inspect CloudTrail digest structure.
- Understand SHA-256 hashing.
- Understand the digest chain.
- Distinguish integrity validation from encryption.
- Generate management events for auditing.
- Investigate digest delivery.
- Select a log referenced by an actual digest.
- Validate CloudTrail logs using AWS CLI.
- Calculate hashes of uncompressed log contents.
- Reproduce a controlled hash mismatch.
- Investigate modified S3 audit objects.
- Restore the original object version.
- Validate restored log contents.
- Understand forensic evidence preservation.
- Clean up an S3 bucket with versioning enabled.

---

## 2. Production Incident Scenario

### Incident Description

A company uses AWS CloudTrail to maintain a historical record of AWS API operations.

CloudTrail delivers audit logs to an encrypted, private Amazon S3 bucket.

The Cloud Security team uses these records during security investigations.

During an audit, an engineer discovers that a CloudTrail log object might have been modified after its original delivery.

The engineer must determine whether the audit evidence is authentic and unchanged.

The trail is enabled and its S3 destination is functioning.

However, successful delivery alone cannot establish the integrity of the log contents.

The company's trail has CloudTrail log file integrity validation enabled.

Therefore, CloudTrail delivers cryptographic digest files that reference the audit log files and their original hashes.

The engineer retrieves the relevant digest information and runs the AWS CLI log-validation command.

The investigation reveals whether the current log object matches the hash recorded at delivery.

If a mismatch is detected, the engineer identifies the affected file, preserves the original and modified versions, and investigates who or what changed the object.

In this controlled lab, we intentionally reproduce the modification in a disposable versioned bucket and then restore the original content.

### Incident Symptoms

- CloudTrail logging remains enabled.
- Audit files exist in S3.
- Log file integrity validation is enabled.
- Digest files are available.
- A delivered audit object is suspected of modification.
- The current object hash differs from its recorded digest hash.
- AWS CLI validation can identify the affected log file.
- The original log object version remains available for recovery.

### Business Impact

Modified or missing audit logs can affect:

- Security incident investigations.
- Compliance reporting.
- Evidence integrity.
- Accountability for AWS API operations.
- Detection of unauthorized infrastructure changes.
- Regulatory and internal audits.
- Trust in historical activity records.

### Objective

Verify the authenticity and integrity of delivered CloudTrail logs, identify a controlled file modification, restore the original contents, and demonstrate successful validation after recovery.

---

## 3. AWS Architecture

### Healthy Architecture

```text
                  AWS Management APIs
                          |
                          v
                     AWS CloudTrail
                          |
                          v
                cloudtrail-lab09-trail
                          |
                          v
              Log File Validation Enabled
                          |
              +-----------+-----------+
              |                       |
              v                       v
        Audit Log Files          Digest Files
              |                       |
              v                       v
        Compressed JSON          SHA-256 Hashes
              |                  Digital Signatures
              |                       |
              +-----------+-----------+
                          |
                          v
                 Private S3 Bucket
                          |
                          v
                 AWS CLI ValidateLogs
                          |
                          v
              Digest Signature Verified
              Log File Hashes Match
                          |
                          v
                  Integrity Confirmed
```

### Broken Architecture

```text
CloudTrail Delivers Original Log
                |
                v
Original SHA-256 Recorded in Digest
                |
                v
Digest Digitally Signed
                |
                v
Log File Stored in S3
                |
                v
Log Object Modified After Delivery
                |
                v
Current File Content Changes
                |
                v
SHA-256 Hash Changes
                |
                v
Original Digest Hash != Current Hash
                |
                v
CloudTrail Integrity Validation Fails
```

### Recovered Architecture

```text
Identify Modified S3 Log Object
                |
                v
Retrieve Original Object Version
                |
                v
Verify Original SHA-256
                |
                v
Restore Original Log Contents
                |
                v
Run CloudTrail ValidateLogs
                |
                v
Log File Hash Matches Signed Digest
                |
                v
Integrity Validation Successful
```

### AWS Components

| Component | Purpose |
|---|---|
| AWS CloudTrail | Records supported API operations |
| CloudTrail Trail | Controls log delivery |
| Amazon S3 | Stores log and digest objects |
| S3 Versioning | Retains previous object versions |
| Digest File | References delivered logs and their hashes |
| SHA-256 | Detects content changes |
| Digital Signature | Authenticates digest evidence |
| Digest Chain | Links successive digest files |
| AWS CLI | Performs official CloudTrail validation |
| Systems Manager | Generates test management events |
| Python | Inspects digests and calculates hashes |
| Bash | Coordinates the troubleshooting workflow |

---

## 4. Understanding CloudTrail Log Integrity

### What Is Log File Integrity Validation?

CloudTrail log file integrity validation is a feature that enables verification of delivered CloudTrail audit logs using signed digest files.

It helps detect modifications or deletions after log delivery.

### What Is SHA-256?

SHA-256 is a cryptographic hash function that produces a 256-bit hash.

Changing the contents of a file is overwhelmingly likely to change its SHA-256 hash.

### What Is a CloudTrail Digest File?

A digest file contains information about CloudTrail log files delivered during a reporting interval.

It includes:

- The S3 bucket and key of referenced logs.
- The SHA-256 hash of each referenced log.
- The digest's reporting interval.
- Information identifying the previous digest.
- Cryptographic information used for signature validation.

### What Is a Digital Signature?

A digital signature helps verify that the digest information was signed using the expected CloudTrail signing key and was not altered.

CloudTrail uses SHA-256 with RSA signing for digest files.

### What Is a Digest Chain?

CloudTrail digest files reference previous digest information.

This makes it possible to validate a sequence of digest files and investigate gaps or changes in the chain.

### How Often Are Digests Delivered?

Digest files are generally delivered approximately hourly.

They may not appear immediately after enabling validation.

The first digest can also reference no log files, depending on the delivery interval.

### Does CloudTrail Validate Logs Automatically?

No.

Enabling the feature causes CloudTrail to deliver digest evidence.

Actual validation must be performed separately using AWS CLI or an appropriate validation implementation.

### Does Encryption Prove Integrity?

Encryption protects data confidentiality.

Integrity validation addresses whether the delivered content is unchanged and whether its associated digest evidence is authentic.

These controls serve different purposes.

### Can AWS CLI Validate Locally Downloaded Logs?

The AWS CLI `validate-logs` command validates objects at their original S3 delivery locations.

Locally downloaded files can be investigated with custom hashing tools but are not direct inputs to the AWS CLI validation command.

### Why Is S3 Versioning Useful?

Versioning allows previous object contents to remain available after an object is overwritten.

It supports recovery and investigation.

However, versioning alone does not prevent authorized deletion of object versions. Stronger retention protection may require S3 Object Lock.

### What Does a Successful Validation Mean?

The digest signatures and referenced log contents validated for the covered interval.

It does not prove that every AWS activity was recorded or that the entire AWS account was secure.

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
- Systems Manager permissions.

### Relevant AWS Permissions

```text
sts:GetCallerIdentity

cloudtrail:CreateTrail
cloudtrail:DescribeTrails
cloudtrail:GetTrailStatus
cloudtrail:PutEventSelectors
cloudtrail:StartLogging
cloudtrail:StopLogging
cloudtrail:AddTags
cloudtrail:ListTags
cloudtrail:DeleteTrail
cloudtrail:ValidateLogs
cloudtrail:ListPublicKeys
cloudtrail:LookupEvents

s3:CreateBucket
s3:HeadBucket
s3:PutBucketPolicy
s3:GetBucketPolicy
s3:PutPublicAccessBlock
s3:PutBucketEncryption
s3:PutBucketTagging
s3:GetBucketTagging
s3:PutBucketVersioning
s3:GetBucketVersioning
s3:GetBucketLocation
s3:ListBucket
s3:ListBucketVersions
s3:GetObject
s3:GetObjectVersion
s3:PutObject
s3:DeleteObject
s3:DeleteObjectVersion
s3:DeleteBucket

ssm:PutParameter
ssm:DeleteParameter
```

### Safety Rules

- Never modify production CloudTrail logs.
- Never disable production audit logging.
- Use a dedicated Lab 09 bucket and trail.
- Verify resource ownership before any destructive operation.
- Preserve the original version before modifying a log object.
- Do not modify digest files.
- Complete healthy validation before fault injection.
- Keep the fault injection optional.
- Do not publish raw CloudTrail evidence.
- Stop and delete the trail before removing audit objects.
- Delete all versions and delete markers during cleanup.

### Cost Considerations

Possible charges include S3 storage, versioned S3 objects, requests, and additional CloudTrail management-event copies.

Keep the dedicated trail active only as needed to receive the required log and digest files.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Create Lab Directory

```bash
cd ~/aws-cloudtrail-troubleshooting-labs

mkdir -p 09-cloudtrail-log-integrity-validation

cd 09-cloudtrail-log-integrity-validation
```

### Step 2 — Verify AWS CLI and Python

```bash
aws --version
python3 --version
aws sts get-caller-identity
```

### Step 3 — Configure Environment Variables

```bash
export AWS_REGION="us-east-1"
export AWS_PAGER=""

export ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text)

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab09"

export TRAIL_NAME="cloudtrail-lab09-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export LOG_BUCKET="cloudtrail-lab09-${ACCOUNT_ID}-${SUFFIX}"

export PARAMETER_PREFIX="/cloudtrail-lab09"

export VALIDATION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

### Step 4 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$TRAIL_ARN"
echo "$LOG_BUCKET"
echo "$VALIDATION_START"
```

### Step 5 — Save Resource Information

```bash
cat > lab09-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export LOG_BUCKET="$LOG_BUCKET"
export PARAMETER_PREFIX="$PARAMETER_PREFIX"
export VALIDATION_START="$VALIDATION_START"
EOF
```

To restore:

```bash
source lab09-resources.env
```

### Step 6 — Inspect Existing Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

Ensure the Lab 09 trail name isn't already used.

---

## 7. Create a Versioned S3 Audit Bucket

### Step 1 — Create the Bucket

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

### Step 4 — Enable Versioning

```bash
aws s3api put-bucket-versioning \
  --bucket "$LOG_BUCKET" \
  --versioning-configuration Status=Enabled \
  --region "$AWS_REGION"
```

### Step 5 — Verify Versioning

```bash
aws s3api get-bucket-versioning \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Expected:

```json
{
  "Status": "Enabled"
}
```

### Step 6 — Tag the Bucket

```bash
aws s3api put-bucket-tagging \
  --bucket "$LOG_BUCKET" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 7 — Verify Bucket

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Expected Configuration

| Setting | Expected |
|---|---|
| S3 bucket | Available |
| Public access | Blocked |
| Encryption | SSE-S3 |
| Versioning | Enabled |
| AWS Region | us-east-1 |
| Project tag | Present |

---

## 8. Configure CloudTrail S3 Permissions

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
            "Sid": "AWSCloudTrailAclCheck",
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
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
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

print("CloudTrail S3 policy generated")
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

### Step 5 — Verify Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$LOG_BUCKET" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Expected CloudTrail permissions:

```text
s3:GetBucketAcl
s3:PutObject
```

The log bucket policy remains unchanged throughout this lab.

---

## 9. Create a CloudTrail Trail with Integrity Validation

### Step 1 — Create Trail

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$LOG_BUCKET" \
  --no-is-multi-region-trail \
  --no-include-global-service-events \
  --enable-log-file-validation \
  --region "$AWS_REGION"
```

The important option is:

```text
--enable-log-file-validation
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
  --event-selectors ReadWriteType=All,IncludeManagementEvents=true \
  --region "$AWS_REGION"
```

### Step 4 — Start Logging

```bash
aws cloudtrail start-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Integrity Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,HomeRegion:HomeRegion,IntegrityValidation:LogFileValidationEnabled,Bucket:S3BucketName}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
IntegrityValidation = true
```

### Step 6 — Verify Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError,LatestDigestDeliveryTime:LatestDigestDeliveryTime,LatestDigestDeliveryError:LatestDigestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
IsLogging = true
```

Digest delivery fields might not yet contain values.

### Step 7 — Save Evidence

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab09-trail-configuration.json
```

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab09-initial-status.json
```

---

## 10. Generate Management Events

### Step 1 — Create Unique Parameter Names

```bash
export EVENT_ID="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export PARAMETER_ONE="${PARAMETER_PREFIX}/event-one-${EVENT_ID}"

export PARAMETER_TWO="${PARAMETER_PREFIX}/event-two-${EVENT_ID}"
```

### Step 2 — Create First Parameter

```bash
aws ssm put-parameter \
  --name "$PARAMETER_ONE" \
  --type String \
  --tier Standard \
  --value "cloudtrail-integrity-event-one" \
  --region "$AWS_REGION"
```

### Step 3 — Create Second Parameter

```bash
aws ssm put-parameter \
  --name "$PARAMETER_TWO" \
  --type String \
  --tier Standard \
  --value "cloudtrail-integrity-event-two" \
  --region "$AWS_REGION"
```

### Step 4 — Save Parameter Names

```bash
cat > lab09-parameters.env <<EOF
export PARAMETER_ONE="$PARAMETER_ONE"
export PARAMETER_TWO="$PARAMETER_TWO"
EOF
```

### Step 5 — Search Event History

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab09-event-history.json
```

CloudTrail Event history may take time to index newly generated operations.

### Baseline Summary

| Component | Expected |
|---|---|
| Trail logging | Enabled |
| Integrity validation | Enabled |
| S3 bucket | Available |
| Test API calls | Successful |
| Management event selection | Enabled |
| Audit delivery | Pending or successful |
| Digest delivery | Asynchronous |

---

<WritingBlock id="90472" variant="document">## 11. Inspect CloudTrail Log and Digest Delivery

### Step 1 — Inspect Normal Log Files

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

### Step 2 — Inspect Digest Files

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail-Digest/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Normal logs and digest files are delivered into separate S3 prefixes.

### Expected Structure

```text
s3://LAB_BUCKET/
└── AWSLogs/
    └── ACCOUNT_ID/
        ├── CloudTrail/
        │   └── us-east-1/
        │       └── YYYY/MM/DD/
        │           └── audit-log.json.gz
        │
        └── CloudTrail-Digest/
            └── us-east-1/
                └── YYYY/MM/DD/
                    └── digest.json.gz
```

### Step 3 — Check Digest Delivery

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDigestDeliveryTime:LatestDigestDeliveryTime,LatestDigestDeliveryError:LatestDigestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

CloudTrail generally delivers digest files approximately hourly. If none have arrived yet, do not interpret that alone as an integrity failure.

### Step 4 — Download Digest Files

```bash
mkdir -p evidence/digests

aws s3 cp \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail-Digest/${AWS_REGION}/" \
  evidence/digests/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 5 — Download Audit Logs

```bash
mkdir -p evidence/logs

aws s3 cp \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Delivery Summary

| Component | Expected |
|---|---|
| Normal audit logs | Delivered |
| Digest files | Delivered after reporting interval |
| Digest delivery error | None affecting validation |
| Log prefix | CloudTrail/us-east-1 |
| Digest prefix | CloudTrail-Digest/us-east-1 |

A valid digest may reference zero log files for a particular interval. The next phase requires a digest that references an actual log object.

---

## 12. Inspect CloudTrail Digest Files

### Step 1 — Create Digest Inspection Script

Save as `inspect-digest.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import os

directory = "evidence/digests"

files = sorted(glob.glob(
    os.path.join(directory, "**", "*.json.gz"),
    recursive=True
))

if not files:
    raise SystemExit("No digest files found")

for filename in files:
    with gzip.open(filename, "rt") as file:
        digest = json.load(file)

    print("\nDigest:", filename)
    print("Start:", digest.get("digestStartTime"))
    print("End:", digest.get("digestEndTime"))
    print("Bucket:", digest.get("digestS3Bucket"))
    print("Object:", digest.get("digestS3Object"))

    print(
        "Signature algorithm:",
        digest.get("digestSignatureAlgorithm")
    )

    print(
        "Previous digest:",
        digest.get("previousDigestS3Object")
    )

    logs = digest.get("logFiles", [])

    print("Referenced logs:", len(logs))

    for item in logs:
        print("  S3 key:", item.get("s3Object"))
        print("  Hash:", item.get("hashValue"))
```

### Step 2 — Run Inspection

```bash
python3 inspect-digest.py
```

### Digest Fields

| Field | Purpose |
|---|---|
| digestStartTime | Beginning of delivery interval |
| digestEndTime | End of delivery interval |
| digestS3Bucket | Digest destination bucket |
| digestS3Object | Digest object key |
| digestSignatureAlgorithm | Signature algorithm |
| previousDigestS3Object | Previous digest reference |
| previousDigestHashValue | Previous digest hash |
| logFiles | Referenced log files |
| logFiles[].s3Bucket | Referenced log bucket |
| logFiles[].s3Object | Referenced log key |
| logFiles[].hashValue | Recorded log hash |
| logFiles[].hashAlgorithm | Hash algorithm |

### Step 3 — Create Referenced Log Selector

Save as `select-referenced-log.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import os

bucket = os.environ["LOG_BUCKET"]
account = os.environ["ACCOUNT_ID"]
region = os.environ["AWS_REGION"]

prefix = f"AWSLogs/{account}/CloudTrail/{region}/"

digest_files = sorted(glob.glob(
    "evidence/digests/**/*.json.gz",
    recursive=True
))

for filename in digest_files:
    with gzip.open(filename, "rt") as file:
        digest = json.load(file)

    if digest.get("digestS3Bucket") != bucket:
        continue

    for log in digest.get("logFiles", []):
        key = log.get("s3Object", "")

        if (
            log.get("s3Bucket") == bucket
            and key.startswith(prefix)
            and key.endswith(".json.gz")
        ):
            with open("lab09-target-log-key.txt", "w") as f:
                f.write(key + "\n")

            with open("lab09-target-hash.txt", "w") as f:
                f.write(log["hashValue"] + "\n")

            print("Selected log:", key)
            print("Expected hash:", log["hashValue"])

            raise SystemExit(0)

raise SystemExit("No referenced lab log found")
```

### Step 4 — Select a Referenced Log

```bash
python3 select-referenced-log.py
```

The script selects an actual log referenced by one of the downloaded digests.

### Step 5 — Verify the S3 Object

```bash
export TARGET_LOG_KEY="$(cat lab09-target-log-key.txt)"
```

```bash
aws s3api head-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  --query '{Size:ContentLength,Version:VersionId,Encryption:ServerSideEncryption}' \
  --output json \
  --region "$AWS_REGION"
```

### Investigation Conclusion

We now have the exact S3 object key and original SHA-256 hash recorded in a CloudTrail digest file.

Before trusting that digest as authentic, we must perform AWS's signature and chain validation in the next phase.

---

## 13. Validate Healthy CloudTrail Logs

### Step 1 — Run Official AWS Validation

```bash
aws cloudtrail validate-logs \
  --trail-arn "$TRAIL_ARN" \
  --start-time "$VALIDATION_START" \
  --s3-bucket "$LOG_BUCKET" \
  --verbose \
  --region "$AWS_REGION" \
  2>&1 | tee lab09-healthy-validation.txt
```

### Step 2 — Inspect Validation Results

```bash
tail -n 30 lab09-healthy-validation.txt
```

The validator checks the signed digest chain and referenced log objects within the covered delivery interval.

Expected after successful delivery and validation:

```text
Digest files valid
Log files valid
```

Actual output includes file paths and totals. Do not fabricate these results.

### Step 3 — Verify the Target Log Was Covered

```bash
grep -F "$TARGET_LOG_KEY" \
  lab09-healthy-validation.txt
```

Confirm the target log was actually validated and marked valid.

### Step 4 — Save Validation End Time

```bash
export VALIDATION_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '%s\n' "$VALIDATION_END" \
  > lab09-validation-end.txt
```

### Step 5 — Confirm a Meaningful Validation

A meaningful successful baseline requires:

- One or more applicable digest files.
- Valid digest signature and chain results.
- One or more validated log files.
- The selected target log included in the validation output.
- No unresolved integrity failure affecting the target.

An empty validation interval does not establish log integrity.

### Validation Summary

| Check | Expected |
|---|---|
| Digest retrieved | Yes |
| Digest signature | Valid |
| Digest chain | Valid for covered interval |
| Target log referenced | Yes |
| Log content hash | Matches digest |
| AWS CLI validation | Successful |

---

## 14. Demonstrate SHA-256 Integrity Detection Locally

### Step 1 — Download the Referenced Log

```bash
mkdir -p evidence/tamper-test
```

```bash
aws s3api get-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  evidence/tamper-test/original.json.gz \
  --region "$AWS_REGION"
```

### Step 2 — Create Hash Comparison Script

Save as `compare-digest-hash.py`:

```python
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

filename, hash_filename = sys.argv[1:]

with open(hash_filename) as file:
    expected = file.read().strip().lower()

with gzip.open(filename, "rb") as file:
    content = file.read()

actual = hashlib.sha256(content).hexdigest()

print("Expected SHA-256:", expected)
print("Actual SHA-256:  ", actual)

if actual != expected:
    print("FAILURE: Log hash mismatch")
    sys.exit(1)

print("SUCCESS: Log matches digest hash")
```

CloudTrail records the SHA-256 hash of the uncompressed log content in the digest.

### Step 3 — Verify Original File

```bash
python3 compare-digest-hash.py \
  evidence/tamper-test/original.json.gz \
  lab09-target-hash.txt
```

Expected:

```text
SUCCESS: Log matches digest hash
```

### Step 4 — Create a Modified Local Copy

```bash
python3 - <<'PY'
import gzip
import json

source = "evidence/tamper-test/original.json.gz"
target = "evidence/tamper-test/modified.json.gz"

with gzip.open(source, "rt") as file:
    document = json.load(file)

document["lab09IntegrityTest"] = "Modified after delivery"

with gzip.open(target, "wt") as file:
    json.dump(document, file)

print("Modified local audit copy created")
PY
```

### Step 5 — Compare Modified File

```bash
python3 compare-digest-hash.py \
  evidence/tamper-test/modified.json.gz \
  lab09-target-hash.txt
```

Expected:

```text
FAILURE: Log hash mismatch
```

### Local Verification

| File | Expected |
|---|---|
| original.json.gz | Hash matches |
| modified.json.gz | Hash mismatch |
| Original digest | Unchanged |
| Modification detection | Successful |

This demonstrates content integrity checking without making any changes to the S3 audit bucket.

---

## 15. Optional Fault Injection — Modify a Versioned S3 Log

**Warning:** Only perform this phase on the dedicated Lab 09 bucket. This phase is optional and must not be used on production audit logs.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

### Step 2 — Verify Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Confirm:

```text
CloudTrail-Troubleshooting-Lab09
```

### Step 3 — Verify Target Key Scope

```bash
case "$TARGET_LOG_KEY" in
  AWSLogs/"$ACCOUNT_ID"/CloudTrail/"$AWS_REGION"/*.json.gz)
    echo "Target object path verified"
    ;;
  *)
    echo "Unexpected object path"
    exit 1
    ;;
esac
```

### Step 4 — Save Original Object Version ID

```bash
export ORIGINAL_VERSION_ID=$(aws s3api head-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  --query VersionId \
  --output text \
  --region "$AWS_REGION")
```

Verify the version ID is not `None` or `null`.

```bash
printf '%s\n' "$ORIGINAL_VERSION_ID" \
  > lab09-original-version-id.txt
```

### Step 5 — Verify Backup

```bash
test -s evidence/tamper-test/original.json.gz
```

```bash
python3 compare-digest-hash.py \
  evidence/tamper-test/original.json.gz \
  lab09-target-hash.txt
```

Only continue if the original file matches the digest hash.

### Step 6 — Replace the Current S3 Object

```bash
aws s3api put-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  --body evidence/tamper-test/modified.json.gz \
  --content-type "application/json" \
  --content-encoding "gzip" \
  --expected-bucket-owner "$ACCOUNT_ID" \
  --region "$AWS_REGION"
```

Because S3 Versioning is enabled, a new current object version is created.

The original object version remains available.

### Step 7 — Verify the Current Version

```bash
aws s3api head-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  --query '{Version:VersionId,Size:ContentLength}' \
  --output json \
  --region "$AWS_REGION"
```

The current version should differ from the original version.

### Step 8 — Run CloudTrail Validation Again

```bash
set -o pipefail

aws cloudtrail validate-logs \
  --trail-arn "$TRAIL_ARN" \
  --start-time "$VALIDATION_START" \
  --end-time "$VALIDATION_END" \
  --s3-bucket "$LOG_BUCKET" \
  --verbose \
  --region "$AWS_REGION" \
  2>&1 | tee lab09-tampered-validation.txt
```

### Step 9 — Investigate the Failure

```bash
grep -i -E 'invalid|modified|mismatch|valid' \
  lab09-tampered-validation.txt
```

Expected: the modified target log should be reported as invalid.

Do not rely only on a process exit code. Inspect the actual validator output and confirm the specific target file was checked.

### Fault Evidence

| Component | Expected |
|---|---|
| Digest | Original, unchanged |
| Target S3 key | Same |
| Current object contents | Modified |
| Original object version | Preserved |
| Digest hash | Original hash |
| Current log hash | Different |
| Validation | Target log invalid |

---

## 16. Root Cause Analysis

### Root Cause

The S3 log object was modified after CloudTrail delivered it.

The digest file retained the SHA-256 hash of the original log contents.

The modified log's current contents no longer matched that recorded hash.

As a result, integrity validation identified the file as invalid.

### Root Cause Diagram

```text
CloudTrail Delivers Log
          |
          v
Original SHA-256 Recorded
          |
          v
Digest File Signed
          |
          v
Log Object Stored in S3
          |
          v
Post-Delivery Modification
          |
          v
Current Log SHA-256 Changes
          |
          v
Digest Hash Mismatch
          |
          v
Integrity Validation Failure
```

### Five Whys

**Why 1 — Why did validation fail?**

The log file's current hash did not match the digest.

**Why 2 — Why did the hash differ?**

The file contents were modified.

**Why 3 — Why could the change be detected?**

The original file hash was recorded in a signed CloudTrail digest.

**Why 4 — Why is this important?**

Audit files must be trustworthy during security investigations.

**Why 5 — How can this risk be reduced?**

Protect audit buckets, restrict modification permissions, implement integrity verification, and use stronger retention controls when appropriate.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-009 |
| AWS Service | CloudTrail |
| Storage | Amazon S3 |
| Fault | Post-delivery audit log modification |
| Detection | SHA-256 mismatch |
| Validation Mechanism | Signed digest chain |
| Root Cause | Current object contents changed |
| Remediation | Restore original contents |
| Verification | Successful AWS CLI log validation |

---

<WritingBlock id="90473" variant="document">## 17. Remediation — Restore the Original Log Object

This phase applies only if the optional S3 fault injection was performed.

### Step 1 — Retrieve the Original Version

```bash
aws s3api get-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  --version-id "$ORIGINAL_VERSION_ID" \
  evidence/tamper-test/restored-original.json.gz \
  --region "$AWS_REGION"
```

### Step 2 — Verify Original Hash

```bash
python3 compare-digest-hash.py \
  evidence/tamper-test/restored-original.json.gz \
  lab09-target-hash.txt
```

Expected:

```text
SUCCESS: Log matches digest hash
```

### Step 3 — Restore Current S3 Contents

```bash
aws s3api put-object \
  --bucket "$LOG_BUCKET" \
  --key "$TARGET_LOG_KEY" \
  --body evidence/tamper-test/restored-original.json.gz \
  --content-type "application/json" \
  --content-encoding "gzip" \
  --expected-bucket-owner "$ACCOUNT_ID" \
  --region "$AWS_REGION"
```

This creates a new version containing the original log bytes.

### Step 4 — Validate the Restored Log

```bash
aws cloudtrail validate-logs \
  --trail-arn "$TRAIL_ARN" \
  --start-time "$VALIDATION_START" \
  --end-time "$VALIDATION_END" \
  --s3-bucket "$LOG_BUCKET" \
  --verbose \
  --region "$AWS_REGION" \
  2>&1 | tee lab09-restored-validation.txt
```

### Step 5 — Inspect Validation Results

```bash
tail -n 30 lab09-restored-validation.txt
```

Confirm that the affected log validates successfully and that no additional covered log or digest failures remain.

### Before and After Comparison

| Investigation | Original | Modified | Restored |
|---|---|---|---|
| Original digest | Valid | Valid | Valid |
| Current log contents | Original | Changed | Original |
| SHA-256 | Matches | Different | Matches |
| AWS validation | Valid | Invalid | Valid |
| Original S3 version | Available | Available | Available |
| Incident state | Healthy | Integrity violation | Technically recovered |

### Production Forensics Consideration

Restoring original bytes does not erase the fact that the object was modified.

In a real incident, preserve the original and modified versions, relevant CloudTrail records, timestamps, and change history before performing recovery.

If the evidence is needed for legal or compliance purposes, follow the organization's approved evidence-retention and chain-of-custody procedures.

---

## 18. Production Troubleshooting Best Practices

### Investigation Workflow

```text
Suspected Audit Log Modification
              |
              v
Identify CloudTrail Trail
              |
              v
Verify Log File Validation Enabled
              |
              v
Inspect S3 Log Destination
              |
              v
Check Digest Delivery Status
              |
              v
Retrieve Relevant Digest Files
              |
              v
Run AWS CLI ValidateLogs
              |
              v
Inspect Digest Signature Results
              |
              v
Inspect Referenced Log Hashes
              |
              v
Identify Invalid or Missing Objects
              |
              v
Preserve Relevant Evidence
              |
              v
Investigate Object Changes
              |
              v
Recover When Authorized
              |
              v
Verify and Document Findings
```

### Other Integrity Validation Scenarios

| Symptom | Possible Cause | Investigation |
|---|---|---|
| No digest files | Delivery timing or failure | GetTrailStatus |
| Validation disabled | Trail configuration | DescribeTrails |
| Invalid log hash | Modified object | ValidateLogs |
| Missing referenced log | Deleted or unavailable object | S3 GetObject |
| Invalid digest signature | Modified digest or invalid evidence | ValidateLogs |
| Digest chain gap | Missing digest or interrupted validation | Digest chain |
| AccessDenied during validation | Missing S3 read permissions | IAM and bucket policy |
| Local file hash mismatch | Modified local contents | SHA-256 comparison |
| Cannot delete lab bucket | Object versions remain | ListObjectVersions |

### Production Security Recommendations

- Enable CloudTrail log file integrity validation.
- Protect centralized audit S3 buckets.
- Restrict `s3:PutObject` and `s3:DeleteObject` access to audit paths.
- Use bucket versioning where appropriate.
- Consider S3 Object Lock for retention requirements.
- Encrypt stored audit records.
- Monitor CloudTrail configuration changes.
- Monitor unauthorized modifications to audit destinations.
- Validate logs during incident response.
- Preserve evidence before remediation.
- Keep audit infrastructure separate from application resources.
- Verify digest delivery and investigate validation gaps.

### Important Security Principle

CloudTrail log integrity validation provides evidence about the authenticity and unchanged state of the covered logs.

It does not guarantee that all AWS activity was recorded, that logging was always enabled, or that the AWS account was never compromised.

---

## 19. AWS Resource Cleanup

**Warning:** This lab uses S3 Versioning. Removing only current objects does not empty the bucket. All object versions and delete markers must be deleted before removing the bucket.

### Step 1 — Verify Trail Ownership

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

### Step 2 — Verify Bucket Ownership

```bash
aws s3api get-bucket-tagging \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Confirm:

```text
Project=CloudTrail-Troubleshooting-Lab09
```

### Step 3 — Stop the Trail

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 4 — Delete the Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

CloudTrail can deliver a final digest after logging stops. Verify that the trail has been deleted and log delivery is no longer continuing before emptying the bucket.

### Step 5 — Restore Parameter Variables

```bash
source lab09-parameters.env
```

### Step 6 — Delete Test Parameters

```bash
for PARAMETER in "$PARAMETER_ONE" "$PARAMETER_TWO"
do
  case "$PARAMETER" in
    /cloudtrail-lab09/*)
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

### Step 7 — Create Versioned Bucket Cleanup Script

Save as `cleanup-versioned-bucket.py`:

```python
#!/usr/bin/env python3

import json
import os
import subprocess
import sys

bucket = os.environ["LOG_BUCKET"]
region = os.environ["AWS_REGION"]
account = os.environ["ACCOUNT_ID"]
project = os.environ["PROJECT_TAG"]

expected_prefix = f"cloudtrail-lab09-{account}-"

if not bucket.startswith(expected_prefix):
    sys.exit("Bucket name failed safety check")

def aws_cli(*args):
    result = subprocess.run(
        ["aws", *args, "--region", region, "--output", "json"],
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(result.stdout)

tags_result = aws_cli(
    "s3api", "get-bucket-tagging",
    "--bucket", bucket
)

tags = {
    item["Key"]: item["Value"]
    for item in tags_result.get("TagSet", [])
}

if tags.get("Project") != project:
    sys.exit("Bucket ownership tag failed safety check")

while True:
    # Retrieve only the first page on each iteration.
    # After deleting it, request the first page again.
    # This avoids pagination skips during deletion.
    result = aws_cli(
        "s3api", "list-object-versions",
        "--bucket", bucket,
        "--max-keys", "1000",
        "--no-paginate"
    )

    objects = [
        {
            "Key": item["Key"],
            "VersionId": item["VersionId"]
        }
        for category in ("Versions", "DeleteMarkers")
        for item in result.get(category, [])
    ]

    if not objects:
        print("No object versions remain")
        break

    response = aws_cli(
        "s3api", "delete-objects",
        "--bucket", bucket,
        "--delete", json.dumps({
            "Objects": objects,
            "Quiet": True
        })
    )

    if response.get("Errors"):
        print(json.dumps(response["Errors"], indent=2))
        sys.exit("Object version deletion failed")

    print(f"Deleted {len(objects)} versions or markers")

print("Versioned bucket cleanup complete")
```

### Step 8 — Execute Cleanup Script

```bash
python3 cleanup-versioned-bucket.py
```

The script checks the account-specific lab bucket prefix and project tag before deleting objects.

It repeatedly retrieves a page of object versions and delete markers, deletes them, and continues until none remain.

**Do not run this script against production buckets or buckets containing retained audit evidence.**

### Step 9 — Verify the Bucket Is Empty

```bash
aws s3api list-object-versions \
  --bucket "$LOG_BUCKET" \
  --query '{Versions:Versions,DeleteMarkers:DeleteMarkers}' \
  --output json \
  --region "$AWS_REGION"
```

Expected: no remaining versions or delete markers.

### Step 10 — Delete the Bucket

```bash
aws s3api delete-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 11 — Verify CloudTrail Cleanup

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

### Step 12 — Verify Bucket Deletion

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Expected: a not-found response.

### Cleanup Summary

| Resource | Expected State |
|---|---|
| CloudTrail trail | Deleted |
| Test parameters | Deleted |
| S3 audit bucket | Deleted |
| S3 object versions | Deleted |
| Delete markers | Deleted |
| Lab-generated digest files | Deleted |
| Production trails | Unchanged |
| Other audit buckets | Unchanged |
| EC2 resources | None created |
| KMS keys | None created |

---

## 20. Interview Questions and Answers

### Q1. What is CloudTrail log file integrity validation?

A feature that uses signed digest files to help verify that delivered CloudTrail audit logs have not been modified or deleted.

### Q2. What is a digest file?

A file containing information about delivered log files, including their S3 locations and SHA-256 hashes.

### Q3. Which hash algorithm does CloudTrail use?

SHA-256.

### Q4. Which digital signature algorithm is used for digest files?

SHA256withRSA.

### Q5. How frequently are digest files delivered?

Generally approximately hourly.

### Q6. Does enabling log file integrity validation automatically validate logs?

No. It enables digest delivery. The actual verification is a separate process.

### Q7. How do you enable log file integrity validation?

Use the `--enable-log-file-validation` option when creating or updating the trail.

### Q8. Which AWS CLI command validates CloudTrail logs?

```bash
aws cloudtrail validate-logs \
  --trail-arn YOUR_TRAIL_ARN \
  --start-time YOUR_START_TIME \
  --region us-east-1
```

### Q9. What does an invalid CloudTrail log indicate?

The log cannot be verified against its expected digest evidence. It may have been modified, deleted, or otherwise become unavailable.

### Q10. Why is SHA-256 important?

It allows engineers to detect changes to file contents by comparing cryptographic hashes.

### Q11. What is a digest chain?

A sequence of signed digest files connected using references to earlier digest information.

### Q12. Can AWS CLI validate a locally downloaded CloudTrail log?

The built-in `validate-logs` command validates logs at their original S3 locations. Custom tools can inspect downloaded copies.

### Q13. Does SSE-S3 replace log integrity validation?

No. Encryption and integrity validation address different security requirements.

### Q14. Why is S3 Versioning useful for this lab?

It preserves previous object versions when a new version is uploaded.

### Q15. Does S3 Versioning make audit objects immutable?

No. Authorized identities may still delete object versions. S3 Object Lock can provide stronger retention protection.

### Q16. What happens when a CloudTrail log file is modified?

Its current hash can differ from the hash recorded in the original digest.

### Q17. Why is a signed digest more trustworthy than a separately saved hash?

The signature helps authenticate the digest itself, rather than relying only on an unauthenticated hash value.

### Q18. Can an empty validation result prove audit integrity?

No. Engineers must verify that applicable digest files and log objects were included in the validation.

### Q19. Why should security teams preserve modified objects during investigation?

They may contain evidence about the modification, including the extent and nature of the change.

### Q20. How would you explain this lab in an interview?

I created a dedicated CloudTrail trail with log file integrity validation enabled.

I configured a private S3 bucket with versioning and generated management events using Systems Manager.

After CloudTrail delivered audit logs and digest files, I inspected the digest structure and selected an actual referenced log.

I used AWS CLI to validate the digest signatures and log hashes.

Then I modified a local copy of the referenced log and verified that its SHA-256 hash no longer matched the original digest.

For the optional S3 test, I replaced the current version of the disposable audit object and ran CloudTrail validation again to identify the integrity failure.

I retrieved the original object version, restored its contents, and validated the recovered log.

Finally, I deleted the trail, test parameters, all S3 object versions, and the dedicated bucket.

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
│
├── 09-cloudtrail-log-integrity-validation/
│   ├── README.md
│   ├── generate-s3-policy.py
│   ├── inspect-digest.py
│   ├── select-referenced-log.py
│   ├── compare-digest-hash.py
│   ├── cleanup-versioned-bucket.py
│   ├── cloudtrail-s3-policy.json
│   ├── lab09-resources.env
│   ├── lab09-parameters.env
│   ├── lab09-trail-configuration.json
│   ├── lab09-initial-status.json
│   ├── lab09-event-history.json
│   ├── lab09-target-log-key.txt
│   ├── lab09-target-hash.txt
│   ├── lab09-original-version-id.txt
│   ├── lab09-validation-end.txt
│   ├── lab09-healthy-validation.txt
│   ├── lab09-tampered-validation.txt
│   ├── lab09-restored-validation.txt
│   │
│   └── evidence/
│       ├── digests/
│       ├── logs/
│       └── tamper-test/
│           ├── original.json.gz
│           ├── modified.json.gz
│           └── restored-original.json.gz
│
└── 10-cloudtrail-lake-query-troubleshooting/
```

### File Descriptions

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `generate-s3-policy.py` | Generates CloudTrail S3 policy |
| `inspect-digest.py` | Displays digest metadata and referenced logs |
| `select-referenced-log.py` | Selects a digest-referenced log |
| `compare-digest-hash.py` | Compares the SHA-256 hash of uncompressed log contents |
| `cleanup-versioned-bucket.py` | Deletes versions and delete markers |
| `cloudtrail-s3-policy.json` | Generated log delivery policy |
| `lab09-resources.env` | Lab resource identifiers |
| `lab09-parameters.env` | Test parameter names |
| `lab09-trail-configuration.json` | Trail configuration |
| `lab09-initial-status.json` | Initial CloudTrail status |
| `lab09-event-history.json` | Generated management events |
| `lab09-target-log-key.txt` | Selected S3 object key |
| `lab09-target-hash.txt` | SHA-256 recorded in digest |
| `lab09-original-version-id.txt` | Original S3 version ID |
| `lab09-validation-end.txt` | End of fixed validation window |
| `lab09-healthy-validation.txt` | Initial integrity validation |
| `lab09-tampered-validation.txt` | Integrity failure evidence |
| `lab09-restored-validation.txt` | Recovery validation |
| `evidence/` | Downloaded logs, digests, and test files |

### Recommended .gitignore

```gitignore
__pycache__/
*.pyc
.venv/
.env

**/lab09-resources.env
**/lab09-parameters.env
**/lab09-*.json
**/lab09-*.txt
**/cloudtrail-s3-policy.json
**/evidence/digests/
**/evidence/logs/
**/evidence/tamper-test/
```

Do not commit raw audit records, unredacted digest files, account-specific object keys, or actual validation outputs without reviewing them.

### Lessons Learned

This lab demonstrates how CloudTrail cryptographic digest files can help verify the integrity of AWS audit records.

We created a dedicated trail and enabled log file integrity validation.

We configured an encrypted S3 destination with versioning and generated management events.

We inspected the delivered log files and digest files.

We used the AWS CLI to verify the digest signatures and log hashes.

We then demonstrated that modifying log contents causes a SHA-256 hash mismatch.

In the optional cloud-based test, we modified only a disposable S3 audit object and confirmed that the validator could detect the integrity issue.

We restored the original log contents using S3 Versioning and revalidated the affected audit records.

Finally, we removed the temporary AWS resources and all S3 object versions.

**Key Lesson:** A CloudTrail log existing in S3 does not automatically prove it is authentic and unchanged. Signed digest files and cryptographic validation provide stronger evidence of integrity for security investigations.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail log integrity validation
- SHA-256 hashing
- RSA digital signatures
- CloudTrail digest files
- Digest-chain investigation
- Amazon S3
- S3 Versioning
- S3 object recovery
- AWS CLI v2
- Linux Bash
- Python 3
- GZIP and JSON processing
- AWS audit log analysis
- File integrity investigation
- Controlled fault injection
- Security incident response
- Digital forensic principles
- Root cause analysis
- Remediation verification
- Versioned bucket cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-009 |
| Scenario | CloudTrail Log Integrity Validation |
| Trail | cloudtrail-lab09-trail |
| Region | us-east-1 |
| Log Validation | Enabled |
| Digest Delivery | Verified |
| Hash Algorithm | SHA-256 |
| Digest Signature | SHA256withRSA |
| Original Log | Valid |
| Modified Log | Hash mismatch |
| AWS Tamper Test | Optional |
| Restored Log | Valid |
| Root Cause | Post-delivery content modification |
| Cleanup | Trail, parameters, and versioned bucket removed |
| Incident Status | Resolved after successful recovery validation |

**Key Takeaway:** Cloud Security Engineers must understand how to verify the authenticity and integrity of audit logs, not only how to enable logging.

---

## Official AWS Documentation

- [CloudTrail Log File Integrity Validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [Enabling CloudTrail Integrity Validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html)
- [CloudTrail Digest File Structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)
- [Validating Logs with AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html)
- [Custom CloudTrail Log Validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html)
- [AWS CLI — ValidateLogs](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/validate-logs.html)
- [Amazon S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)