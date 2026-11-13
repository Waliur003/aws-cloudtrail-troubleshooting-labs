# Lab 05 — CloudTrail KMS Encryption Failure

### AWS CloudTrail Troubleshooting Labs | Cloud Security Engineering

## Overview

This lab demonstrates how to investigate and resolve an AWS CloudTrail log delivery failure caused by incorrect AWS Key Management Service (KMS) permissions.

AWS CloudTrail records supported AWS API activity and delivers selected audit logs to Amazon S3. Organizations can configure CloudTrail to encrypt those logs using a customer-managed AWS KMS key.

However, CloudTrail requires the correct permissions to use that key.

If the KMS key policy is misconfigured, CloudTrail may be unable to encrypt and deliver new log files, even when the trail is enabled and the destination S3 bucket is available.

In this lab, we simulate a production incident where CloudTrail loses permission to generate encryption data keys.

We create a dedicated CloudTrail trail, a private S3 bucket, and a customer-managed KMS key. We configure the required S3 permissions and CloudTrail KMS permissions.

After verifying successful encrypted log delivery, we intentionally replace the KMS key policy with an incomplete version that removes CloudTrail's `kms:GenerateDataKey*` permission.

We investigate the failure using AWS CLI, compare the working and broken key policies, inspect the CloudTrail encryption configuration, and verify that the S3 bucket remains available.

We then restore the KMS key policy, generate a fresh AWS management event, and verify that it is delivered to S3 using SSE-KMS encryption.

Finally, we remove the temporary resources and schedule deletion of the dedicated KMS key.

**Troubleshooting workflow:**

CloudTrail Configuration → S3 Bucket Setup → Customer-Managed KMS Key → Correct Key Policy → SSE-KMS Log Delivery → Remove GenerateDataKey Permission → Encryption Failure → KMS Investigation → Root Cause Analysis → Restore Key Policy → Verify Encrypted S3 Delivery → Cleanup

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-005 |
| Difficulty | Intermediate to Advanced |
| Primary AWS Service | AWS CloudTrail |
| Supporting Services | AWS KMS, Amazon S3, AWS Systems Manager |
| AWS Region | `us-east-1` |
| Operating System | WSL2 Ubuntu |
| Command-Line Interface | AWS CLI v2 |
| Automation | Bash and Python 3 |
| Trail Name | `cloudtrail-lab05-trail` |
| Trail Type | Single-Region |
| Organization Trail | No |
| S3 Destination | Dedicated private lab bucket |
| S3 Bucket Default Encryption | SSE-S3 |
| Trail Log Encryption | SSE-KMS |
| KMS Key Type | Customer-managed symmetric key |
| KMS Key Usage | ENCRYPT_DECRYPT |
| KMS Key State | Enabled |
| Event Category | Management events |
| Event Selectors | Read and write |
| Test API | `PutParameter` |
| Event Source | `ssm.amazonaws.com` |
| Fault Injection | Remove CloudTrail data-key generation permission |
| Broken Permission | `kms:GenerateDataKey*` |
| Correct Policy | `correct-kms-policy.json` |
| Broken Policy | `broken-kms-policy.json` |
| Investigation | CloudTrail, KMS, and S3 configuration |
| Root Cause | KMS key policy authorization failure |
| Remediation | Restore CloudTrail encryption permissions |
| Verification | Recovery event and SSE-KMS metadata |
| Cleanup | Delete lab infrastructure and schedule KMS deletion |

### Lab Objectives

- Understand SSE-KMS encryption for CloudTrail.
- Create a customer-managed KMS key.
- Understand KMS key policies.
- Configure CloudTrail encryption permissions.
- Understand `kms:GenerateDataKey*`.
- Understand `kms:DescribeKey`.
- Understand CloudTrail encryption context.
- Configure a private S3 destination.
- Generate real management events.
- Verify encrypted audit log delivery.
- Reproduce a KMS permission failure.
- Investigate KMS authorization problems.
- Compare correct and incorrect key policies.
- Restore the required permissions.
- Verify encryption on the recovered log object.
- Perform root cause analysis.
- Document investigation evidence.
- Safely delete temporary AWS resources.

---

## 2. Production Incident Scenario

### Incident Description

A company uses AWS CloudTrail to maintain audit records of administrative operations performed across its AWS infrastructure.

CloudTrail delivers management-event logs to Amazon S3.

The company requires these logs to be encrypted with a customer-managed AWS KMS key.

This allows the security team to manage encryption key permissions and control who can decrypt audit records.

During a routine audit, engineers discover that new CloudTrail log files are no longer arriving in S3.

The CloudTrail trail still exists.

The trail reports that logging is enabled.

The S3 bucket also exists, and its CloudTrail write permissions are correctly configured.

However, the CloudTrail KMS key policy was changed.

The new policy no longer grants CloudTrail permission to perform `kms:GenerateDataKey*`.

This prevents CloudTrail from completing the expected encryption workflow for new audit logs.

The engineer investigates the trail's KMS configuration, the key state, the current key policy, and the S3 delivery status.

After identifying the incorrect policy, the engineer restores the required KMS permissions.

A new management event is then generated to verify the recovered pipeline.

The engineer confirms that the event appears in a CloudTrail S3 log file and that the corresponding S3 object uses SSE-KMS encryption with the expected KMS key.

### Incident Symptoms

- CloudTrail trail exists.
- Trail logging remains enabled.
- `IsLogging=true`.
- S3 destination exists.
- S3 bucket policy is correctly configured.
- Customer-managed KMS key exists.
- KMS key state is Enabled.
- Trail references the KMS key.
- CloudTrail data-key generation permission is missing.
- New encrypted log delivery may fail.
- CloudTrail delivery diagnostics may report a KMS-related problem.
- Previously delivered logs may still be present.

### Business Impact

- Interrupted delivery of encrypted audit logs.
- Reduced visibility into AWS account activity.
- Gaps or delays in historical audit records.
- Security incident investigation difficulties.
- Compliance concerns.
- Encryption governance problems.
- Potential delivery retry costs.
- Increased operational risk.

### Objective

Determine why CloudTrail cannot use its configured KMS key, restore the required encryption permissions, and verify successful SSE-KMS log delivery.

---

## 3. AWS Architecture

### Healthy CloudTrail SSE-KMS Architecture

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
                cloudtrail-lab05-trail
                         |
                         v
                  IsLogging = true
                         |
                         v
               Management Event Logs
                         |
                         v
                 AWS KMS Key Policy
                         |
             +-----------+-----------+
             |                       |
             v                       v
       kms:DescribeKey       kms:GenerateDataKey*
             |                       |
             +-----------+-----------+
                         |
                         v
               KMS Data Key Generation
                         |
                         v
                 SSE-KMS Encryption
                         |
                         v
                    Amazon S3
                         |
                         v
                 Encrypted Audit Logs
                         |
                         v
                Security Investigation
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
SSE-KMS Encryption Required
          |
          v
AWS KMS Key Policy
          |
          v
kms:GenerateDataKey* Missing
          |
          v
KMS Authorization Failure
          |
          v
Log Encryption Cannot Complete
          |
          v
S3 Log Delivery Interrupted
```

### Recovered Architecture

```text
CloudTrail Management Events
          |
          v
Customer-Managed KMS Key
          |
          v
Correct KMS Key Policy Restored
          |
          v
GenerateDataKey Authorized
          |
          v
SSE-KMS Encryption Succeeds
          |
          v
Amazon S3 Audit Bucket
          |
          v
Recovery Event Delivered
          |
          v
S3 Object Encryption Verified
```

### Architecture Components

| Component | Purpose |
|---|---|
| AWS CloudTrail | Collects selected AWS API events |
| CloudTrail Trail | Controls ongoing audit log delivery |
| Amazon S3 | Stores audit log objects |
| AWS KMS | Manages encryption keys |
| Customer-Managed KMS Key | Protects CloudTrail log encryption |
| KMS Key Policy | Controls access to the encryption key |
| S3 Bucket Policy | Authorizes CloudTrail log delivery |
| Systems Manager Parameter Store | Generates controlled API events |
| AWS CLI | Investigates and remediates configurations |
| Python | Generates policies and analyzes audit logs |
| Bash | Performs infrastructure operations |

---

## 4. Understanding CloudTrail SSE-KMS Encryption

### What Is AWS KMS?

AWS Key Management Service is a managed service for creating and controlling cryptographic keys.

KMS keys are used by many AWS services to protect stored data.

### What Is SSE-KMS?

SSE-KMS means server-side encryption using AWS KMS keys.

For CloudTrail, it allows audit logs delivered to S3 to be protected using a specified KMS key.

### What Is SSE-S3?

SSE-S3 uses encryption keys managed by Amazon S3.

Unlike SSE-KMS with a customer-managed key, it does not require the user to maintain a separate customer-managed KMS key policy.

### What Is a Customer-Managed KMS Key?

A customer-managed KMS key is created and managed in the AWS account.

The account controls its key policy, lifecycle, and authorized usage.

### What Is GenerateDataKey?

`GenerateDataKey` is a KMS operation that returns data-key material for use in encryption.

For CloudTrail SSE-KMS delivery, the encryption workflow requires data-key generation permissions.

### What Is DescribeKey?

`DescribeKey` retrieves information about a KMS key, including its state and configuration.

CloudTrail requires appropriate permission to inspect the configured key.

### What Is a KMS Key Policy?

A KMS key policy is a resource-based policy controlling access to the KMS key.

It determines which principals may use or administer the key.

### What Is aws:SourceArn?

This IAM condition key can restrict the use of a KMS key to requests associated with a specified CloudTrail trail.

### What Is the CloudTrail Encryption Context?

CloudTrail provides encryption-context information identifying the CloudTrail resource associated with its encryption operation.

A key policy can use the following condition key:

```text
kms:EncryptionContext:aws:cloudtrail:arn
```

### Why Does Encryption Affect Log Delivery?

For SSE-KMS log delivery, CloudTrail must be authorized to use the configured encryption key.

If KMS refuses the required operation, CloudTrail cannot complete delivery through that encryption path.

### What Is IsLogging?

`IsLogging` indicates whether the trail's logging function is enabled.

It does not guarantee successful KMS encryption or S3 delivery.

### Why Is KMS Decrypt Permission Different?

Generating a data key for new log encryption and decrypting an existing log are different operations.

A principal downloading encrypted logs may require `kms:Decrypt`.

Therefore, a local download failure should not automatically be interpreted as a CloudTrail delivery failure.

---

## 5. Prerequisites and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL2 Ubuntu.
- Bash.
- Python 3.
- AWS CloudTrail permissions.
- Amazon S3 permissions.
- AWS KMS administration permissions.
- Systems Manager Parameter Store permissions.
- Git and GitHub.

### Relevant KMS Permissions

```text
kms:CreateKey
kms:DescribeKey
kms:GetKeyPolicy
kms:PutKeyPolicy
kms:GenerateDataKey
kms:Decrypt
kms:TagResource
kms:ListResourceTags
kms:ScheduleKeyDeletion
```

Additional authorization is required for CloudTrail, S3, Systems Manager, and STS operations.

### Safety Rules

- Use only the dedicated Lab 05 KMS key.
- Never modify production KMS key policies.
- Never remove your administrative ability to update the key policy.
- Do not disable a shared KMS key.
- Use a dedicated CloudTrail trail and S3 bucket.
- Verify ownership tags before changing policies.
- Keep the broken-policy period short.
- Save all important audit evidence before cleanup.
- Avoid publishing account-specific key policies.
- Never commit access keys or credentials.
- Schedule deletion only for the disposable lab KMS key.

### Cost Considerations

Potential charges include:

- Customer-managed KMS key usage.
- KMS API requests.
- S3 storage and requests.
- Additional CloudTrail management-event copies.
- CloudTrail retry-related usage.

The key cannot be deleted immediately. AWS KMS requires a deletion waiting period of at least seven days.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Create Lab Directory

```bash
cd ~/aws-cloudtrail-troubleshooting-labs

mkdir -p 05-cloudtrail-kms-encryption-failure

cd 05-cloudtrail-kms-encryption-failure
```

### Step 2 — Verify AWS Authentication

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

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab05"

export TRAIL_NAME="cloudtrail-lab05-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export BUCKET_NAME="cloudtrail-lab05-${ACCOUNT_ID}-${SUFFIX}"

export PARAMETER_PREFIX="/cloudtrail-lab05"
```

### Step 4 — Verify Variables

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$TRAIL_ARN"
echo "$BUCKET_NAME"
```

### Step 5 — Save Resource Information

Create `lab05-resources.env`:

```bash
cat > lab05-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export BUCKET_NAME="$BUCKET_NAME"
export PARAMETER_PREFIX="$PARAMETER_PREFIX"
EOF
```

Restore variables in a later terminal session:

```bash
source lab05-resources.env
```

### Step 6 — Verify Existing CloudTrail Trails

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

Ensure the lab trail does not already exist.

---

## 7. Create and Secure the S3 Bucket

### Step 1 — Create Bucket

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

### Step 3 — Configure Default SSE-S3

```bash
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":false}]}' \
  --region "$AWS_REGION"
```

The default bucket encryption is SSE-S3.

CloudTrail will use SSE-KMS for its delivered objects after the trail is configured with the customer-managed KMS key.

### Step 4 — Tag the Bucket

```bash
aws s3api put-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Bucket Configuration

```bash
aws s3api head-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

```bash
aws s3api get-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Expected Configuration

| Item | Expected |
|---|---|
| S3 bucket | Available |
| AWS Region | us-east-1 |
| Public access | Blocked |
| Default encryption | SSE-S3 |
| Bucket Key | Disabled |
| Project tag | Present |

---

## 8. Configure the CloudTrail S3 Bucket Policy

### Purpose

CloudTrail requires the destination bucket to authorize S3 log delivery.

We configure this policy correctly and leave it unchanged during fault injection.

This isolates the KMS key policy as the source of the failure.

### Step 1 — Create S3 Policy Generator

Save as `generate-s3-policy.py`:

```python
#!/usr/bin/env python3

import json
import os

bucket = os.environ["BUCKET_NAME"]
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
  --bucket "$BUCKET_NAME" \
  --policy file://cloudtrail-s3-policy.json \
  --region "$AWS_REGION"
```

### Step 5 — Verify Applied Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

### Expected Permissions

| Permission | Expected |
|---|---|
| `s3:GetBucketAcl` | Allowed |
| `s3:PutObject` | Allowed |
| CloudTrail service principal | Correct |
| `aws:SourceArn` | Restricted to lab trail |
| S3 destination | Correct account path |

---

## 9. Create the Customer-Managed KMS Key

### Step 1 — Generate the Administrative Policy

Create `kms-admin-policy.json`:

```bash
python3 - <<'PY'
import json
import os

account = os.environ["ACCOUNT_ID"]

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EnableAccountKeyAdministration",
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{account}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        }
    ]
}

with open("kms-admin-policy.json", "w") as file:
    json.dump(policy, file, indent=2)
PY
```

This standard account-principal statement enables IAM-based delegation of KMS key permissions.

It does not independently grant every IAM identity access to use the key.

### Step 2 — Create KMS Key

```bash
export KMS_KEY_ID=$(aws kms create-key \
  --description "Lab05 disposable CloudTrail SSE-KMS key" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --policy file://kms-admin-policy.json \
  --tags "TagKey=Project,TagValue=$PROJECT_TAG" \
  --query 'KeyMetadata.KeyId' \
  --output text \
  --region "$AWS_REGION")
```

### Step 3 — Retrieve Key ARN

```bash
export KMS_KEY_ARN=$(aws kms describe-key \
  --key-id "$KMS_KEY_ID" \
  --query 'KeyMetadata.Arn' \
  --output text \
  --region "$AWS_REGION")
```

### Step 4 — Save KMS Identifiers

```bash
cat >> lab05-resources.env <<EOF
export KMS_KEY_ID="$KMS_KEY_ID"
export KMS_KEY_ARN="$KMS_KEY_ARN"
EOF
```

### Step 5 — Verify KMS Key Metadata

```bash
aws kms describe-key \
  --key-id "$KMS_KEY_ID" \
  --query 'KeyMetadata.{Arn:Arn,State:KeyState,Usage:KeyUsage,Spec:KeySpec,Manager:KeyManager}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
KeyState = Enabled
KeyUsage = ENCRYPT_DECRYPT
KeySpec = SYMMETRIC_DEFAULT
KeyManager = CUSTOMER
```

---

## 10. Generate Correct and Broken KMS Policies

### Purpose

We create two key policies.

The correct policy allows CloudTrail to describe the key and generate encryption data keys.

The broken policy preserves key administration and CloudTrail key-description access but removes the CloudTrail data-key permission.

### Step 1 — Create Policy Generator

Save as `generate-kms-policies.py`:

```python
#!/usr/bin/env python3

import json
import os

account = os.environ["ACCOUNT_ID"]
trail = os.environ["TRAIL_ARN"]

admin_statement = {
    "Sid": "EnableAccountKeyAdministration",
    "Effect": "Allow",
    "Principal": {
        "AWS": f"arn:aws:iam::{account}:root"
    },
    "Action": "kms:*",
    "Resource": "*"
}

encrypt_statement = {
    "Sid": "AllowCloudTrailGenerateDataKey",
    "Effect": "Allow",
    "Principal": {
        "Service": "cloudtrail.amazonaws.com"
    },
    "Action": "kms:GenerateDataKey*",
    "Resource": "*",
    "Condition": {
        "StringEquals": {
            "aws:SourceArn": trail
        },
        "StringLike": {
            "kms:EncryptionContext:aws:cloudtrail:arn":
                f"arn:aws:cloudtrail:*:{account}:trail/*"
        }
    }
}

describe_statement = {
    "Sid": "AllowCloudTrailDescribeKey",
    "Effect": "Allow",
    "Principal": {
        "Service": "cloudtrail.amazonaws.com"
    },
    "Action": "kms:DescribeKey",
    "Resource": "*",
    "Condition": {
        "StringEquals": {
            "aws:SourceArn": trail
        }
    }
}

correct_policy = {
    "Version": "2012-10-17",
    "Statement": [
        admin_statement,
        encrypt_statement,
        describe_statement
    ]
}

broken_policy = {
    "Version": "2012-10-17",
    "Statement": [
        admin_statement,
        describe_statement
    ]
}

for filename, policy in [
    ("correct-kms-policy.json", correct_policy),
    ("broken-kms-policy.json", broken_policy)
]:
    with open(filename, "w") as file:
        json.dump(policy, file, indent=2)

    print("Generated:", filename)
```

### Step 2 — Generate Policies

```bash
python3 generate-kms-policies.py
```

### Step 3 — Compare Policies

```bash
diff -u \
  correct-kms-policy.json \
  broken-kms-policy.json
```

### Policy Comparison

| Permission | Correct | Broken |
|---|---|---|
| Account administration | Allowed | Allowed |
| CloudTrail DescribeKey | Allowed | Allowed |
| CloudTrail GenerateDataKey | Allowed | Missing |
| Trail SourceArn restriction | Present | Present on DescribeKey |
| Encryption context restriction | Present | No data-key statement |

### Step 4 — Apply the Correct Policy

```bash
aws kms put-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --policy file://correct-kms-policy.json \
  --region "$AWS_REGION"
```

### Step 5 — Verify Correct Policy

```bash
aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

### Important Safety Consideration

Never remove the administrative policy statement during this lab.

An incorrect KMS policy can prevent administrators from managing or recovering the key.

The deliberately broken policy removes only the CloudTrail data-key authorization.

---

## README.md — Sections 11–21

Append these sections directly after Section 10 in the same file.

<WritingBlock id="58317" variant="document">## 11. Create the SSE-KMS CloudTrail Trail

### Step 1 — Create the Trail

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$BUCKET_NAME" \
  --kms-key-id "$KMS_KEY_ARN" \
  --no-is-multi-region-trail \
  --no-include-global-service-events \
  --no-enable-log-file-validation \
  --region "$AWS_REGION"
```

The KMS key policy must already authorize the required CloudTrail encryption operations.

If AWS returns `InsufficientEncryptionPolicyException`, inspect the KMS key policy and the configured trail ARN before continuing.

### Step 2 — Tag the Trail

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
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,KMSKey:KmsKeyId,Region:HomeRegion}' \
  --output json \
  --region "$AWS_REGION"
```

Expected: the trail references the dedicated S3 bucket and customer-managed KMS key.

### Step 6 — Verify Logging Status

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

The delivery fields may not be populated immediately.

---

## 12. Verify Healthy SSE-KMS Log Delivery

### Step 1 — Generate Baseline Management Event

```bash
export BASELINE_PARAMETER="${PARAMETER_PREFIX}/baseline-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$BASELINE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "kms-baseline-success" \
  --region "$AWS_REGION"
```

### Step 2 — Save Parameter Name

```bash
printf '%s\n' "$BASELINE_PARAMETER" \
  > lab05-baseline-parameter.txt
```

### Step 3 — Inspect Delivered Logs

```bash
aws s3 ls \
  "s3://${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

CloudTrail delivers log files asynchronously.

### Step 4 — Identify a Delivered Log Object

```bash
export BASELINE_LOG_KEY=$(aws s3api list-objects-v2 \
  --bucket "$BUCKET_NAME" \
  --prefix "AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --query "reverse(sort_by(Contents[?ends_with(Key, '.json.gz')], &LastModified))[0].Key" \
  --output text \
  --region "$AWS_REGION")
```

Verify that the result isn't `None` before continuing.

### Step 5 — Inspect Object Encryption

```bash
aws s3api head-object \
  --bucket "$BUCKET_NAME" \
  --key "$BASELINE_LOG_KEY" \
  --query '{Encryption:ServerSideEncryption,KMSKey:SSEKMSKeyId,Size:ContentLength}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
Encryption = aws:kms
KMSKey = Lab 05 KMS key ARN
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

Downloading SSE-KMS encrypted logs requires appropriate S3 permissions and KMS decrypt authorization.

### Step 7 — Create the Verification Script

Save as `verify-kms-cloudtrail-logs.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import sys

if len(sys.argv) != 4:
    print(
        "Usage: python3 verify-kms-cloudtrail-logs.py "
        "DIRECTORY PARAMETER_NAME OUTPUT_FILE"
    )
    sys.exit(2)

directory, parameter_name, output_file = sys.argv[1:]

matches = []

for filename in glob.glob(
    f"{directory}/**/*.json.gz",
    recursive=True
):
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
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
                "awsRegion": event.get("awsRegion"),
                "parameterName": parameter_name,
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit("Target event not found")

print("SUCCESS: CloudTrail event verified")
```

### Step 8 — Verify Baseline Event

```bash
python3 verify-kms-cloudtrail-logs.py \
  evidence/baseline-logs \
  "$BASELINE_PARAMETER" \
  lab05-baseline-evidence.json
```

Expected after delivery:

```text
SUCCESS: CloudTrail event verified
```

### Step 9 — Save Baseline Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab05-before-failure-status.json
```

### Baseline Summary

| Component | Expected |
|---|---|
| CloudTrail trail | Enabled |
| S3 bucket | Available |
| Bucket policy | Correct |
| KMS key | Enabled |
| KMS key policy | Correct |
| Trail encryption | SSE-KMS |
| S3 object encryption | aws:kms |
| Baseline event | Found in S3 |

Do not proceed to fault injection until baseline encrypted delivery is verified.

---

## 13. Fault Injection — Remove KMS Data-Key Permission

### Step 1 — Verify Resource Ownership

```bash
aws kms list-resource-tags \
  --key-id "$KMS_KEY_ID" \
  --region "$AWS_REGION"
```

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Confirm both resources belong to:

```text
CloudTrail-Troubleshooting-Lab05
```

### Step 2 — Save Current Key Policy

```bash
aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  > lab05-before-kms-policy.json
```

### Step 3 — Apply Broken Key Policy

```bash
aws kms put-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --policy file://broken-kms-policy.json \
  --region "$AWS_REGION"
```

### Step 4 — Verify Broken Policy

```bash
aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Expected: CloudTrail's `kms:GenerateDataKey*` statement is absent.

### Step 5 — Verify the Key Remains Enabled

```bash
aws kms describe-key \
  --key-id "$KMS_KEY_ID" \
  --query 'KeyMetadata.{State:KeyState,Enabled:Enabled}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
KeyState = Enabled
Enabled = true
```

### Step 6 — Generate Failure-Period Management Event

```bash
export FAILURE_PARAMETER="${PARAMETER_PREFIX}/failure-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$FAILURE_PARAMETER" \
  --type String \
  --tier Standard \
  --value "kms-policy-broken" \
  --region "$AWS_REGION"
```

### Step 7 — Save Parameter Name

```bash
printf '%s\n' "$FAILURE_PARAMETER" \
  > lab05-failure-parameter.txt
```

### Step 8 — Inspect Trail Delivery

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Expected configuration state:

```text
IsLogging = true
```

CloudTrail may report an encryption or delivery error after attempting to deliver encrypted logs.

The exact AWS error and reporting time can vary.

### Step 9 — Save Fault Evidence

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab05-kms-failure-status.json
```

```bash
aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  > lab05-broken-kms-policy.json
```

### Fault-State Matrix

| Component | Healthy | Broken |
|---|---|---|
| CloudTrail logging | Enabled | Enabled |
| S3 bucket | Available | Available |
| S3 policy | Correct | Correct |
| KMS key state | Enabled | Enabled |
| CloudTrail DescribeKey | Allowed | Allowed |
| CloudTrail GenerateDataKey | Allowed | Missing |
| SSE-KMS configuration | Enabled | Enabled |
| New encrypted delivery | Working | Expected to fail |

Previously delivered log objects may still be present in S3.

Their presence does not prove successful delivery during the fault period.

---

## 14. Investigate the KMS Encryption Failure

### Step 1 — Inspect Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Trail:Name,Bucket:S3BucketName,KMSKey:KmsKeyId}' \
  --output json \
  --region "$AWS_REGION"
```

Verify the trail still references the expected key.

### Step 2 — Verify S3 Bucket

```bash
aws s3api head-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Expected: success.

### Step 3 — Verify Bucket Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Expected: CloudTrail still has the required S3 permissions.

### Step 4 — Inspect KMS Key State

```bash
aws kms describe-key \
  --key-id "$KMS_KEY_ID" \
  --region "$AWS_REGION"
```

Expected: the key exists and remains enabled.

### Step 5 — Compare Policies

```bash
diff -u \
  correct-kms-policy.json \
  broken-kms-policy.json
```

Expected: the CloudTrail data-key generation permission is missing from the broken policy.

### Step 6 — Inspect Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION"
```

Review:

```text
IsLogging
LatestDeliveryTime
LatestDeliveryError
```

### Step 7 — Inspect KMS API Activity

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=GenerateDataKey \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab05-kms-api-investigation.json
```

KMS event results can help explain the encryption activity.

However, the presence or absence of a specific event should not be treated as the only evidence of the failure.

### Investigation Matrix

| Investigation | Finding |
|---|---|
| Trail exists | Yes |
| Trail logging | Enabled |
| S3 bucket | Available |
| S3 bucket policy | Correct |
| KMS key | Available |
| KMS key state | Enabled |
| Trail KMS configuration | Correct key referenced |
| Data-key permission | Missing |
| Root cause | KMS key policy misconfiguration |

### Investigation Conclusion

The KMS key itself is available, and the S3 destination remains correctly configured.

The fault is caused by a missing service authorization in the KMS key policy.

---

## 15. Root Cause Analysis

### Root Cause

The customer-managed KMS key policy no longer granted CloudTrail permission to generate encryption data keys.

The healthy policy included:

```text
kms:GenerateDataKey*
kms:DescribeKey
```

The intentionally broken policy retained:

```text
kms:DescribeKey
```

But removed the CloudTrail data-key generation statement.

The trail remained enabled, the S3 destination remained available, and the KMS key remained enabled.

However, CloudTrail could no longer complete the expected SSE-KMS encryption workflow for new log deliveries.

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
SSE-KMS Encryption Required
       |
       v
AWS KMS Key Policy Evaluation
       |
       v
GenerateDataKey Permission Missing
       |
       v
KMS Authorization Failure
       |
       v
Encrypted Log Delivery Interrupted
```

### Five Whys

**Why 1 — Why did encrypted log delivery fail?**

The required KMS authorization was missing.

**Why 2 — Why was the permission missing?**

The key policy was replaced with an incomplete version.

**Why 3 — Why did the CloudTrail trail remain active?**

The logging state and KMS authorization are separate conditions.

**Why 4 — Why didn't the correct S3 policy resolve the problem?**

CloudTrail also required permission to use the configured encryption key.

**Why 5 — How can this be prevented?**

Use validated KMS policies, restrict changes to encryption infrastructure, monitor CloudTrail delivery, and verify encrypted log delivery after configuration changes.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-005 |
| AWS Service | CloudTrail |
| Supporting Service | AWS KMS |
| Trail Logging | Enabled |
| S3 Bucket | Available |
| KMS Key State | Enabled |
| Fault Injection | Remove CloudTrail GenerateDataKey permission |
| Root Cause | Incomplete KMS key policy |
| Remediation | Restore data-key generation permission |
| Verification | SSE-KMS log object with recovery event |

---

## 16. Remediation — Restore the Correct KMS Policy

### Step 1 — Inspect Correct Policy

```bash
python3 -m json.tool correct-kms-policy.json
```

Verify:

- Administrative permissions remain intact.
- CloudTrail GenerateDataKey permission exists.
- CloudTrail DescribeKey permission exists.
- The `aws:SourceArn` condition references the lab trail.
- The CloudTrail encryption-context restriction is configured.

### Step 2 — Restore Policy

```bash
aws kms put-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --policy file://correct-kms-policy.json \
  --region "$AWS_REGION"
```

### Step 3 — Verify Restored Permissions

```bash
aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Expected:

```text
kms:GenerateDataKey*
kms:DescribeKey
```

### Step 4 — Save Restored Policy

```bash
aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  > lab05-restored-kms-policy.json
```

### Step 5 — Verify Trail Logging

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

Restarting the trail is not necessary because this exercise does not intentionally stop logging.

### Remediation Comparison

| Component | Broken | Recovered |
|---|---|---|
| Trail Logging | Enabled | Enabled |
| S3 Bucket | Available | Available |
| KMS Key | Enabled | Enabled |
| KMS Policy | Incomplete | Correct |
| GenerateDataKey | Missing | Allowed |
| DescribeKey | Allowed | Allowed |
| Encryption Delivery | Failing | Ready for verification |

---

## 17. Verify SSE-KMS Recovery

### Step 1 — Generate a Recovery Event

```bash
export RECOVERY_PARAMETER="${PARAMETER_PREFIX}/recovery-$(date -u +%Y%m%d%H%M%S)"

aws ssm put-parameter \
  --name "$RECOVERY_PARAMETER" \
  --type String \
  --tier Standard \
  --value "kms-encryption-restored" \
  --region "$AWS_REGION"
```

### Step 2 — Save Parameter Name

```bash
printf '%s\n' "$RECOVERY_PARAMETER" \
  > lab05-recovery-parameter.txt
```

### Step 3 — Check Delivery Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

Watch for a newer successful delivery timestamp.

### Step 4 — Download Recovery Logs

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

### Step 5 — Verify the Exact Recovery Event

```bash
python3 verify-kms-cloudtrail-logs.py \
  evidence/recovery-logs \
  "$RECOVERY_PARAMETER" \
  lab05-recovery-evidence.json
```

Expected after successful delivery:

```text
SUCCESS: CloudTrail event verified
```

### Step 6 — Inspect Recovery Evidence

```bash
python3 -m json.tool lab05-recovery-evidence.json
```

### Step 7 — Extract the Recovery S3 Object Key

```bash
export RECOVERY_LOG_KEY=$(python3 - <<'PY'
import json
import os

with open("lab05-recovery-evidence.json") as file:
    records = json.load(file)

if not records:
    raise SystemExit("Recovery event not verified")

filename = records[0]["sourceFile"]

relative_path = os.path.relpath(
    filename,
    "evidence/recovery-logs"
)

account = os.environ["ACCOUNT_ID"]
region = os.environ["AWS_REGION"]

print(
    f"AWSLogs/{account}/CloudTrail/{region}/"
    f"{relative_path}"
)
PY
)
```

### Step 8 — Verify the Recovery Object Encryption

```bash
aws s3api head-object \
  --bucket "$BUCKET_NAME" \
  --key "$RECOVERY_LOG_KEY" \
  --query '{Encryption:ServerSideEncryption,KMSKey:SSEKMSKeyId,Size:ContentLength}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
Encryption = aws:kms
KMSKey = Lab 05 KMS key ARN
```

### Step 9 — Save Encryption Evidence

```bash
aws s3api head-object \
  --bucket "$BUCKET_NAME" \
  --key "$RECOVERY_LOG_KEY" \
  --query '{Encryption:ServerSideEncryption,KMSKey:SSEKMSKeyId,Size:ContentLength}' \
  --output json \
  --region "$AWS_REGION" \
  > lab05-recovery-encryption.json
```

### Step 10 — Save Final Trail Status

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab05-final-trail-status.json
```

### Final Verification Matrix

| Investigation | Healthy | Broken | Recovered |
|---|---|---|---|
| Trail exists | Yes | Yes | Yes |
| IsLogging | true | true | true |
| S3 bucket | Available | Available | Available |
| KMS key | Enabled | Enabled | Enabled |
| KMS policy | Correct | Broken | Restored |
| GenerateDataKey | Allowed | Missing | Allowed |
| Encrypted log delivery | Working | Failing | Working |
| Recovery event in S3 | — | — | Verified |
| Recovery object uses SSE-KMS | — | — | Verified |

### Final Success Criteria

The incident is resolved when:

1. The required KMS permissions are restored.
2. The CloudTrail trail remains enabled.
3. The recovery API operation completes.
4. New audit logs arrive in S3.
5. The Python verification script finds the exact recovery event.
6. The corresponding S3 object reports `aws:kms`.
7. The KMS key ARN matches the dedicated Lab 05 key.
8. The investigation evidence is saved.

---

## 18. Production Troubleshooting Best Practices

### CloudTrail KMS Troubleshooting Checklist

1. Identify the CloudTrail trail.
2. Verify the AWS account and Region.
3. Inspect `IsLogging`.
4. Verify the S3 destination.
5. Inspect the S3 bucket policy.
6. Identify the KMS key configured for the trail.
7. Verify the KMS key exists.
8. Confirm the KMS key is enabled.
9. Retrieve the current key policy.
10. Check CloudTrail service principal permissions.
11. Verify `kms:GenerateDataKey*`.
12. Verify `kms:DescribeKey`.
13. Check `aws:SourceArn`.
14. Inspect encryption-context conditions.
15. Investigate explicit deny statements.
16. Review CloudTrail delivery status.
17. Check relevant KMS API activity.
18. Compare current and expected policies.
19. Restore the required permissions.
20. Generate a new management event.
21. Verify its delivery to S3.
22. Verify SSE-KMS encryption metadata.
23. Preserve evidence and document the root cause.

### Other KMS Failure Scenarios

| Symptom | Possible Cause | Investigation |
|---|---|---|
| KMS AccessDenied | Missing data-key permission | KMS key policy |
| Trail creation fails | Insufficient encryption policy | CloudTrail and KMS policies |
| KMS key unavailable | Key disabled | DescribeKey |
| Incorrect encryption key | Wrong KMS key ARN | DescribeTrails |
| Encryption context mismatch | Incorrect policy condition | KMS key policy |
| SourceArn mismatch | Policy references different trail | Key policy conditions |
| Cannot download encrypted logs | Missing decrypt authorization | IAM and KMS permissions |
| S3 delivery fails | Bucket policy incorrect | S3 policy |
| IsLogging=false | Trail stopped | GetTrailStatus |

### Recommended Production Architecture

```text
AWS API Activity
       |
       v
Multi-Region CloudTrail
       |
       v
Customer-Managed KMS Key
       |
       v
Restricted Encryption Key Policy
       |
       v
Private S3 Audit Bucket
       |
       v
Protected Log Retention
       |
       v
Security Monitoring
       |
       v
Incident Investigation
```

### Security Recommendations

- Use least-privilege KMS key policies.
- Restrict CloudTrail encryption requests using `aws:SourceArn`.
- Use encryption-context conditions where appropriate.
- Protect key administration permissions.
- Monitor modifications to KMS key policies.
- Monitor changes to CloudTrail configuration.
- Preserve access for authorized log readers.
- Avoid disabling shared production keys.
- Apply appropriate log retention and integrity protections.
- Verify encrypted delivery following key-policy changes.

### Operational Recommendations

Use infrastructure as code to maintain consistent key policies.

Review key-policy changes before production deployment.

Verify both logging state and actual S3 delivery.

Inspect encryption metadata on recovered objects rather than assuming all logs use the expected KMS key.

---

## 19. AWS Resource Cleanup

**Warning:** AWS KMS key deletion is destructive. Schedule deletion only after verifying that the dedicated lab key is not protecting any data that must be retained.

### Step 1 — Verify Ownership

Verify CloudTrail:

```bash
aws cloudtrail list-tags \
  --resource-id-list "$TRAIL_ARN" \
  --region "$AWS_REGION"
```

Verify S3:

```bash
aws s3api get-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

Verify KMS:

```bash
aws kms list-resource-tags \
  --key-id "$KMS_KEY_ID" \
  --region "$AWS_REGION"
```

Confirm the expected Lab 05 project tag on every resource.

### Step 2 — Stop Trail Logging

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 3 — Delete Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 4 — Delete Temporary Parameters

```bash
for FILE in \
  lab05-baseline-parameter.txt \
  lab05-failure-parameter.txt \
  lab05-recovery-parameter.txt
do
  if [[ -f "$FILE" ]]; then
    PARAMETER=$(cat "$FILE")

    case "$PARAMETER" in
      /cloudtrail-lab05/*)
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

### Step 5 — Delete Lab S3 Log Objects

```bash
aws s3 rm "s3://${BUCKET_NAME}/" \
  --recursive \
  --region "$AWS_REGION"
```

Only run this against the verified disposable lab bucket.

### Step 6 — Delete Lab S3 Bucket

```bash
aws s3api delete-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$AWS_REGION"
```

### Step 7 — Schedule KMS Key Deletion

```bash
aws kms schedule-key-deletion \
  --key-id "$KMS_KEY_ID" \
  --pending-window-in-days 7 \
  --region "$AWS_REGION"
```

### Step 8 — Verify Deletion Schedule

```bash
aws kms describe-key \
  --key-id "$KMS_KEY_ID" \
  --query 'KeyMetadata.{State:KeyState,DeletionDate:DeletionDate}' \
  --output json \
  --region "$AWS_REGION"
```

Expected:

```text
KeyState = PendingDeletion
```

The key is not deleted immediately.

It becomes unavailable for cryptographic operations during the waiting period and will be permanently deleted afterward unless the deletion is canceled.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| Lab CloudTrail trail | Deleted |
| Lab S3 bucket | Deleted |
| Baseline parameter | Deleted |
| Failure parameter | Deleted |
| Recovery parameter | Deleted |
| Customer-managed KMS key | Pending deletion |
| Production CloudTrail trails | Unchanged |
| Other KMS keys | Unchanged |
| EC2 instances | None created |
| VPC resources | None created |

---

## 20. Interview Questions and Answers

### Q1. What is AWS KMS?

AWS Key Management Service provides managed cryptographic keys and controls access to their use.

### Q2. What is SSE-KMS?

Server-side encryption using AWS KMS keys.

### Q3. What is the difference between SSE-S3 and SSE-KMS?

SSE-S3 uses S3-managed encryption keys. SSE-KMS uses KMS keys and supports additional key management and access controls.

### Q4. Why does CloudTrail need GenerateDataKey permission?

CloudTrail's SSE-KMS encryption workflow requires authorization to generate data keys used to protect delivered log files.

### Q5. Why does CloudTrail need DescribeKey?

It allows CloudTrail to inspect the configured encryption key's properties.

### Q6. What happens if CloudTrail loses KMS permissions?

Encrypted log delivery can fail, even when trail logging remains enabled.

### Q7. Does IsLogging=true guarantee encrypted delivery?

No. KMS authorization and S3 delivery must be verified separately.

### Q8. How do you inspect a KMS key policy?

```bash
aws kms get-key-policy \
  --key-id YOUR_KEY_ID \
  --policy-name default
```

### Q9. What does aws:SourceArn do?

It restricts access to requests associated with the expected CloudTrail trail.

### Q10. What is a KMS encryption context?

Additional key-value information associated with a cryptographic operation that can support policy conditions and auditing.

### Q11. How do you investigate a disabled KMS key?

Use `kms describe-key` to inspect its current state.

### Q12. How do you verify S3 log encryption?

Use `s3api head-object` and inspect `ServerSideEncryption` and `SSEKMSKeyId`.

### Q13. What permission may be needed to read CloudTrail SSE-KMS log files?

The reader needs appropriate S3 access and KMS decrypt authorization.

### Q14. Can KMS keys be deleted immediately?

Customer-managed KMS key deletion requires a waiting period. This lab uses seven days.

### Q15. How do you prevent KMS key policy failures?

Use validated key policies, infrastructure as code, change reviews, monitoring, and encryption verification.

### Q16. What is the difference between Lab 04 and Lab 05?

Lab 04 involves missing S3 write permissions.

Lab 05 involves missing KMS encryption permissions.

### Q17. What should an engineer inspect when CloudTrail reports an encryption problem?

Check the trail encryption configuration, KMS key ARN, key state, key policy, CloudTrail service principal permissions, source ARN restrictions, and delivery status.

### Q18. Why is protecting KMS administrative access important?

Incorrect key administration permissions can prevent administrators from updating or recovering the key configuration.

### Q19. Why must recovery verification include a newly generated event?

Previously delivered logs do not prove that the current CloudTrail encryption pipeline is functioning.

### Q20. How would you explain this lab in an interview?

I created a dedicated CloudTrail trail with a private S3 destination and configured SSE-KMS encryption using a customer-managed KMS key.

I configured the correct CloudTrail permissions and verified normal encrypted log delivery.

Then I intentionally removed CloudTrail's GenerateDataKey permission from the KMS key policy.

The trail remained enabled, but the KMS policy no longer permitted the required encryption operation.

I investigated the incident using AWS CLI by inspecting the trail configuration, S3 permissions, KMS key state, and key policy.

I compared the healthy and broken policies and identified the missing data-key permission as the root cause.

After restoring the correct KMS policy, I generated a fresh management event and verified that it appeared in a delivered CloudTrail S3 log.

I also checked the S3 object's encryption metadata and confirmed that it used SSE-KMS with the dedicated lab key.

Finally, I cleaned up the temporary resources and scheduled the KMS key for deletion.

---

## 21. Repository Structure, Lessons Learned, and Skills Demonstrated

### Repository Structure

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
│   ├── README.md
│   ├── generate-s3-policy.py
│   ├── generate-kms-policies.py
│   ├── verify-kms-cloudtrail-logs.py
│   ├── cloudtrail-s3-policy.json
│   ├── kms-admin-policy.json
│   ├── correct-kms-policy.json
│   ├── broken-kms-policy.json
│   ├── lab05-resources.env
│   ├── lab05-baseline-parameter.txt
│   ├── lab05-failure-parameter.txt
│   ├── lab05-recovery-parameter.txt
│   ├── lab05-baseline-evidence.json
│   ├── lab05-before-failure-status.json
│   ├── lab05-before-kms-policy.json
│   ├── lab05-kms-failure-status.json
│   ├── lab05-broken-kms-policy.json
│   ├── lab05-kms-api-investigation.json
│   ├── lab05-restored-kms-policy.json
│   ├── lab05-recovery-evidence.json
│   ├── lab05-recovery-encryption.json
│   ├── lab05-final-trail-status.json
│   │
│   └── evidence/
│       ├── baseline-logs/
│       └── recovery-logs/
│
├── 06-data-events-not-recorded/
├── 07-multi-region-trail-misconfiguration/
├── 08-investigating-unauthorized-api-calls/
├── 09-cloudtrail-log-integrity-validation/
└── 10-cloudtrail-lake-query-troubleshooting/
```

### Important Project Files

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `generate-s3-policy.py` | Generates CloudTrail S3 policy |
| `generate-kms-policies.py` | Creates healthy and broken KMS policies |
| `verify-kms-cloudtrail-logs.py` | Verifies exact events in encrypted audit logs |
| `cloudtrail-s3-policy.json` | S3 log delivery permissions |
| `kms-admin-policy.json` | Initial KMS administration policy |
| `correct-kms-policy.json` | Healthy CloudTrail encryption policy |
| `broken-kms-policy.json` | Intentionally incomplete KMS policy |
| `lab05-resources.env` | Local AWS resource identifiers |
| `lab05-baseline-evidence.json` | Baseline event verification |
| `lab05-kms-failure-status.json` | Fault-state investigation |
| `lab05-broken-kms-policy.json` | Actual broken policy evidence |
| `lab05-restored-kms-policy.json` | Remediation evidence |
| `lab05-recovery-evidence.json` | Verified recovery event |
| `lab05-recovery-encryption.json` | S3 SSE-KMS metadata |
| `lab05-final-trail-status.json` | Final trail status |

### GitHub Evidence Guidelines

All evidence should come from actual AWS CLI responses.

Do not invent KMS errors, CloudTrail event IDs, delivery timestamps, or encryption metadata.

Avoid committing raw CloudTrail log files or unredacted account information.

Generated KMS key policies can contain account IDs and resource ARNs, so sanitize them before committing.

For a public portfolio, the README, Python scripts, generic policies, and redacted evidence summaries are the most useful artifacts.

### Recommended .gitignore

```gitignore
__pycache__/
*.pyc
.venv/
.env

**/lab05-resources.env
**/evidence/baseline-logs/
**/evidence/recovery-logs/
```

### Lessons Learned

This lab demonstrates how AWS CloudTrail encryption can fail even when the trail, S3 bucket, and KMS key are available.

We configured a customer-managed KMS key to encrypt CloudTrail audit logs.

After verifying normal encrypted delivery, we intentionally removed CloudTrail's data-key generation permission.

The trail continued to report an enabled logging state, but encryption authorization was no longer correct.

We investigated the trail configuration, KMS key state, S3 destination, and key policy.

The root cause was an incomplete KMS key policy.

We restored the required permission and verified delivery of a new management event.

We also inspected the recovered log object's S3 encryption metadata to confirm the intended KMS key was used.

Finally, we removed the temporary trail and S3 bucket, deleted the test parameters, and scheduled the KMS key for deletion.

### Skills Demonstrated

- AWS CloudTrail
- AWS KMS
- Customer-managed KMS keys
- KMS key policies
- `kms:GenerateDataKey*`
- `kms:DescribeKey`
- `kms:Decrypt`
- KMS encryption context
- IAM condition keys
- SSE-KMS encryption
- Amazon S3
- S3 bucket policies
- AWS CLI v2
- Linux Bash
- Python 3
- JSON processing
- GZIP audit log analysis
- CloudTrail delivery diagnostics
- Encryption permission troubleshooting
- AWS security incident investigation
- Root cause analysis
- Remediation verification
- AWS resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-005 |
| Scenario | CloudTrail KMS Encryption Failure |
| Trail | cloudtrail-lab05-trail |
| Region | us-east-1 |
| S3 Destination | Dedicated private bucket |
| Key Type | Customer-managed symmetric KMS key |
| Trail Logging During Failure | Enabled |
| KMS Key State During Failure | Enabled |
| Broken Permission | `kms:GenerateDataKey*` |
| Root Cause | Incomplete KMS key policy |
| Remediation | Restore CloudTrail data-key permission |
| Recovery Test | PutParameter |
| Recovery Event | Verified in S3 |
| Object Encryption | SSE-KMS |
| Encryption Key | Dedicated Lab 05 KMS key |
| Trail Cleanup | Deleted |
| Bucket Cleanup | Deleted |
| KMS Cleanup | Pending deletion |
| Incident Status | Resolved after recovery verification |

**Key Takeaway:** CloudTrail logging, S3 permissions, and KMS encryption authorization are separate parts of an audit logging pipeline. A Cloud Security Engineer must verify all three to diagnose encrypted delivery failures correctly.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Encrypt CloudTrail Logs with AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
- [Configure KMS Key Policies for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)
- [How CloudTrail Uses AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-kms-works-with-cloudtrail.html)
- [AWS CLI — PutKeyPolicy](https://docs.aws.amazon.com/cli/latest/reference/kms/put-key-policy.html)
- [AWS CLI — GetKeyPolicy](https://docs.aws.amazon.com/cli/latest/reference/kms/get-key-policy.html)
- [AWS CLI — ScheduleKeyDeletion](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)
- [AWS KMS Pricing](https://aws.amazon.com/kms/pricing/)