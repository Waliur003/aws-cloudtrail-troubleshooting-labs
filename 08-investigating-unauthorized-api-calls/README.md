# Lab 08 — Investigating Unauthorized API Calls

**AWS CloudTrail Troubleshooting Labs | Cloud Security Engineering**

## Overview

This lab demonstrates how to investigate unauthorized AWS API operations using AWS CloudTrail, IAM, STS, Amazon S3, and AWS Systems Manager.

In production AWS environments, security teams investigate unsuccessful API requests to determine who made the request, what action was attempted, which resource was targeted, and whether the request indicates a security problem.

CloudTrail provides audit records containing important investigation fields, including the calling identity, API operation, AWS Region, source IP address, timestamp, user agent, error code, and request parameters.

In this lab, we create a controlled security incident involving a temporary IAM role.

The role can read a specific Systems Manager parameter but has an explicit deny preventing it from deleting the parameter.

We assume the restricted role using temporary AWS STS credentials and attempt to execute `ssm:DeleteParameter`.

AWS denies the request.

We then investigate the denied operation through CloudTrail Event history and the audit logs delivered to an S3 bucket.

Using Python, we identify the exact CloudTrail event, examine the assumed-role session, and build an incident timeline.

Finally, we verify that the parameter was not deleted, preserve the security evidence, and remove the temporary AWS resources.

**This is a controlled authorization test, not an actual account compromise.** An AccessDenied event is evidence of a denied operation, but does not independently establish malicious intent.

### Troubleshooting workflow

```text
Create Private Audit Bucket
          |
          v
Configure CloudTrail Trail
          |
          v
Create Restricted IAM Role
          |
          v
Create Protected SSM Parameter
          |
          v
Assume Role with AWS STS
          |
          v
Verify Allowed GetParameter
          |
          v
Attempt Denied DeleteParameter
          |
          v
Investigate CloudTrail Event History
          |
          v
Identify Principal and API Error
          |
          v
Verify Event in S3 Audit Logs
          |
          v
Build Security Incident Timeline
          |
          v
Verify Resource Protection
          |
          v
Cleanup
```

---

## 1. Lab Information

| Item | Configuration |
|---|---|
| Incident ID | INC-CT-008 |
| Difficulty | Advanced |
| Primary AWS Service | AWS CloudTrail |
| Supporting Services | IAM, STS, Amazon S3, Systems Manager |
| AWS Region | `us-east-1` |
| Operating System | WSL2 Ubuntu |
| Interface | AWS CLI v2 |
| Automation | Bash and Python 3 |
| Trail | `cloudtrail-lab08-trail` |
| Trail Type | Single-Region |
| Management Events | Read and write |
| S3 Audit Bucket | Dedicated private bucket |
| Bucket Encryption | SSE-S3 |
| IAM Role | `cloudtrail-lab08-investigator-role` |
| Inline Policy | `cloudtrail-lab08-restricted-policy` |
| Authorized API | `ssm:GetParameter` |
| Unauthorized API | `ssm:DeleteParameter` |
| Expected Error | AccessDenied / AccessDeniedException |
| Identity Type | AssumedRole |
| Test Resource | Disposable SSM Standard String parameter |
| Investigation | CloudTrail Event history and S3 logs |
| Correlation Identifier | `eventID` |
| Root Cause | Explicit IAM authorization deny |
| Security Outcome | Delete request blocked |
| Cleanup | Trail, bucket, role, policy, and parameter deleted |

### Lab Objectives

- Understand CloudTrail management-event investigation.
- Create and secure a CloudTrail audit destination.
- Configure an IAM role trust policy.
- Create a least-privilege IAM permissions policy.
- Understand explicit deny.
- Use AWS STS AssumeRole.
- Generate an authorized and a denied API operation.
- Identify a failed management API call.
- Analyze CloudTrail `userIdentity`.
- Understand assumed-role sessions.
- Identify source IP and user agent.
- Inspect CloudTrail error codes.
- Correlate Event history and S3 log records.
- Build a security incident timeline.
- Distinguish unauthorized attempts from confirmed malicious activity.
- Verify preventive security controls.
- Document investigation findings.
- Safely remove temporary resources.

---

## 2. Production Incident Scenario

### Incident Description

A company stores configuration values in AWS Systems Manager Parameter Store.

An application accesses those values using an IAM role.

The role has permission to read specific parameters, but it is not authorized to delete them.

One day, the Cloud Security team observes a failed `DeleteParameter` operation.

The event reports an access-denied error.

The security engineer must determine whether the failure resulted from an expected application behavior, an incorrect deployment, or potentially suspicious activity.

The engineer investigates the CloudTrail management event.

The event identifies an assumed IAM role session attempting to delete a protected parameter.

The request was denied because the role's effective permissions explicitly prohibited `ssm:DeleteParameter`.

The engineer verifies that the targeted parameter still exists and that the deletion did not occur.

The same event is located in the archived CloudTrail S3 logs using its unique event ID.

The incident is documented with evidence, findings, and recommended follow-up actions.

### Incident Symptoms

- A `DeleteParameter` API call fails.
- AWS reports AccessDenied.
- CloudTrail records the attempted operation.
- The calling identity is an assumed IAM role.
- The requested resource is a protected SSM parameter.
- The IAM policy contains an explicit deny.
- The parameter remains available.
- CloudTrail Event history contains the denied operation.
- The S3 audit logs contain the same event after delivery.

### Business Impact

In a real environment, unexpected API authorization failures may indicate:

- Misconfigured application permissions.
- Incorrect deployment credentials.
- Unauthorized administrative attempts.
- Unexpected role usage.
- Potential credential misuse.
- Failed attempts to modify critical infrastructure.
- Workloads operating outside their intended permissions.

However, the impact must be established from the evidence rather than assumed.

In this controlled incident, the protected parameter remains intact.

### Objective

Identify the calling identity, attempted API action, target resource, error, and outcome, then verify the incident through CloudTrail records and confirm the security control prevented deletion.

---

## 3. AWS Architecture

### Controlled Incident Architecture

```text
                  Authorized Lab Identity
                            |
                            v
                      AWS STS AssumeRole
                            |
                            v
                   Temporary Credentials
                            |
                            v
                  Restricted IAM Lab Role
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          ssm:GetParameter      ssm:DeleteParameter
                 |                     |
                 v                     v
               Allow               Explicit Deny
                 |                     |
                 v                     v
          Read Successful         AccessDenied
                                       |
                                       v
                                AWS CloudTrail
                                       |
                          +------------+------------+
                          |                         |
                          v                         v
                    Event History              S3 Audit Logs
                          |                         |
                          +------------+------------+
                                       |
                                       v
                              Python Investigation
                                       |
                                       v
                              Incident Timeline
```

### Audit Logging Architecture

```text
AWS Management API Activity
             |
             v
         CloudTrail
             |
             v
      Management Events
             |
             v
     cloudtrail-lab08-trail
             |
             v
       Private S3 Bucket
             |
             v
      AWSLogs/ACCOUNT_ID/
             |
             v
       CloudTrail/us-east-1/
             |
             v
       Compressed JSON Logs
             |
             v
       Incident Investigation
```

### Architecture Components

| Component | Purpose |
|---|---|
| AWS CloudTrail | Records supported AWS API activity |
| CloudTrail Event history | Provides recent regional management events |
| CloudTrail Trail | Delivers selected events to S3 |
| Amazon S3 | Stores archived audit records |
| IAM Role | Provides restricted authorization |
| IAM Trust Policy | Controls who may assume the role |
| IAM Inline Policy | Controls allowed and denied actions |
| AWS STS | Issues temporary role session credentials |
| SSM Parameter Store | Hosts the protected test resource |
| AWS CLI | Generates and investigates API activity |
| Python | Extracts and correlates CloudTrail evidence |
| Bash | Coordinates the hands-on workflow |

---

## 4. Understanding Unauthorized API Investigations

### What Is an Unauthorized API Call?

An unauthorized API call is a request that is not permitted by the effective authorization controls.

The request may fail because permissions are missing or because an explicit deny applies.

An unauthorized request is not necessarily malicious.

### What Is AccessDenied?

AccessDenied is an AWS authorization error indicating that an API operation was not permitted.

For this lab:

```text
API: ssm:DeleteParameter
Result: AccessDenied
```

### What Is an IAM Role?

An IAM role is an AWS identity with permissions and a trust policy.

An authorized principal can assume the role to receive temporary credentials.

### What Is AssumeRole?

`AssumeRole` is an AWS STS operation that creates temporary role session credentials.

The credentials are used to make requests under the role's permissions.

### What Is Explicit Deny?

An explicit deny prevents an operation even when another applicable policy would otherwise allow it.

For the test resource:

```text
ssm:GetParameter    → Allow
ssm:DeleteParameter → Deny
```

### What Is userIdentity?

The CloudTrail `userIdentity` element describes the identity associated with the API request.

It helps investigators identify who or what performed an operation.

### What Is AssumedRole?

`AssumedRole` indicates the request was performed using credentials obtained from an IAM role session.

Example ARN structure:

```text
arn:aws:sts::ACCOUNT_ID:assumed-role/ROLE_NAME/SESSION_NAME
```

### What Is sessionIssuer?

`sessionIssuer` identifies the IAM role that issued the assumed-role session credentials.

It helps correlate a temporary session with its underlying role.

### What Is sourceIPAddress?

`sourceIPAddress` describes the source of the request as recorded by CloudTrail.

The value may represent a client IP address or AWS service context.

It is not automatically proof of an attacker's identity or physical location.

### What Is userAgent?

`userAgent` contains information about the client making the API request.

It may identify AWS CLI, an SDK, or another application client.

### What Is eventID?

`eventID` is the unique identifier associated with a CloudTrail event.

It helps correlate a particular operation between Event history and the trail's archived S3 logs.

### What Is eventName?

`eventName` identifies the API operation, such as:

```text
GetParameter
DeleteParameter
AssumeRole
```

### What Is errorCode?

`errorCode` indicates the error reported by the service.

Examples include access-denied and validation-related errors.

### What Is errorMessage?

`errorMessage` can provide additional details about the failure.

The exact wording depends on the AWS service and authorization path.

---

## 5. Prerequisites and Safety

### Requirements

- AWS account.
- AWS CLI v2.
- WSL2 Ubuntu.
- Bash.
- Python 3.
- Permission to create a lab IAM role.
- CloudTrail and S3 management permissions.
- Systems Manager permissions.
- AWS STS AssumeRole permission.
- Git and GitHub.

### Relevant AWS Permissions

```text
sts:GetCallerIdentity
sts:AssumeRole

cloudtrail:CreateTrail
cloudtrail:DescribeTrails
cloudtrail:GetTrailStatus
cloudtrail:PutEventSelectors
cloudtrail:StartLogging
cloudtrail:StopLogging
cloudtrail:AddTags
cloudtrail:ListTags
cloudtrail:DeleteTrail
cloudtrail:LookupEvents

s3:CreateBucket
s3:PutBucketPolicy
s3:GetBucketPolicy
s3:PutPublicAccessBlock
s3:PutBucketEncryption
s3:PutBucketTagging
s3:GetBucketTagging
s3:ListBucket
s3:GetObject
s3:DeleteObject
s3:DeleteBucket

iam:CreateRole
iam:GetRole
iam:PutRolePolicy
iam:GetRolePolicy
iam:DeleteRolePolicy
iam:DeleteRole
iam:ListRoleTags

ssm:PutParameter
ssm:GetParameter
ssm:DeleteParameter
```

### Safety Rules

- Use a dedicated CloudTrail trail.
- Never modify existing production IAM roles.
- Never test against real application parameters.
- Use a disposable Standard String parameter.
- Do not publish temporary STS credentials.
- Disable shell tracing before handling credentials.
- Do not save secrets in Git.
- Verify the assumed role before making the denied request.
- Never remove the explicit deny to make the test succeed.
- Do not classify the controlled event as a real compromise.
- Verify ownership tags before deleting resources.

### Cost Considerations

Potential charges include additional CloudTrail management-event copies, S3 storage, and API requests.

This lab does not require EC2 instances, KMS customer-managed keys, or VPC infrastructure.

---

## 6. Prepare WSL Ubuntu

### Step 1 — Create Lab Directory

```bash
cd ~/aws-cloudtrail-troubleshooting-labs

mkdir -p 08-investigating-unauthorized-api-calls

cd 08-investigating-unauthorized-api-calls
```

### Step 2 — Verify AWS Identity

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

export PROJECT_TAG="CloudTrail-Troubleshooting-Lab08"

export TRAIL_NAME="cloudtrail-lab08-trail"

export TRAIL_ARN="arn:aws:cloudtrail:${AWS_REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"

export SUFFIX="$(date -u +%Y%m%d%H%M%S)-${RANDOM}"

export LOG_BUCKET="cloudtrail-lab08-${ACCOUNT_ID}-${SUFFIX}"

export ROLE_NAME="cloudtrail-lab08-investigator-role"

export ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

export INLINE_POLICY_NAME="cloudtrail-lab08-restricted-policy"

export SESSION_NAME="lab08-incident-${SUFFIX}"

export PARAMETER_NAME="/cloudtrail-lab08/protected-${SUFFIX}"
```

### Step 4 — Verify Configuration

```bash
echo "$AWS_REGION"
echo "$TRAIL_NAME"
echo "$LOG_BUCKET"
echo "$ROLE_NAME"
echo "$PARAMETER_NAME"
```

### Step 5 — Save Resource Identifiers

```bash
cat > lab08-resources.env <<EOF
export AWS_REGION="$AWS_REGION"
export ACCOUNT_ID="$ACCOUNT_ID"
export PROJECT_TAG="$PROJECT_TAG"
export TRAIL_NAME="$TRAIL_NAME"
export TRAIL_ARN="$TRAIL_ARN"
export LOG_BUCKET="$LOG_BUCKET"
export ROLE_NAME="$ROLE_NAME"
export ROLE_ARN="$ROLE_ARN"
export INLINE_POLICY_NAME="$INLINE_POLICY_NAME"
export SESSION_NAME="$SESSION_NAME"
export PARAMETER_NAME="$PARAMETER_NAME"
EOF
```

Restore the environment later using:

```bash
source lab08-resources.env
```

### Step 6 — Inspect Existing Resources

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --output table
```

```bash
aws iam get-role \
  --role-name "$ROLE_NAME"
```

If a role with this name already exists, do not reuse it without verifying ownership.

---

## 7. Create the S3 Audit Log Destination

### Step 1 — Create S3 Bucket

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

### Step 4 — Tag the Bucket

```bash
aws s3api put-bucket-tagging \
  --bucket "$LOG_BUCKET" \
  --tagging "TagSet=[{Key=Project,Value=$PROJECT_TAG}]" \
  --region "$AWS_REGION"
```

### Step 5 — Verify Bucket Availability

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 6 — Verify Bucket Encryption

```bash
aws s3api get-bucket-encryption \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Expected:

| Component | Expected State |
|---|---|
| Bucket | Available |
| Encryption | SSE-S3 |
| Public access | Blocked |
| Project tag | Present |

---

## 8. Configure the CloudTrail S3 Bucket Policy

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

### Step 2 — Generate the Policy

```bash
python3 generate-s3-policy.py
```

### Step 3 — Review the Policy

```bash
python3 -m json.tool cloudtrail-s3-policy.json
```

### Step 4 — Apply the Policy

```bash
aws s3api put-bucket-policy \
  --bucket "$LOG_BUCKET" \
  --policy file://cloudtrail-s3-policy.json \
  --region "$AWS_REGION"
```

### Step 5 — Verify the Applied Policy

```bash
aws s3api get-bucket-policy \
  --bucket "$LOG_BUCKET" \
  --query Policy \
  --output text \
  --region "$AWS_REGION" \
  | python3 -m json.tool
```

Confirm:

```text
s3:GetBucketAcl
s3:PutObject
```

The policy restricts service access to the dedicated trail ARN.

---

## 9. Create and Start the CloudTrail Trail

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

### Step 6 — Verify Trail Configuration

```bash
aws cloudtrail describe-trails \
  --trail-name-list "$TRAIL_NAME" \
  --query 'trailList[].{Name:Name,Bucket:S3BucketName,HomeRegion:HomeRegion}' \
  --output json \
  --region "$AWS_REGION"
```

The trail is ready to deliver management-event logs.

---

## 10. Create the Restricted IAM Role

### Step 1 — Generate the Role Trust Policy

Create `lab08-trust-policy.json`:

```bash
python3 - <<'PY'
import json
import os

account = os.environ["ACCOUNT_ID"]

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAuthorizedAccountPrincipals",
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{account}:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

with open("lab08-trust-policy.json", "w") as file:
    json.dump(policy, file, indent=2)
PY
```

The account principal allows the account to delegate role assumption through IAM authorization.

It does not permit arbitrary external accounts to assume the role.

For production environments, prefer a narrowly defined trusted principal and suitable additional conditions.

### Step 2 — Create the IAM Role

```bash
aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file://lab08-trust-policy.json \
  --description "Temporary restricted role for CloudTrail Lab08" \
  --tags "Key=Project,Value=$PROJECT_TAG"
```

### Step 3 — Verify the Role

```bash
aws iam get-role \
  --role-name "$ROLE_NAME" \
  --query 'Role.{Name:RoleName,Arn:Arn}' \
  --output json
```

### Step 4 — Create the Restricted Policy Generator

Save as `generate-role-policy.py`:

```python
#!/usr/bin/env python3

import json
import os

account = os.environ["ACCOUNT_ID"]
region = os.environ["AWS_REGION"]
parameter = os.environ["PARAMETER_NAME"]

resource = (
    f"arn:aws:ssm:{region}:{account}:parameter"
    f"{parameter}"
)

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadingLabParameter",
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": resource
        },
        {
            "Sid": "ExplicitlyDenyDeletingLabParameter",
            "Effect": "Deny",
            "Action": "ssm:DeleteParameter",
            "Resource": resource
        }
    ]
}

with open("lab08-role-policy.json", "w") as file:
    json.dump(policy, file, indent=2)

print("Restricted IAM role policy generated")
```

### Step 5 — Generate Role Policy

```bash
python3 generate-role-policy.py
```

### Step 6 — Inspect Permissions

```bash
python3 -m json.tool lab08-role-policy.json
```

Expected:

| Action | Effect |
|---|---|
| ssm:GetParameter | Allow |
| ssm:DeleteParameter | Deny |

### Step 7 — Attach Inline Policy

```bash
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$INLINE_POLICY_NAME" \
  --policy-document file://lab08-role-policy.json
```

### Step 8 — Verify Applied Policy

```bash
aws iam get-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$INLINE_POLICY_NAME"
```

### Security Explanation

The restricted role can read the dedicated test parameter.

The explicit deny prevents it from deleting that resource.

This creates a predictable authorization failure for CloudTrail investigation.

---

<WritingBlock id="82642" variant="document">## 11. Create the Protected SSM Parameter

### Step 1 — Create Test Parameter

Using your original authorized AWS identity:

```bash
aws ssm put-parameter \
  --name "$PARAMETER_NAME" \
  --type String \
  --tier Standard \
  --value "lab08-protected-test-value" \
  --region "$AWS_REGION"
```

### Step 2 — Verify Parameter

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Version:Version,Type:Type}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 3 — Verify Original Caller

```bash
aws sts get-caller-identity \
  --query '{Account:Account,Arn:Arn}' \
  --output json
```

This original identity is responsible for creating and cleaning up the lab.

The restricted role will be used only for the controlled API test.

---

## 12. Assume the Restricted IAM Role

### Step 1 — Disable Shell Tracing

```bash
set +x
```

This reduces the chance of temporary credentials being exposed through shell tracing.

### Step 2 — Assume the Role

```bash
read -r LAB_ACCESS_KEY LAB_SECRET_KEY LAB_SESSION_TOKEN \
  <<< "$(aws sts assume-role \
    --role-arn "$ROLE_ARN" \
    --role-session-name "$SESSION_NAME" \
    --duration-seconds 3600 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)"
```

If AWS returns AccessDenied, verify that your original identity has `sts:AssumeRole` permission and that the role trust policy authorizes it.

### Step 3 — Verify the Temporary Role Session

```bash
env -u AWS_PROFILE \
  AWS_ACCESS_KEY_ID="$LAB_ACCESS_KEY" \
  AWS_SECRET_ACCESS_KEY="$LAB_SECRET_KEY" \
  AWS_SESSION_TOKEN="$LAB_SESSION_TOKEN" \
  aws sts get-caller-identity \
  --query '{Account:Account,Arn:Arn}' \
  --output json
```

Expected ARN structure:

```text
arn:aws:sts::ACCOUNT_ID:assumed-role/cloudtrail-lab08-investigator-role/SESSION_NAME
```

### Step 4 — Save Expected Principal ARN

```bash
export INCIDENT_PRINCIPAL_ARN="arn:aws:sts::${ACCOUNT_ID}:assumed-role/${ROLE_NAME}/${SESSION_NAME}"
```

This ARN identifies the controlled session in the investigation.

### Step 5 — Execute an Authorized API Request

```bash
env -u AWS_PROFILE \
  AWS_ACCESS_KEY_ID="$LAB_ACCESS_KEY" \
  AWS_SECRET_ACCESS_KEY="$LAB_SECRET_KEY" \
  AWS_SESSION_TOKEN="$LAB_SESSION_TOKEN" \
  aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

Expected: successful parameter read.

### Baseline Verification

| Component | Expected Result |
|---|---|
| IAM role | Exists |
| Trust relationship | Working |
| STS temporary credentials | Issued |
| Calling identity | AssumedRole |
| GetParameter permission | Allowed |
| GetParameter operation | Successful |

Do not publish the temporary credentials.

---

## 13. Fault Injection — Unauthorized DeleteParameter

### Step 1 — Execute the Denied API Operation

```bash
if env -u AWS_PROFILE \
  AWS_ACCESS_KEY_ID="$LAB_ACCESS_KEY" \
  AWS_SECRET_ACCESS_KEY="$LAB_SECRET_KEY" \
  AWS_SESSION_TOKEN="$LAB_SESSION_TOKEN" \
  aws ssm delete-parameter \
    --name "$PARAMETER_NAME" \
    --region "$AWS_REGION" \
    2>lab08-denied-command.stderr
then
  echo "UNEXPECTED: DeleteParameter succeeded"
else
  echo "EXPECTED: DeleteParameter request failed"
fi
```

### Step 2 — Inspect the AWS CLI Error

```bash
cat lab08-denied-command.stderr
```

Expected error category:

```text
AccessDeniedException
```

The exact error text depends on AWS authorization and service behavior.

Confirm the failure is an authorization error rather than an unrelated networking or configuration problem.

### Step 3 — Verify the Resource Was Not Deleted

Using the original AWS identity:

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

Expected: parameter still exists.

### Step 4 — Record a Local Investigation Timestamp

```bash
date -u +"%Y-%m-%dT%H:%M:%SZ" \
  | tee lab08-investigation-time.txt
```

The CloudTrail `eventTime` is the authoritative time for the API request.

### Step 5 — Verify Trail Status

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

### Incident State

| Investigation | Expected |
|---|---|
| Assumed role session | Active |
| GetParameter | Successful |
| DeleteParameter | Denied |
| Error category | AccessDenied |
| Parameter | Preserved |
| CloudTrail | Enabled |
| Management events | Selected |

**Important:** The expected failure is the security control working correctly. Do not remove the deny permission to make the deletion succeed.

---

## 14. Investigate the Event in CloudTrail Event History

### Step 1 — Search for DeleteParameter

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
    AttributeKey=EventName,AttributeValue=DeleteParameter \
  --max-items 100 \
  --output json \
  --region "$AWS_REGION" \
  > lab08-delete-parameter-history.json
```

CloudTrail Event history is eventually consistent. A recent event may require additional time before it becomes searchable.

### Step 2 — Create Investigation Script

Save as `investigate-event-history.py`:

```python
#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 5:
    print(
        "Usage: python3 investigate-event-history.py "
        "HISTORY_JSON PARAMETER_NAME PRINCIPAL_ARN OUTPUT_JSON"
    )
    sys.exit(2)

history_file, parameter_name, principal_arn, output_file = sys.argv[1:]

with open(history_file) as file:
    document = json.load(file)

matches = []

for item in document.get("Events", []):
    raw = item.get("CloudTrailEvent")

    if not raw:
        continue

    event = json.loads(raw)
    request = event.get("requestParameters") or {}
    identity = event.get("userIdentity") or {}
    error = str(event.get("errorCode") or "")

    is_denied = (
        "accessdenied" in error.lower()
        or "unauthorized" in error.lower()
    )

    if (
        event.get("eventName") == "DeleteParameter"
        and event.get("eventSource") == "ssm.amazonaws.com"
        and request.get("name") == parameter_name
        and identity.get("arn") == principal_arn
        and is_denied
    ):
        session = identity.get("sessionContext") or {}
        issuer = session.get("sessionIssuer") or {}

        matches.append({
            "eventID": event.get("eventID"),
            "eventTime": event.get("eventTime"),
            "awsRegion": event.get("awsRegion"),
            "eventSource": event.get("eventSource"),
            "eventName": event.get("eventName"),
            "errorCode": event.get("errorCode"),
            "errorMessage": event.get("errorMessage"),
            "identityType": identity.get("type"),
            "principalArn": identity.get("arn"),
            "roleArn": issuer.get("arn"),
            "sourceIPAddress": event.get("sourceIPAddress"),
            "userAgent": event.get("userAgent"),
            "parameterName": parameter_name,
            "readOnly": event.get("readOnly")
        })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit("Target denied event not found")

print("SUCCESS: Exact denied API event identified")
```

### Step 3 — Run Investigation

```bash
python3 investigate-event-history.py \
  lab08-delete-parameter-history.json \
  "$PARAMETER_NAME" \
  "$INCIDENT_PRINCIPAL_ARN" \
  lab08-incident-event.json
```

Expected after Event history indexes the event:

```text
SUCCESS: Exact denied API event identified
```

### Step 4 — Inspect Incident Evidence

```bash
python3 -m json.tool lab08-incident-event.json
```

### Important Event Fields

| Field | Meaning |
|---|---|
| `eventID` | Unique CloudTrail event identifier |
| `eventTime` | Actual API event timestamp |
| `awsRegion` | Region receiving the API operation |
| `eventSource` | AWS service involved |
| `eventName` | Attempted API action |
| `errorCode` | Reported failure type |
| `errorMessage` | Additional error information |
| `identityType` | IAM identity category |
| `principalArn` | Calling assumed-role session |
| `roleArn` | Underlying IAM role |
| `sourceIPAddress` | Recorded request source |
| `userAgent` | Calling client information |
| `parameterName` | Target SSM resource |
| `readOnly` | Read-only classification of API operation |

### Step 5 — Verify the IAM Role Policy

```bash
aws iam get-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$INLINE_POLICY_NAME" \
  --output json
```

Expected:

```text
Effect = Deny
Action = ssm:DeleteParameter
```

### Investigation Conclusion

The assumed role attempted to delete a protected SSM parameter.

AWS rejected the request because the role's effective permissions did not authorize the operation.

The explicit IAM deny is the known preventive control causing the denial in this exercise.

---

## 15. Verify the Incident in CloudTrail S3 Audit Logs

### Step 1 — Inspect CloudTrail Delivery

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json \
  --region "$AWS_REGION"
```

### Step 2 — List Delivered Audit Logs

```bash
aws s3 ls \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  --recursive \
  --region "$AWS_REGION"
```

Expected after delivery: compressed `.json.gz` log files.

### Step 3 — Download Log Files

```bash
mkdir -p evidence/cloudtrail-logs

aws s3 cp \
  "s3://${LOG_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/${AWS_REGION}/" \
  evidence/cloudtrail-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz" \
  --region "$AWS_REGION"
```

### Step 4 — Create S3 Event Verification Script

Save as `verify-unauthorized-api-event.py`:

```python
#!/usr/bin/env python3

import glob
import gzip
import json
import os
import sys

if len(sys.argv) != 6:
    print(
        "Usage: python3 verify-unauthorized-api-event.py "
        "LOG_DIR PARAMETER_NAME PRINCIPAL_ARN "
        "INCIDENT_JSON OUTPUT_JSON"
    )
    sys.exit(2)

log_dir, parameter, principal, incident_file, output_file = sys.argv[1:]

with open(incident_file) as file:
    incident_events = json.load(file)

expected_ids = {
    event["eventID"]
    for event in incident_events
    if event.get("eventID")
}

if not expected_ids:
    raise SystemExit("No verified Event history IDs provided")

matches = []

files = glob.glob(
    os.path.join(log_dir, "**", "*.json.gz"),
    recursive=True
)

for filename in files:
    with gzip.open(filename, "rt") as file:
        document = json.load(file)

    for event in document.get("Records", []):
        request = event.get("requestParameters") or {}
        identity = event.get("userIdentity") or {}
        error = str(event.get("errorCode") or "")

        denied = (
            "accessdenied" in error.lower()
            or "unauthorized" in error.lower()
        )

        if (
            event.get("eventID") in expected_ids
            and event.get("eventName") == "DeleteParameter"
            and event.get("eventSource") == "ssm.amazonaws.com"
            and request.get("name") == parameter
            and identity.get("arn") == principal
            and denied
        ):
            matches.append({
                "eventID": event.get("eventID"),
                "eventTime": event.get("eventTime"),
                "eventName": event.get("eventName"),
                "eventSource": event.get("eventSource"),
                "awsRegion": event.get("awsRegion"),
                "principalArn": identity.get("arn"),
                "errorCode": event.get("errorCode"),
                "parameterName": parameter,
                "sourceFile": filename
            })

with open(output_file, "w") as file:
    json.dump(matches, file, indent=2)

print(json.dumps(matches, indent=2))

if not matches:
    raise SystemExit(
        "Denied incident event not yet found in S3 logs"
    )

print("SUCCESS: Denied API call verified in S3 audit logs")
```

### Step 5 — Verify Archived Event

```bash
python3 verify-unauthorized-api-event.py \
  evidence/cloudtrail-logs \
  "$PARAMETER_NAME" \
  "$INCIDENT_PRINCIPAL_ARN" \
  lab08-incident-event.json \
  lab08-s3-incident-evidence.json
```

Expected after delivery:

```text
SUCCESS: Denied API call verified in S3 audit logs
```

### Step 6 — Inspect Archived Evidence

```bash
python3 -m json.tool lab08-s3-incident-evidence.json
```

### Event Correlation

| Investigation | Expected |
|---|---|
| API name | DeleteParameter |
| Event source | ssm.amazonaws.com |
| Identity type | AssumedRole |
| Role session | Dedicated Lab 08 session |
| Target parameter | Dedicated protected parameter |
| Error | AccessDenied |
| Event history | Matching event |
| S3 audit log | Same eventID |
| Resource deletion | Prevented |

### Why Match Event IDs?

A log file may contain multiple API operations with the same event name.

Matching the exact `eventID` verifies that the archived event corresponds to the specific incident identified in Event history.

This prevents unrelated activity from being treated as the investigation result.

---

<WritingBlock id="82643" variant="document">## 16. Build the Security Incident Timeline

### Step 1 — Create Timeline Generator

Save as `build-incident-timeline.py`:

```python
#!/usr/bin/env python3

import json

with open("lab08-incident-event.json") as file:
    events = json.load(file)

if not events:
    raise SystemExit("Incident event not verified")

event = events[0]

timeline = {
    "incidentID": "INC-CT-008",
    "classification": "Controlled denied API operation",
    "eventID": event["eventID"],
    "eventTime": event["eventTime"],
    "awsRegion": event["awsRegion"],
    "eventSource": event["eventSource"],
    "eventName": event["eventName"],
    "principalArn": event["principalArn"],
    "roleArn": event["roleArn"],
    "sourceIPAddress": event["sourceIPAddress"],
    "userAgent": event["userAgent"],
    "resource": event["parameterName"],
    "errorCode": event["errorCode"],
    "outcome": "Denied",
    "rootCause": "Explicit IAM deny for ssm:DeleteParameter",
    "resourceDeleted": False
}

with open("lab08-incident-timeline.json", "w") as file:
    json.dump(timeline, file, indent=2)

print(json.dumps(timeline, indent=2))
```

### Step 2 — Generate Timeline

```bash
python3 build-incident-timeline.py
```

### Step 3 — Inspect Timeline

```bash
python3 -m json.tool lab08-incident-timeline.json
```

### Investigation Sequence

| Stage | Activity | Finding |
|---|---|---|
| 1 | Parameter created | Protected test resource available |
| 2 | IAM role created | Restricted permissions configured |
| 3 | STS AssumeRole | Temporary credentials issued |
| 4 | GetParameter | Authorized read succeeded |
| 5 | DeleteParameter | Unauthorized request denied |
| 6 | CloudTrail Event history | Denied event identified |
| 7 | IAM policy inspection | Explicit deny confirmed |
| 8 | S3 audit log verification | Same eventID confirmed |
| 9 | Resource verification | Parameter still exists |

The sequence combines recorded CloudTrail evidence with lab operations. Each stage should be reported as verified only when its corresponding command or audit record supports it.

### Incident Classification

```text
Incident ID: INC-CT-008

Classification:
Controlled Unauthorized API Attempt

Identity:
Restricted IAM AssumedRole

Attempted Action:
ssm:DeleteParameter

AWS Service:
Systems Manager Parameter Store

Authorization Result:
AccessDenied

Preventive Security Control:
Explicit IAM Deny

Resource Impact:
No successful deletion

Investigation:
CloudTrail Event History and S3 Logs

Disposition:
Expected authorized security test
```

---

## 17. Root Cause Analysis and Remediation

### Root Cause

The restricted IAM role attempted to execute `ssm:DeleteParameter` against a protected test resource.

Its inline policy explicitly denied that action.

AWS authorization evaluated the request and denied it.

This is an expected security control, not a malfunction.

The failure occurred because the attempted API operation exceeded the permissions intentionally granted to the role.

### Root Cause Flow

```text
Restricted IAM Role
        |
        v
STS Temporary Session
        |
        v
DeleteParameter Request
        |
        v
IAM Policy Evaluation
        |
        v
Explicit Deny Applies
        |
        v
AccessDenied
        |
        v
CloudTrail Event Recorded
        |
        v
Security Investigation
        |
        v
Protected Resource Verified Intact
```

### Five Whys

**Why 1 — Why did DeleteParameter fail?**

AWS rejected the operation.

**Why 2 — Why was the operation rejected?**

An explicit IAM policy deny applied to the requested action and resource.

**Why 3 — Why did the role have this restriction?**

It was designed to permit parameter reads without allowing deletion.

**Why 4 — Why did the attempted operation appear in CloudTrail?**

The API operation was a supported management event selected by CloudTrail.

**Why 5 — What remediation is required?**

For this controlled test, no permission expansion is needed. Preserve the authorization restriction, verify the resource remains intact, and document the attempted operation.

### Root Cause Summary

| Item | Finding |
|---|---|
| Incident | INC-CT-008 |
| AWS Service | Systems Manager |
| Audit Service | CloudTrail |
| Identity | AssumedRole |
| Attempted API | DeleteParameter |
| Protected Resource | Lab SSM parameter |
| IAM Control | Explicit Deny |
| API Result | AccessDenied |
| Root Cause | Attempted operation outside allowed permissions |
| Resource Impact | No deletion |
| Remediation | Preserve least-privilege policy |
| Verification | IAM policy, CloudTrail event, parameter state |

### Remediation Verification

Inspect the role policy:

```bash
aws iam get-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$INLINE_POLICY_NAME" \
  --query PolicyDocument \
  --output json
```

Verify the resource remains available:

```bash
aws ssm get-parameter \
  --name "$PARAMETER_NAME" \
  --query 'Parameter.{Name:Name,Version:Version}' \
  --output json \
  --region "$AWS_REGION"
```

Save final trail status:

```bash
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --output json \
  --region "$AWS_REGION" \
  > lab08-final-trail-status.json
```

### Security Outcome

The control functioned as intended.

The denied request was recorded, the calling role was identifiable, and the protected parameter remained intact.

---

## 18. Production Incident Response Best Practices

### Investigation Workflow

```text
Suspicious API Event
         |
         v
Identify AWS Account and Region
         |
         v
Find CloudTrail Event
         |
         v
Inspect Event Name and Error
         |
         v
Identify Calling Principal
         |
         v
Inspect Assumed Role Session
         |
         v
Review Source IP and User Agent
         |
         v
Identify Target Resource
         |
         v
Review Effective IAM Permissions
         |
         v
Inspect Related API Activity
         |
         v
Determine Resource Impact
         |
         v
Preserve Audit Evidence
         |
         v
Classify Incident and Respond
```

### Questions to Answer During Investigation

1. Which AWS account experienced the API attempt?
2. Which AWS Region received the request?
3. What operation was attempted?
4. What resource was targeted?
5. Who or what was the calling principal?
6. Was the request made using an assumed role?
7. When was the request made?
8. What was the reported error?
9. Did the operation succeed or fail?
10. Was there related activity before or after the event?
11. Was the role expected to perform that operation?
12. Did the resource change?
13. Was the source IP expected?
14. Was the session associated with an approved deployment?
15. Is the event expected, suspicious, or confirmed malicious activity?

### Other Unauthorized API Scenarios

| Scenario | Possible Cause | Investigation |
|---|---|---|
| AccessDenied on S3 | Missing bucket permission | Bucket and IAM policies |
| AccessDenied on KMS | Key policy restriction | KMS key policy |
| AccessDenied on SSM | IAM permission restriction | IAM and CloudTrail |
| UnauthorizedOperation on EC2 | Missing EC2 authorization | Effective permissions |
| AssumeRole denied | Incorrect trust or identity permission | Trust and IAM policy |
| Unexpected API principal | Wrong credentials or workload | userIdentity |
| Unexpected source IP | Unrecognized request origin | sourceIPAddress |
| Repeated denied operations | Misconfiguration or probing | Event correlation |
| Successful destructive API | Potential unauthorized change | Response and resource state |

### Production Security Recommendations

- Use least-privilege IAM roles.
- Prefer temporary credentials over long-lived access keys.
- Restrict role trust relationships.
- Review unexpected role assumptions.
- Monitor unusual high-risk API operations.
- Protect CloudTrail logging configurations.
- Preserve centralized audit evidence.
- Use appropriate alerts for important permission failures.
- Investigate successful high-risk operations in addition to denied attempts.
- Correlate CloudTrail with application, identity, and network context.
- Use approved incident response procedures when compromise is suspected.

### Important Investigation Principle

**AccessDenied is an authorization result, not a threat verdict.**

A security engineer should assess the caller's identity, expected behavior, authorization context, and surrounding activity before classifying the event as malicious.

---

## 19. AWS Resource Cleanup

**Warning:** Delete only the dedicated Lab 08 resources. Preserve investigation evidence before deleting the audit destination.

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

### Step 3 — Verify IAM Role Ownership

```bash
aws iam list-role-tags \
  --role-name "$ROLE_NAME"
```

Confirm all resources have:

```text
Project=CloudTrail-Troubleshooting-Lab08
```

### Step 4 — Clear Temporary Credentials

```bash
unset LAB_ACCESS_KEY
unset LAB_SECRET_KEY
unset LAB_SESSION_TOKEN
```

This clears the local shell variables but does not revoke an already issued STS session.

Use the original authorized identity for the remaining cleanup.

### Step 5 — Stop Trail Logging

```bash
aws cloudtrail stop-logging \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 6 — Delete CloudTrail Trail

```bash
aws cloudtrail delete-trail \
  --name "$TRAIL_NAME" \
  --region "$AWS_REGION"
```

### Step 7 — Delete the Disposable Parameter

```bash
case "$PARAMETER_NAME" in
  /cloudtrail-lab08/*)
    aws ssm delete-parameter \
      --name "$PARAMETER_NAME" \
      --region "$AWS_REGION"
    ;;
  *)
    echo "Skipping unexpected parameter"
    ;;
esac
```

### Step 8 — Delete IAM Inline Policy

```bash
aws iam delete-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$INLINE_POLICY_NAME"
```

### Step 9 — Delete IAM Role

```bash
aws iam delete-role \
  --role-name "$ROLE_NAME"
```

### Step 10 — Verify Role Deletion

```bash
aws iam get-role \
  --role-name "$ROLE_NAME"
```

Expected: `NoSuchEntity`.

### Step 11 — Delete CloudTrail S3 Log Objects

```bash
aws s3 rm "s3://${LOG_BUCKET}/" \
  --recursive \
  --region "$AWS_REGION"
```

### Step 12 — Delete S3 Bucket

```bash
aws s3api delete-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

### Step 13 — Verify Trail Deletion

```bash
aws cloudtrail list-trails \
  --region "$AWS_REGION" \
  --query "Trails[?Name=='${TRAIL_NAME}']" \
  --output json
```

### Step 14 — Verify Bucket Deletion

```bash
aws s3api head-bucket \
  --bucket "$LOG_BUCKET" \
  --region "$AWS_REGION"
```

Expected: the lab bucket is no longer found.

### Cleanup Summary

| Resource | Expected Result |
|---|---|
| Dedicated CloudTrail trail | Deleted |
| S3 audit bucket | Deleted |
| IAM investigation role | Deleted |
| IAM inline policy | Deleted |
| Protected SSM parameter | Deleted by authorized identity |
| Temporary STS credentials | Unset locally; expire naturally |
| Existing AWS resources | Unchanged |
| EC2 instances | None created |
| Customer-managed KMS keys | None created |

---

## 20. Interview Questions and Answers

### Q1. What is an unauthorized AWS API call?

A request to perform an operation that the calling identity is not authorized to execute.

### Q2. What does AccessDenied mean?

AWS rejected the operation because the applicable authorization did not permit it.

### Q3. Does AccessDenied prove an attack occurred?

No. It can result from ordinary misconfiguration, insufficient permissions, expected tests, or suspicious activity.

### Q4. How does CloudTrail help with security investigations?

It records supported AWS API activity, including information about the calling identity, operation, time, request, and outcome.

### Q5. What is userIdentity in CloudTrail?

It describes the identity responsible for an API request.

### Q6. What is the difference between IAMUser and AssumedRole?

IAMUser indicates an IAM user identity. AssumedRole indicates temporary credentials obtained through a role session.

### Q7. What is sessionIssuer?

It identifies the IAM role that issued the temporary session credentials.

### Q8. What does sourceIPAddress show?

The recorded source of the API request. Interpretation depends on the request's context.

### Q9. What does userAgent show?

Information about the calling tool or application, such as AWS CLI or an AWS SDK.

### Q10. Why is eventID useful?

It uniquely identifies an event and helps correlate the same operation across CloudTrail evidence sources.

### Q11. What is explicit deny in IAM?

An authorization rule that blocks an action even when another applicable policy grants permission.

### Q12. Why use AWS STS AssumeRole?

It allows authorized identities to obtain temporary credentials for an IAM role.

### Q13. What is the purpose of an IAM trust policy?

It determines which principals may assume the role, subject to applicable authorization controls.

### Q14. What is the difference between a trust policy and a permissions policy?

The trust policy controls role assumption. The permissions policy controls which AWS operations the role can perform.

### Q15. How do you search CloudTrail for a failed API operation?

Use `lookup-events` with an appropriate lookup attribute, then inspect the returned event JSON for errors and identity details.

### Q16. How do you verify an API event was archived in S3?

Download the relevant CloudTrail log files and match the event ID and other identifying fields.

### Q17. Why should you verify the target resource after an AccessDenied event?

To confirm the actual resource state and determine whether the attempted operation had an impact.

### Q18. Should an engineer grant additional permissions to fix every AccessDenied error?

No. Determine whether the operation is legitimately required before changing authorization.

### Q19. How do you investigate repeated AccessDenied events?

Correlate the affected principal, role session, event names, resource ARNs, source IPs, timestamps, and related successful operations.

### Q20. How would you explain this lab in an interview?

I created a dedicated CloudTrail trail with a private S3 destination and configured management-event logging.

I then created a restricted IAM role that could read a particular Systems Manager parameter but could not delete it.

I assumed the role using temporary AWS STS credentials.

The authorized GetParameter operation succeeded, but DeleteParameter was denied by IAM.

I investigated the denied operation using CloudTrail Event history and identified the calling assumed-role session, error code, API action, source IP, user agent, and target resource.

I verified that the same event was delivered to the CloudTrail S3 audit bucket by matching its event ID.

I also generated a security incident timeline and confirmed that the protected parameter remained intact.

Finally, I documented the investigation and removed the temporary AWS resources.

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
│
├── 08-investigating-unauthorized-api-calls/
│   ├── README.md
│   ├── generate-s3-policy.py
│   ├── generate-role-policy.py
│   ├── investigate-event-history.py
│   ├── verify-unauthorized-api-event.py
│   ├── build-incident-timeline.py
│   ├── cloudtrail-s3-policy.json
│   ├── lab08-trust-policy.json
│   ├── lab08-role-policy.json
│   ├── lab08-resources.env
│   ├── lab08-denied-command.stderr
│   ├── lab08-investigation-time.txt
│   ├── lab08-delete-parameter-history.json
│   ├── lab08-incident-event.json
│   ├── lab08-s3-incident-evidence.json
│   ├── lab08-incident-timeline.json
│   ├── lab08-final-trail-status.json
│   └── evidence/
│       └── cloudtrail-logs/
│
├── 09-cloudtrail-log-integrity-validation/
└── 10-cloudtrail-lake-query-troubleshooting/
```

### File Descriptions

| File | Purpose |
|---|---|
| `README.md` | Complete incident documentation |
| `generate-s3-policy.py` | Generates CloudTrail bucket policy |
| `generate-role-policy.py` | Generates restricted IAM policy |
| `investigate-event-history.py` | Extracts the exact denied event |
| `verify-unauthorized-api-event.py` | Correlates the S3 audit record |
| `build-incident-timeline.py` | Creates structured incident findings |
| `cloudtrail-s3-policy.json` | Generated CloudTrail delivery policy |
| `lab08-trust-policy.json` | Temporary role trust relationship |
| `lab08-role-policy.json` | IAM allow and explicit deny policy |
| `lab08-resources.env` | Local AWS resource identifiers |
| `lab08-denied-command.stderr` | AWS CLI authorization error |
| `lab08-delete-parameter-history.json` | CloudTrail Event history results |
| `lab08-incident-event.json` | Filtered incident event |
| `lab08-s3-incident-evidence.json` | Verified archived event |
| `lab08-incident-timeline.json` | Structured incident timeline |
| `lab08-final-trail-status.json` | Final CloudTrail status |
| `evidence/cloudtrail-logs/` | Downloaded CloudTrail audit logs |

### GitHub Evidence Guidelines

All evidence must come from actual AWS CLI operations.

Do not fabricate event IDs, timestamps, error messages, source IP addresses, user agents, or incident outcomes.

Before publishing, review all event records and generated policy files for sensitive or identifying information.

Raw CloudTrail records may contain account IDs, principal ARNs, source IP addresses, resource names, and request metadata.

Avoid committing temporary AWS credentials, account-specific environment files, or unredacted logs.

### Recommended .gitignore

```gitignore
__pycache__/
*.pyc
.venv/
.env

**/lab08-resources.env
**/lab08-*.json
**/lab08-*.stderr
**/lab08-*.txt
**/cloudtrail-s3-policy.json
**/evidence/cloudtrail-logs/
```

Generated JSON policies and incident records should remain local unless they have been sanitized and reviewed for public release.

### Lessons Learned

This lab demonstrates how AWS CloudTrail can be used to investigate unauthorized API operations.

We created a dedicated CloudTrail trail, a restricted IAM role, and a protected SSM parameter.

The IAM role was configured to permit parameter reads while explicitly denying deletion.

We assumed the restricted role using STS and reproduced an AccessDenied event.

We then examined CloudTrail Event history to identify the attempted action, role session, target resource, and authorization error.

Using Python, we located the same event in the archived CloudTrail S3 logs and verified the event ID.

We documented the investigation as a structured incident timeline.

The protected parameter remained intact, demonstrating that the authorization restriction prevented the requested deletion.

Finally, we removed the temporary AWS resources.

**Key Lesson:** CloudTrail gives security engineers evidence about AWS API activity, but the existence of an authorization failure does not independently prove malicious intent. Effective investigations require identity analysis, event correlation, resource-state verification, and appropriate context.

### Skills Demonstrated

- AWS CloudTrail
- CloudTrail Event history
- CloudTrail management events
- AWS IAM
- IAM roles
- Role trust policies
- IAM inline policies
- Explicit Deny
- AWS STS AssumeRole
- Temporary credentials
- AWS Systems Manager Parameter Store
- Amazon S3
- CloudTrail S3 log delivery
- AWS CLI v2
- Linux Bash
- Python 3
- JSON processing
- GZIP audit log parsing
- AssumedRole identity analysis
- CloudTrail event correlation
- AccessDenied troubleshooting
- Incident timeline creation
- Root cause analysis
- Security control verification
- Resource cleanup

### Final Outcome

| Item | Expected Result |
|---|---|
| Incident | INC-CT-008 |
| Scenario | Investigating Unauthorized API Calls |
| Trail | cloudtrail-lab08-trail |
| AWS Region | us-east-1 |
| IAM Identity | Restricted AssumedRole |
| Authorized Operation | GetParameter |
| Denied Operation | DeleteParameter |
| Error | AccessDenied |
| Root Cause | Explicit IAM deny |
| Protected Parameter | Not deleted by denied attempt |
| Event History | Incident verified |
| S3 Audit Logs | Same eventID verified |
| Timeline | Generated from actual evidence |
| Security Classification | Controlled denied operation |
| Cleanup | Dedicated resources deleted |
| Incident Status | Closed after evidence verification |

**Key Takeaway:** A Cloud Security Engineer should be able to trace an AWS API operation back to its calling principal, explain the authorization result, verify the affected resource's state, and correlate the evidence across CloudTrail sources.

---

## Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Working with CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [CloudTrail Event Records](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [CloudTrail userIdentity Element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [AWS CLI — LookupEvents](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html)
- [AWS CLI — AssumeRole](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)
- [CloudTrail S3 Bucket Policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)