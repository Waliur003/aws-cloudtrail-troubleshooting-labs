# AWS CloudTrail Troubleshooting Labs

### Production-Style AWS Cloud Security, Audit Logging, and Incident Investigation

A hands-on collection of 10 AWS CloudTrail troubleshooting labs designed to simulate real-world cloud engineering and cloud security incidents.

This repository focuses on investigating, diagnosing, and resolving AWS CloudTrail logging failures, security misconfigurations, missing audit events, encryption issues, and incident investigation challenges.

Each lab uses AWS CLI and Linux Bash to reproduce a controlled problem, investigate the root cause, implement remediation, verify recovery, and document the results.

The labs progress from foundational CloudTrail troubleshooting to more advanced audit logging, security investigations, log integrity validation, and CloudTrail Lake analysis.

---

## 1. Project Overview

AWS CloudTrail records account activity and supported AWS API operations to help organizations monitor cloud environments, investigate incidents, and maintain audit records.

CloudTrail is widely used in cloud operations, cloud security, incident response, and compliance workflows.

However, an incorrectly configured trail can create serious visibility gaps.

Examples include:

- Missing audit events.
- Disabled trail logging.
- Failed delivery to Amazon S3.
- Incorrect S3 bucket policies.
- AWS KMS encryption failures.
- Missing S3 object-level events.
- Incomplete multi-Region logging.
- Suspicious API activity.
- Log integrity validation failures.
- CloudTrail Lake query problems.

This repository demonstrates how engineers can investigate these situations using practical AWS CLI commands, service configuration inspection, audit event analysis, and structured root cause analysis.

### Project Goals

- Develop AWS CloudTrail troubleshooting skills.
- Understand management events and data events.
- Investigate S3 log delivery failures.
- Troubleshoot CloudTrail permissions and encryption.
- Identify multi-Region logging gaps.
- Investigate suspicious and unauthorized API operations.
- Validate CloudTrail log file integrity.
- Learn CloudTrail Lake query troubleshooting.
- Apply production-oriented incident response methods.
- Build a documented cloud security engineering portfolio.

---

## 2. Technologies and Tools

| Technology | Purpose |
|---|---|
| AWS CloudTrail | AWS API activity auditing |
| Amazon S3 | CloudTrail log storage |
| AWS KMS | CloudTrail log encryption |
| AWS CloudTrail Lake | Event data storage and SQL queries |
| AWS IAM | Identity and access investigation |
| Amazon CloudWatch | Related monitoring and diagnostics |
| AWS CLI v2 | Troubleshooting and remediation |
| Linux Ubuntu (WSL2) | Command-line environment |
| Bash | Automation and investigation |
| JSON | CloudTrail event analysis |
| SQL | CloudTrail Lake queries |
| Git | Version control |
| GitHub | Lab documentation and portfolio |

**Primary Region:** `us-east-1`

Labs involving multi-Region logging will use an additional AWS Region when required.

---

## 3. CloudTrail Architecture

### Standard CloudTrail Logging Architecture

```text
                 AWS Account
                      |
                      v
             AWS API Activity
                      |
         +------------+------------+
         |            |            |
         v            v            v
       AWS CLI     Console       AWS SDK
         |            |            |
         +------------+------------+
                      |
                      v
                 AWS CloudTrail
                      |
                      v
             Trail Configuration
                      |
         +------------+------------+
         |            |            |
         v            v            v
     Management    Data Events   Insights Events
       Events       (Optional)     (Optional)
         |            |            |
         +------------+------------+
                      |
                      v
               Event Collection
                      |
                      v
              Amazon S3 Bucket
                      |
         +------------+------------+
         |                         |
         v                         v
    AWS KMS Encryption     Log File Integrity
       (Optional)             Validation
         |                         |
         +------------+------------+
                      |
                      v
                 Audit Logs
                      |
                      v
          Security Investigation
                      |
                      v
             Root Cause Analysis
```

### CloudTrail Lake Architecture

```text
             AWS API Activity
                    |
                    v
               AWS CloudTrail
                    |
                    v
            CloudTrail Lake
                    |
                    v
             Event Data Store
                    |
                    v
                SQL Queries
                    |
                    v
             Query Results
                    |
                    v
        Security and Audit Analysis
```

### Important Architecture Concepts

A CloudTrail trail delivers selected events to Amazon S3 and can optionally integrate with CloudWatch Logs.

CloudTrail Lake uses event data stores and SQL-based analysis.

CloudTrail Event history is separate from trails and Lake event data stores.

---

## 4. CloudTrail Fundamentals

### CloudTrail Event History

CloudTrail Event history provides access to the previous 90 days of supported management events in an AWS Region.

Event history is available without creating a trail.

Example:

```bash
aws cloudtrail lookup-events \
  --region us-east-1
```

Event history does not show data events, and its historical management events remain accessible even when a separate trail is stopped.

### CloudTrail Trails

A trail is a configuration that delivers selected CloudTrail events to an S3 bucket.

Trails support ongoing audit log collection, including management events and appropriately configured data events.

Common AWS CLI commands:

```bash
aws cloudtrail describe-trails
```

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

```bash
aws cloudtrail get-event-selectors \
  --trail-name YOUR_TRAIL_NAME
```

### Management Events

Management events record supported control-plane activity, such as:

- Creating AWS resources.
- Modifying security configurations.
- Updating routing configurations.
- Changing CloudTrail settings.
- Managing IAM policies.

### Data Events

Data events record supported resource-level operations.

Examples include:

- Amazon S3 object API operations.
- AWS Lambda function invocations.

Data events require explicit configuration for the applicable trails or event data stores.

### Multi-Region Trails

A multi-Region trail collects supported events from enabled AWS Regions in an account.

This helps organizations maintain broader audit visibility.

### CloudTrail Log File Integrity Validation

CloudTrail can deliver digest files that support validation of log file integrity.

Engineers can use CloudTrail's validation tools to detect modifications or deletions that affect the validated log chain.

### CloudTrail Lake

CloudTrail Lake supports storing and querying supported events using event data stores.

It provides SQL-based investigations beyond the basic Event history lookup functionality.

---

## 5. Troubleshooting Lab Roadmap

| Lab | Troubleshooting Scenario | Main Investigation |
|---|---|---|
| 01 | CloudTrail Events Missing | Event history, Region, event source, time range |
| 02 | Trail Logging Disabled | Trail status and logging state |
| 03 | CloudTrail S3 Delivery Failure | Delivery status and S3 destination |
| 04 | CloudTrail Bucket Policy Error | S3 permissions and CloudTrail service principal |
| 05 | CloudTrail KMS Encryption Failure | KMS key policy and encryption configuration |
| 06 | Data Events Not Recorded | Event selectors and S3 object-level activity |
| 07 | Multi-Region Trail Misconfiguration | Regional coverage and trail configuration |
| 08 | Investigating Unauthorized API Calls | Identity, source IP, error codes, and event history |
| 09 | CloudTrail Log Integrity Validation | Digest files and integrity verification |
| 10 | CloudTrail Lake Query Troubleshooting | Event data stores and SQL query investigation |

---

## 6. Lab 01 — CloudTrail Events Missing

**Folder:** `01-cloudtrail-events-missing/`

### Production Incident

A Cloud Engineer attempts to investigate a recent AWS API operation but cannot find the expected event in CloudTrail Event history.

### Troubleshooting Focus

- Verify AWS account and Region.
- Inspect event history.
- Search by event name and source.
- Review event timestamps.
- Understand Event history limitations.
- Distinguish management events from data events.
- Identify why the expected event isn't visible in the searched location.
- Verify the corrected investigation process.

### AWS CLI Commands

```bash
aws sts get-caller-identity
```

```bash
aws cloudtrail lookup-events \
  --region us-east-1
```

**Expected Learning:** Understand how to troubleshoot apparently missing CloudTrail events before assuming audit logging has failed.

---

## 7. Lab 02 — Trail Logging Disabled

**Folder:** `02-trail-logging-disabled/`

### Production Incident

A dedicated CloudTrail trail stops delivering new log files because logging was disabled.

### Troubleshooting Focus

- Inspect trail configuration.
- Verify `IsLogging`.
- Review trail status.
- Identify the logging interruption.
- Restore logging on the dedicated test trail.
- Verify new log delivery.

### AWS CLI Commands

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

```bash
aws cloudtrail start-logging \
  --name YOUR_TRAIL_NAME
```

**Expected Learning:** Diagnose and restore a stopped CloudTrail trail.

All logging-state tests must use lab-owned trails, not production or organization security trails.

---

## 8. Lab 03 — CloudTrail S3 Delivery Failure

**Folder:** `03-cloudtrail-s3-delivery-failure/`

### Production Incident

CloudTrail is configured to deliver audit logs to Amazon S3, but the expected objects are missing.

### Troubleshooting Focus

- Inspect trail configuration.
- Check the S3 destination bucket.
- Inspect CloudTrail delivery status.
- Verify bucket Region and destination configuration.
- Review delivery errors.
- Restore successful S3 log delivery.

### AWS CLI Commands

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

```bash
aws s3api head-bucket \
  --bucket YOUR_BUCKET_NAME
```

**Expected Learning:** Troubleshoot CloudTrail log delivery to S3.

---

## 9. Lab 04 — CloudTrail Bucket Policy Error

**Folder:** `04-cloudtrail-bucket-policy-error/`

### Production Incident

A CloudTrail trail cannot write audit logs because its destination S3 bucket policy contains an incorrect permission or resource configuration.

### Troubleshooting Focus

- Inspect S3 bucket policies.
- Understand the CloudTrail service principal.
- Check required bucket access.
- Investigate permission failures.
- Correct a lab-owned bucket policy.
- Verify CloudTrail log delivery.

### AWS CLI Commands

```bash
aws s3api get-bucket-policy \
  --bucket YOUR_BUCKET_NAME
```

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

**Expected Learning:** Diagnose and correct S3 access policy failures affecting audit log delivery.

---

## 10. Lab 05 — CloudTrail KMS Encryption Failure

**Folder:** `05-cloudtrail-kms-encryption-failure/`

### Production Incident

CloudTrail encounters an encryption-related delivery failure because the configured AWS KMS key policy does not allow the required CloudTrail operations.

### Troubleshooting Focus

- Inspect trail encryption settings.
- Verify KMS key configuration.
- Inspect key policies.
- Investigate CloudTrail delivery errors.
- Understand CloudTrail KMS permissions.
- Correct encryption configuration.
- Verify encrypted log delivery.

### AWS CLI Commands

```bash
aws cloudtrail describe-trails
```

```bash
aws kms describe-key \
  --key-id YOUR_KMS_KEY_ID
```

```bash
aws kms get-key-policy \
  --key-id YOUR_KMS_KEY_ID \
  --policy-name default
```

**Expected Learning:** Troubleshoot CloudTrail log encryption failures without weakening production key security.

---

## 11. Lab 06 — Data Events Not Recorded

**Folder:** `06-data-events-not-recorded/`

### Production Incident

A security team expects to see S3 object-level API activity, but the events do not appear in its trail logs.

### Troubleshooting Focus

- Understand management and data events.
- Inspect event selectors.
- Verify supported resource types.
- Investigate missing object-level events.
- Configure appropriate data event logging.
- Generate controlled test activity.
- Verify newly recorded events.

### AWS CLI Commands

```bash
aws cloudtrail get-event-selectors \
  --trail-name YOUR_TRAIL_NAME
```

```bash
aws cloudtrail put-event-selectors \
  --trail-name YOUR_TRAIL_NAME \
  --advanced-event-selectors file://event-selectors.json
```

**Expected Learning:** Understand and troubleshoot CloudTrail data event collection.

---

## 12. Lab 07 — Multi-Region Trail Misconfiguration

**Folder:** `07-multi-region-trail-misconfiguration/`

### Production Incident

An organization expects centralized AWS audit visibility, but its trail records events from only one Region.

### Troubleshooting Focus

- Inspect trail Region configuration.
- Understand single-Region and multi-Region trails.
- Investigate event coverage gaps.
- Verify enabled AWS Regions.
- Correct the lab trail configuration.
- Verify multi-Region coverage.

### AWS CLI Commands

```bash
aws cloudtrail describe-trails
```

```bash
aws cloudtrail update-trail \
  --name YOUR_TRAIL_NAME \
  --is-multi-region-trail
```

**Expected Learning:** Troubleshoot missing audit coverage caused by incorrect regional configuration.

---

## 13. Lab 08 — Investigating Unauthorized API Calls

**Folder:** `08-investigating-unauthorized-api-calls/`

### Production Incident

The security team identifies suspicious AWS API operations returning authorization errors.

A Cloud Security Engineer must determine which identity attempted the action, when it occurred, which resource was targeted, and why the operation was denied.

### Troubleshooting Focus

- Inspect CloudTrail events.
- Identify event names and sources.
- Investigate the request identity.
- Inspect error codes and messages.
- Examine source IP addresses.
- Correlate timestamps and actions.
- Distinguish expected AccessDenied events from suspicious activity.
- Document security investigation findings.

### AWS CLI Commands

```bash
aws cloudtrail lookup-events \
  --lookup-attributes \
  AttributeKey=EventName,AttributeValue=YOUR_EVENT_NAME \
  --region us-east-1
```

**Expected Learning:** Perform evidence-based CloudTrail API activity investigations without attempting unauthorized access.

---

## 14. Lab 09 — CloudTrail Log Integrity Validation

**Folder:** `09-cloudtrail-log-integrity-validation/`

### Production Incident

A security audit requires verification that CloudTrail log files have not been modified or deleted after delivery.

### Troubleshooting Focus

- Understand CloudTrail digest files.
- Inspect integrity validation configuration.
- Locate log files and digest files.
- Execute validation commands.
- Interpret validation results.
- Understand integrity failure scenarios.
- Document audit evidence.

### AWS CLI Commands

```bash
aws cloudtrail validate-logs \
  --trail-arn YOUR_TRAIL_ARN \
  --start-time YOUR_START_TIME \
  --end-time YOUR_END_TIME
```

**Expected Learning:** Verify CloudTrail log file integrity and understand evidence preservation.

---

## 15. Lab 10 — CloudTrail Lake Query Troubleshooting

**Folder:** `10-cloudtrail-lake-query-troubleshooting/`

### Production Incident

A Cloud Security Engineer runs a CloudTrail Lake query but receives missing records, unexpected results, or a query execution error.

### Troubleshooting Focus

- Inspect event data stores.
- Verify event collection settings.
- Understand retention configuration.
- Investigate query time ranges.
- Troubleshoot SQL syntax.
- Inspect query status.
- Retrieve query results.
- Analyze selected AWS API activity.
- Verify the incident investigation.

### AWS CLI Commands

```bash
aws cloudtrail list-event-data-stores \
  --region us-east-1
```

```bash
aws cloudtrail start-query \
  --query-statement "SELECT * FROM EVENT_DATA_STORE_ID LIMIT 10" \
  --region us-east-1
```

```bash
aws cloudtrail describe-query \
  --query-id YOUR_QUERY_ID \
  --region us-east-1
```

**Expected Learning:** Troubleshoot CloudTrail Lake ingestion and SQL query investigations.

CloudTrail Lake creates additional usage-based charges. Event data stores must be configured with appropriate retention and deleted when no longer needed, subject to service restrictions.

---

## 16. Standard Troubleshooting Methodology

Each lab follows a consistent production-oriented approach.

### Phase 1 — Prepare Environment

Verify AWS credentials, Region, CLI configuration, and required permissions.

### Phase 2 — Deploy Test Infrastructure

Create dedicated AWS resources required to reproduce the incident.

### Phase 3 — Fault Injection

Intentionally introduce a controlled logging, delivery, encryption, or configuration problem.

### Phase 4 — Observe Symptoms

Inspect CloudTrail and related AWS service behavior.

### Phase 5 — Investigate

Use AWS CLI to inspect service configuration, delivery errors, events, policies, and other evidence.

### Phase 6 — Root Cause Analysis

Identify the exact reason the simulated failure occurred.

### Phase 7 — Remediation

Correct the misconfiguration using the minimum necessary changes.

### Phase 8 — Verification

Confirm that CloudTrail behaves as intended after remediation.

### Phase 9 — Evidence Collection

Save relevant AWS CLI outputs, event records, and configuration comparisons.

### Phase 10 — Cleanup

Delete temporary lab resources after validating ownership.

### Phase 11 — Documentation

Create a detailed lab-specific README that explains the entire troubleshooting process.

---

## 17. AWS CLI Troubleshooting Reference

### CloudTrail

```bash
aws cloudtrail describe-trails
```

```bash
aws cloudtrail list-trails
```

```bash
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME
```

```bash
aws cloudtrail lookup-events \
  --region us-east-1
```

```bash
aws cloudtrail get-event-selectors \
  --trail-name YOUR_TRAIL_NAME
```

### Amazon S3

```bash
aws s3api head-bucket \
  --bucket YOUR_BUCKET_NAME
```

```bash
aws s3api get-bucket-policy \
  --bucket YOUR_BUCKET_NAME
```

```bash
aws s3 ls s3://YOUR_BUCKET_NAME/
```

### AWS KMS

```bash
aws kms describe-key \
  --key-id YOUR_KMS_KEY_ID
```

```bash
aws kms get-key-policy \
  --key-id YOUR_KMS_KEY_ID \
  --policy-name default
```

### CloudTrail Lake

```bash
aws cloudtrail list-event-data-stores
```

```bash
aws cloudtrail list-queries \
  --event-data-store YOUR_EVENT_DATA_STORE_ID
```

---

## 18. Security and Cost Management

### Security Guidelines

- Never disable an existing production CloudTrail trail.
- Never modify organization-level trails for testing.
- Use dedicated resources for fault injection.
- Protect CloudTrail log buckets from unauthorized modification.
- Preserve encryption and audit evidence.
- Use least-privilege IAM permissions.
- Avoid committing credentials or sensitive event data.
- Verify resources before deletion.
- Document every intentional configuration change.

### Cost Management

Potential charges include:

- CloudTrail data events.
- Additional copies of management events.
- S3 storage and requests.
- AWS KMS API requests.
- CloudWatch Logs integrations.
- CloudTrail Lake ingestion, retention, and query usage.

CloudTrail Event history provides access to recent management events without requiring paid trail creation.

Use only the resources needed for each lab, and review cost implications before enabling CloudTrail Lake or high-volume data event collection.

### Cleanup Principles

Always verify ownership before deleting resources.

Delete dedicated lab trails and temporary storage resources after completing the exercise, provided they are no longer required.

Do not delete existing organization audit infrastructure.

---

## 19. Repository Structure

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
│   └── README.md
│
├── 08-investigating-unauthorized-api-calls/
│   └── README.md
│
├── 09-cloudtrail-log-integrity-validation/
│   └── README.md
│
└── 10-cloudtrail-lake-query-troubleshooting/
    └── README.md
```

Each lab will contain the relevant scripts, configuration files, incident evidence, and detailed documentation required for its scenario.

Lab folders are developed individually, with their contents added after the corresponding hands-on exercise.

---

## 20. Interview Preparation

These labs build troubleshooting skills relevant to Cloud Engineer, Cloud Operations Engineer, Infrastructure Engineer, and Cloud Security Engineer positions.

### Core Interview Topics

**What is AWS CloudTrail?**

AWS CloudTrail records supported account activity and API operations to support auditing, operational troubleshooting, and security investigations.

**What is the difference between Event history and a trail?**

Event history provides recent regional management events, while a trail delivers selected events to S3 for ongoing collection.

**Why might CloudTrail logs be missing?**

Possible causes include searching the wrong Region, disabled trail logging, unsupported event types, event selector configuration, delivery problems, or an incorrect time range.

**How do you investigate CloudTrail S3 delivery failures?**

Inspect trail status, destination bucket configuration, bucket policy, and the reported delivery errors.

**What is CloudTrail log integrity validation?**

A mechanism for checking the integrity of delivered CloudTrail logs using digest files and cryptographic verification.

**Why are multi-Region trails important?**

They help maintain audit coverage across enabled AWS Regions.

**What is CloudTrail Lake?**

A managed capability for storing and querying supported audit events using SQL.

---

## 21. Skills Demonstrated

### AWS Services

- Amazon CloudTrail
- Amazon S3
- AWS KMS
- AWS IAM
- Amazon CloudWatch
- AWS CloudTrail Lake

### Technical Skills

- AWS CLI v2
- Linux Bash
- JSON event analysis
- SQL query investigation
- AWS API auditing
- Event selector configuration
- S3 bucket policy troubleshooting
- KMS key policy investigation
- Multi-Region audit logging
- CloudTrail delivery diagnostics
- Log integrity validation
- Security incident investigation
- Root cause analysis
- Operational documentation
- Infrastructure cleanup

### Career Relevance

This repository demonstrates practical experience with AWS audit logging, CloudTrail configuration, cloud security monitoring, event investigation, and production-style troubleshooting.

It is intended as a hands-on portfolio project for:

- Junior Cloud Engineer
- Cloud Operations Engineer
- Associate Cloud Engineer
- Infrastructure Engineer
- Cloud Security Engineer
- Cloud Security Operations Engineer

---

## 22. Official AWS Documentation

- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [How AWS CloudTrail Works](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html)
- [Creating a CloudTrail Trail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html)
- [Multi-Region CloudTrail Trails](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html)
- [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/)

---

## Final Project Goal

Build practical troubleshooting skills through ten progressively more advanced AWS CloudTrail incidents.

Each lab focuses on understanding the failure, investigating the root cause, applying remediation, verifying the outcome, and documenting evidence.

The project emphasizes real AWS CLI operations, security principles, audit logging reliability, and the troubleshooting methods used in cloud engineering and cloud security roles.
