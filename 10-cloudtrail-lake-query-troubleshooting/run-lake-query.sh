#!/usr/bin/env bash
set -euo pipefail

SQL_FILE="${1:?Usage: ./run-lake-query.sh FILE.sql LABEL}"
LABEL="${2:?Provide a label}"

QUERY_ID=$(aws cloudtrail start-query \
  --query-statement "file://${SQL_FILE}" \
  --query QueryId \
  --output text \
  --region "$AWS_REGION")

echo "Query ID: $QUERY_ID"

printf '%s\n' "$QUERY_ID" > "${LABEL}-query-id.txt"

aws cloudtrail describe-query \
  --query-id "$QUERY_ID" \
  --region "$AWS_REGION" \
  --output json \
  > "${LABEL}-query-status.json"

cat "${LABEL}-query-status.json"
