SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion,
    parameterName
FROM events
WHERE eventName = 'PutParameters'
  AND awsRegion = 'us-east-1'
LIMIT 20;
