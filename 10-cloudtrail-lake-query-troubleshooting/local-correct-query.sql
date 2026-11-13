SELECT
    eventID,
    eventTime,
    eventName,
    eventSource,
    awsRegion,
    parameterName
FROM events
WHERE eventName = 'PutParameter'
  AND eventSource = 'ssm.amazonaws.com'
  AND awsRegion = 'us-east-1'
ORDER BY eventTime DESC
LIMIT 20;
