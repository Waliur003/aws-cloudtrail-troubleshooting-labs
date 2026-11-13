SELECT eventTime, eventName, parameterName
FROM events
WHERE eventTime >= '2020-01-01T00:00:00'
  AND eventTime < '2020-01-02T00:00:00'
  AND eventName = 'PutParameter';
