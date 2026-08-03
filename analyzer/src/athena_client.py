"""Athena access to CloudTrail logs: table DDL with partition
projection, plus the consumer access query."""

import time

DDL = """
CREATE EXTERNAL TABLE IF NOT EXISTS {database}.cloudtrail_logs (
    eventversion STRING,
    useridentity STRUCT<
        type: STRING,
        principalid: STRING,
        arn: STRING,
        accountid: STRING,
        invokedby: STRING,
        accesskeyid: STRING,
        username: STRING>,
    eventtime STRING,
    eventsource STRING,
    eventname STRING,
    awsregion STRING,
    sourceipaddress STRING,
    useragent STRING,
    errorcode STRING,
    errormessage STRING,
    requestparameters STRING,
    responseelements STRING,
    requestid STRING,
    eventid STRING,
    eventtype STRING,
    recipientaccountid STRING
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{trail_bucket}/AWSLogs/{account_id}/CloudTrail/{region}/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.dt.type' = 'date',
    'projection.dt.format' = 'yyyy/MM/dd',
    'projection.dt.range' = 'NOW-{lookback_days}DAYS,NOW',
    'projection.dt.interval' = '1',
    'projection.dt.interval.unit' = 'DAYS',
    'storage.location.template' =
        's3://{trail_bucket}/AWSLogs/{account_id}/CloudTrail/{region}/${{dt}}/'
)
"""

# Athena partition-projected tables need the partition column declared.
DDL_PARTITION = "PARTITIONED BY (dt STRING)\n"

ACCESS_QUERY = """
SELECT
    COALESCE(
        json_extract_scalar(requestparameters, '$.secretId'),
        json_extract_scalar(requestparameters, '$.name')
    ) AS resource_id,
    useridentity.arn AS principal_arn,
    eventname AS event_name,
    COUNT(*) AS access_count,
    MAX(eventtime) AS last_accessed
FROM {database}.cloudtrail_logs
WHERE eventname IN ('GetSecretValue', 'GetParameter')
  AND errorcode IS NULL
  AND dt >= date_format(date_add('day', -{lookback_days}, now()), '%Y/%m/%d')
GROUP BY 1, 2, 3
"""


def build_ddl(database, trail_bucket, account_id, region, lookback_days):
    body = DDL.format(
        database=database,
        trail_bucket=trail_bucket,
        account_id=account_id,
        region=region,
        lookback_days=lookback_days,
    )
    # Insert the PARTITIONED BY clause before ROW FORMAT.
    return body.replace("ROW FORMAT SERDE", DDL_PARTITION + "ROW FORMAT SERDE", 1)


def run_query(athena, sql, database, workgroup, timeout_seconds=120):
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": database},
        WorkGroup=workgroup,
    )["QueryExecutionId"]
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        if state["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            if state["State"] != "SUCCEEDED":
                raise RuntimeError(
                    f"athena query {state['State']}: {state.get('StateChangeReason', '')}")
            return qid
        time.sleep(2)
    raise TimeoutError("athena query timed out")


def fetch_rows(athena, qid):
    """Yield result rows as dicts keyed by column name."""
    paginator = athena.get_paginator("get_query_results")
    header = None
    for page in paginator.paginate(QueryExecutionId=qid):
        rows = page["ResultSet"]["Rows"]
        if header is None:
            header = [c["VarCharValue"] for c in rows[0]["Data"]]
            rows = rows[1:]
        for row in rows:
            values = [c.get("VarCharValue") for c in row["Data"]]
            yield dict(zip(header, values))


def query_access_events(athena, database, workgroup, trail_bucket,
                        account_id, region, lookback_days):
    run_query(athena, build_ddl(database, trail_bucket, account_id, region,
                                lookback_days),
              database, workgroup)
    sql = ACCESS_QUERY.format(database=database, lookback_days=lookback_days)
    qid = run_query(athena, sql, database, workgroup)
    return list(fetch_rows(athena, qid))
