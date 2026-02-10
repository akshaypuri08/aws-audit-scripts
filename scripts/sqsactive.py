import boto3
import csv
from datetime import datetime, timedelta, timezone

REGION = "us-east-1"
DAYS = 30
OUTPUT_FILE = "sqs_activity_report.csv"

sqs = boto3.client("sqs", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=DAYS)

METRICS = [
    "NumberOfMessagesSent",
    "NumberOfMessagesReceived",
    "NumberOfMessagesDeleted"
]

def get_queue_name(queue_url):
    return queue_url.split("/")[-1]

def get_activity(queue_name):
    queries = []
    for idx, metric in enumerate(METRICS):
        queries.append({
            "Id": f"m{idx}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/SQS",
                    "MetricName": metric,
                    "Dimensions": [
                        {"Name": "QueueName", "Value": queue_name}
                    ]
                },
                "Period": 300,   # 5 minutes
                "Stat": "Sum"
            },
            "ReturnData": True
        })

    response = cw.get_metric_data(
        MetricDataQueries=queries,
        StartTime=start_time,
        EndTime=end_time,
        ScanBy="TimestampDescending",
        MaxDatapoints=1000
    )

    totals = {}
    active = False

    for result in response["MetricDataResults"]:
        total = int(sum(result.get("Values", [])))
        totals[result["Id"]] = total
        if total > 0:
            active = True

    return active, totals

# List all queues
queues = []
response = sqs.list_queues()
queues.extend(response.get("QueueUrls", []))

while "NextToken" in response:
    response = sqs.list_queues(NextToken=response["NextToken"])
    queues.extend(response.get("QueueUrls", []))

rows = []

for queue_url in queues:
    queue_name = get_queue_name(queue_url)
    print(f"Checking: {queue_name}")

    active, totals = get_activity(queue_name)

    rows.append({
        "QueueName": queue_name,
        "QueueUrl": queue_url,
        "Status": "ACTIVE" if active else "DORMANT",
        "MessagesSentLast30Days": totals.get("m0", 0),
        "MessagesReceivedLast30Days": totals.get("m1", 0),
        "MessagesDeletedLast30Days": totals.get("m2", 0),
        "LastCheckedAt": end_time.isoformat()
    })

# Write CSV
with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "QueueName",
            "QueueUrl",
            "Status",
            "MessagesSentLast30Days",
            "MessagesReceivedLast30Days",
            "MessagesDeletedLast30Days",
            "LastCheckedAt"
        ]
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"\n✅ Corrected CSV generated: {OUTPUT_FILE}")
