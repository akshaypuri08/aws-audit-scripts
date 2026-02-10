import boto3
import json
import csv
from datetime import datetime, timedelta, timezone

DAYS = 30
REGION = "us-east-1"   # change if needed
OUTPUT_FILE = "active_sqs_from_cloudtrail.csv"

EVENT_NAMES = ["SendMessage", "ReceiveMessage", "DeleteMessage"]

start_time = datetime.now(timezone.utc) - timedelta(days=DAYS)
end_time = datetime.now(timezone.utc)

cloudtrail = boto3.client("cloudtrail", region_name=REGION)

active_queues = set()

print("Fetching CloudTrail events...")

for event_name in EVENT_NAMES:
    print(f"Checking {event_name} events...")

    paginator = cloudtrail.get_paginator("lookup_events")

    for page in paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventName", "AttributeValue": event_name}
        ],
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"PageSize": 50}
    ):
        for event in page["Events"]:
            try:
                detail = json.loads(event["CloudTrailEvent"])
                queue_url = detail.get("requestParameters", {}).get("queueUrl")
                if queue_url:
                    queue_name = queue_url.split("/")[-1]
                    active_queues.add(queue_name)
            except Exception:
                continue


# Write CSV
with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["QueueName"])
    for q in sorted(active_queues):
        writer.writerow([q])

print("\n==============================")
print(f"Total active queues (last {DAYS} days): {len(active_queues)}")
print(f"Saved to: {OUTPUT_FILE}")
