from __future__ import annotations
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

import boto3
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError
import pandas as pd

# =========================================================
# CONFIG
# =========================================================
MAX_THREADS = 10
DEFAULT_PROFILE = "samples"
DEFAULT_OUTPUT = "aws_security_pillar_inventory"

TARGET_REGIONS = {
    "us-east-1": "N. Virginia",
    "eu-west-1": "Ireland",
    "ap-southeast-2": "Sydney",
    "ca-central-1": "Canada Central"
}

SECURITY_PILLAR_COVERAGE = {
    "Amazon EC2": "Yes",
    "Amazon S3": "Yes",
    "AWS Lambda": "Yes",
    "Amazon RDS": "Yes",
    "Amazon ECS": "Yes",
    "AWS CloudFormation": "Yes",
    "Amazon SNS": "Conditional",
    "Amazon SQS": "Conditional",
    "Elastic Load Balancing": "Yes",
    "Amazon VPC": "Yes",
    "CloudWatch Alarms": "Yes",
    "Amazon GuardDuty": "Yes",
    "Amazon ECR": "Yes",
    "Amazon SES": "Conditional",
    "AWS Systems Manager": "Yes",
    "AWS Elastic Disaster Recovery": "Yes",
    "Amazon ElastiCache": "Yes",
    "AWS Pinpoint": "Conditional",
    "Amazon Location Service": "Conditional",
    "Amazon Neptune": "Yes",
    "Amazon Route 53": "Yes",
    "AWS Secrets Manager": "Yes",
    "AWS KMS": "Yes",
    "AWS Glue": "Yes",
    "AWS WAF v2": "Yes",
    "AWS CloudTrail": "Yes",
    "Amazon ACM": "Yes",
}

lock = threading.Lock()

# =========================================================
# LOGGING
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# =========================================================
# HELPERS
# =========================================================
def safe_call(func, default=0):
    try:
        return func()
    except (ClientError, BotoCoreError, EndpointConnectionError):
        return default

def get_session(profile):
    try:
        return boto3.Session(profile_name=profile)
    except Exception:
        return boto3.Session()

# =========================================================
# REGION WORKER
# =========================================================
def worker(session, account_id, region):
    region_name = TARGET_REGIONS[region]
    logger.info(f"Scanning {region} ({region_name})")
    rows = []

    def client(svc):
        return session.client(svc, region_name=region)

    def add(service, count):
        if count > 0:
            rows.append([
                account_id,
                region,
                region_name,
                service,
                count,
                SECURITY_PILLAR_COVERAGE.get(service, "Unknown")
            ])

    # ---------------- COMPUTE ----------------
    add("Amazon EC2", safe_call(lambda: sum(
        len(r["Instances"]) for r in client("ec2").describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )["Reservations"]
    )))

    # ---------------- NETWORK ----------------
    add("Amazon VPC", safe_call(lambda: len(client("ec2").describe_vpcs()["Vpcs"])))
    add("Elastic Load Balancing", safe_call(lambda: len(
        client("elbv2").describe_load_balancers()["LoadBalancers"]
    )))

    # ---------------- STORAGE ----------------
    if region == "us-east-1":
        add("Amazon S3", safe_call(lambda: len(
            session.client("s3").list_buckets()["Buckets"]
        )))

    # ---------------- SERVERLESS / CONTAINERS ----------------
    add("AWS Lambda", safe_call(lambda: len(
        client("lambda").list_functions()["Functions"]
    )))
    add("Amazon ECS", safe_call(lambda: len(
        client("ecs").list_clusters()["clusterArns"]
    )))
    add("Amazon ECR", safe_call(lambda: len(
        client("ecr").describe_repositories()["repositories"]
    )))

    # ---------------- DATABASE ----------------
    add("Amazon RDS", safe_call(lambda: len(
        client("rds").describe_db_instances()["DBInstances"]
    )))
    add("Amazon ElastiCache", safe_call(lambda: len(
        client("elasticache").describe_cache_clusters()["CacheClusters"]
    )))
    add("Amazon Neptune", safe_call(lambda: len(
        client("neptune").describe_db_clusters()["DBClusters"]
    )))

    # ---------------- SECURITY ----------------
    add("AWS KMS", safe_call(lambda: len(client("kms").list_keys()["Keys"])))
    add("AWS Secrets Manager", safe_call(lambda: len(
        client("secretsmanager").list_secrets()["SecretList"]
    )))
    add("Amazon ACM", safe_call(lambda: sum(
        len(p["CertificateSummaryList"])
        for p in client("acm").get_paginator("list_certificates")
        .paginate(CertificateStatuses=["ISSUED"])
    )))
    add("AWS WAF v2", safe_call(lambda: len(
        client("wafv2").list_web_acls(Scope="REGIONAL")["WebACLs"]
    )))
    add("Amazon GuardDuty", safe_call(lambda: len(
        client("guardduty").list_detectors()["DetectorIds"]
    )))
    add("AWS CloudTrail", safe_call(lambda: len(
        client("cloudtrail").describe_trails()["trailList"]
    )))

    # ---------------- OBSERVABILITY ----------------
    add("CloudWatch Alarms", safe_call(lambda: len(
        client("cloudwatch").describe_alarms()["MetricAlarms"]
    )))

    # ---------------- MESSAGING ----------------
    add("Amazon SNS", safe_call(lambda: len(
        client("sns").list_topics()["Topics"]
    )))
    add("Amazon SQS", safe_call(lambda: len(
        client("sqs").list_queues().get("QueueUrls", [])
    )))

    # ---------------- OTHER ----------------
    add("AWS Glue", safe_call(lambda: len(
        client("glue").get_jobs()["Jobs"]
    )))
    add("AWS Systems Manager", safe_call(lambda: len(
        client("ssm").describe_instance_information()["InstanceInformationList"]
    )))
    add("AWS CloudFormation", safe_call(lambda: len(
        client("cloudformation").describe_stacks()["Stacks"]
    )))

    # ---------------- GLOBAL ----------------
    if region == "us-east-1":
        add("Amazon Route 53", safe_call(lambda: len(
            session.client("route53").list_hosted_zones()["HostedZones"]
        )))

    return rows

# =========================================================
# WRITE EXCEL
# =========================================================
def write_excel(path, rows):
    df = pd.DataFrame(rows, columns=[
        "AWS Account",
        "Region",
        "Region Name",
        "Service",
        "Resource Count",
        "Security Pillar Covered"
    ])
    df.to_excel(path, index=False)

# =========================================================
# MAIN
# =========================================================
def main(profile, output, threads):
    session = get_session(profile)
    account_id = session.client("sts").get_caller_identity()["Account"]

    rows = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [
            ex.submit(worker, session, account_id, region)
            for region in TARGET_REGIONS
        ]
        for f in as_completed(futures):
            with lock:
                rows.extend(f.result())

    outfile = f"{output}_{profile}.xlsx"
    write_excel(outfile, rows)
    logger.info(f"Report generated: {outfile}")

# =========================================================
# ENTRY
# =========================================================
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--profile", "-p", default=DEFAULT_PROFILE)
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    p.add_argument("--threads", "-t", type=int, default=MAX_THREADS)
    a = p.parse_args()
    main(a.profile, a.output, a.threads)
