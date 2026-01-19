from __future__ import annotations
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

import boto3
from botocore.exceptions import ClientError, BotoCoreError
import pandas as pd


# =========================================================
# CONFIG
# =========================================================
MAX_THREADS = 15
DEFAULT_PROFILE = "aqcn"
DEFAULT_OUTPUT = "aws_infra_audit"
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
# SESSION CREATION
# =========================================================
def get_session(profile: str):
    try:
        return boto3.Session(profile_name=profile)
    except Exception:
        return boto3.Session()


# =========================================================
# SAFE CALL
# =========================================================
def safe_call(func, default=0):
    try:
        return func()
    except Exception as e:
        logger.error(f"AWS Error: {e}")
        return default


# =========================================================
# LIST REGIONS
# =========================================================
def list_regions(session):
    try:
        ec2 = session.client("ec2")
        return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    except Exception as e:
        logger.error(f"Failed to list regions: {e}")
        sys.exit(1)


# =========================================================
# REGION WORKER
# =========================================================
def worker(session, account_id, region):
    logger.info(f"Scanning {region} ...")

    def client(svc):
        return session.client(svc, region_name=region)

    results = []

    # -----------------------------------------------------
    # COMPUTE / NETWORKING
    # -----------------------------------------------------
    ec2_cnt = safe_call(lambda:
        sum(len(r["Instances"]) for r in client("ec2").describe_instances()["Reservations"])
    )
    if ec2_cnt > 0:
        results.append([account_id, region, "EC2 Instances", ec2_cnt])

    vpc_cnt = safe_call(lambda:
        len(client("ec2").describe_vpcs()["Vpcs"])
    )
    if vpc_cnt > 0:
        results.append([account_id, region, "VPCs", vpc_cnt])

    elb_cnt = safe_call(lambda:
        len(client("elbv2").describe_load_balancers().get("LoadBalancers", []))
    )
    if elb_cnt > 0:
        results.append([account_id, region, "Load Balancers", elb_cnt])

    # -----------------------------------------------------
    # SERVERLESS / CONTAINERS
    # -----------------------------------------------------
    lambda_cnt = safe_call(lambda:
        len(client("lambda").list_functions().get("Functions", []))
    )
    if lambda_cnt > 0:
        results.append([account_id, region, "Lambda Functions", lambda_cnt])

    ecs_cnt = safe_call(lambda:
        len(client("ecs").list_clusters().get("clusterArns", []))
    )
    if ecs_cnt > 0:
        results.append([account_id, region, "ECS Clusters", ecs_cnt])

    ecr_cnt = safe_call(lambda:
        len(client("ecr").describe_repositories().get("repositories", []))
    )
    if ecr_cnt > 0:
        results.append([account_id, region, "ECR Repositories", ecr_cnt])

    # -----------------------------------------------------
    # STORAGE
    # -----------------------------------------------------
    if region == "us-east-1":
        s3_cnt = safe_call(lambda:
            len(session.client("s3").list_buckets().get("Buckets", []))
        )
        if s3_cnt > 0:
            results.append([account_id, region, "S3 Buckets", s3_cnt])

    # -----------------------------------------------------
    # DATABASES
    # -----------------------------------------------------
    rds_cnt = safe_call(lambda:
        len(client("rds").describe_db_instances().get("DBInstances", []))
    )
    if rds_cnt > 0:
        results.append([account_id, region, "RDS Instances", rds_cnt])

    neptune_cnt = safe_call(lambda:
        len(client("neptune").describe_db_clusters().get("DBClusters", []))
    )
    if neptune_cnt > 0:
        results.append([account_id, region, "Neptune Clusters", neptune_cnt])

    elasticache_cnt = safe_call(lambda:
        len(client("elasticache").describe_cache_clusters().get("CacheClusters", []))
    )
    if elasticache_cnt > 0:
        results.append([account_id, region, "ElastiCache Clusters", elasticache_cnt])

    # -----------------------------------------------------
    # ANALYTICS
    # -----------------------------------------------------
    glue_cnt = safe_call(lambda:
        len(client("glue").get_databases().get("DatabaseList", []))
    )
    if glue_cnt > 0:
        results.append([account_id, region, "Glue Databases", glue_cnt])

    # -----------------------------------------------------
    # NOTIFICATION / MESSAGING
    # -----------------------------------------------------
    sns_cnt = safe_call(lambda:
        len(client("sns").list_topics().get("Topics", []))
    )
    if sns_cnt > 0:
        results.append([account_id, region, "SNS Topics", sns_cnt])

    sqs_cnt = safe_call(lambda:
        len(client("sqs").list_queues().get("QueueUrls", []))
    )
    if sqs_cnt > 0:
        results.append([account_id, region, "SQS Queues", sqs_cnt])

    ses_cnt = safe_call(lambda:
        len(client("ses").list_identities().get("Identities", []))
    )
    if ses_cnt > 0:
        results.append([account_id, region, "SES Identities", ses_cnt])

    # -----------------------------------------------------
    # SECURITY
    # -----------------------------------------------------
    kms_cnt = safe_call(lambda:
        len(client("kms").list_keys().get("Keys", []))
    )
    if kms_cnt > 0:
        results.append([account_id, region, "KMS Keys", kms_cnt])

    secrets_cnt = safe_call(lambda:
        len(client("secretsmanager").list_secrets().get("SecretList", []))
    )
    if secrets_cnt > 0:
        results.append([account_id, region, "Secrets Manager Secrets", secrets_cnt])

    waf_cnt = safe_call(lambda:
        len(client("wafv2").list_web_acls(Scope="REGIONAL").get("WebACLs", []))
    )
    if waf_cnt > 0:
        results.append([account_id, region, "WAF WebACLs", waf_cnt])

    # GuardDuty
    try:
        dets = client("guardduty").list_detectors().get("DetectorIds", [])
        if dets:
            results.append([account_id, region, "GuardDuty Detectors", len(dets)])
    except:
        pass

    # CloudTrail
    ct_cnt = safe_call(lambda:
        len(client("cloudtrail").describe_trails().get("trailList", []))
    )
    if ct_cnt > 0:
        results.append([account_id, region, "CloudTrails", ct_cnt])

    # -----------------------------------------------------
    # ACTIVE ACM CERTIFICATES
    # -----------------------------------------------------
    def list_active_acm():
        certs = []
        paginator = client("acm").get_paginator("list_certificates")
        for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
            certs.extend(page.get("CertificateSummaryList", []))
        return len(certs)

    acm_cnt = safe_call(list_active_acm)
    if acm_cnt > 0:
        results.append([account_id, region, "ACM Active Certificates", acm_cnt])

    # -----------------------------------------------------
    # MANAGEMENT / OPERATIONS
    # -----------------------------------------------------
    ssm_cnt = safe_call(lambda:
        len(client("ssm").describe_instance_information().get("InstanceInformationList", []))
    )
    if ssm_cnt > 0:
        results.append([account_id, region, "SSM Managed Instances", ssm_cnt])

    # AWS Elastic Disaster Recovery
    try:
        drs_cnt = len(client("drs").describe_source_servers().get("items", []))
        if drs_cnt > 0:
            results.append([account_id, region, "DRS Source Servers", drs_cnt])
    except:
        pass

    # -----------------------------------------------------
    # PINPOINT / LOCATION SERVICE
    # -----------------------------------------------------
    loc_cnt = safe_call(lambda:
        len(client("location").list_maps().get("Entries", []))
    )
    if loc_cnt > 0:
        results.append([account_id, region, "Location Service Maps", loc_cnt])

    pinpoint_cnt = safe_call(lambda:
        len(client("pinpoint").get_apps().get("ApplicationsResponse", {}).get("Item", []))
    )
    if pinpoint_cnt > 0:
        results.append([account_id, region, "Pinpoint Apps", pinpoint_cnt])

    # -----------------------------------------------------
    # ROUTE 53 (GLOBAL)
    # -----------------------------------------------------
    if region == "us-east-1":
        r53_cnt = safe_call(lambda:
            len(session.client("route53").list_hosted_zones()["HostedZones"])
        )
        if r53_cnt > 0:
            results.append([account_id, region, "Route53 Hosted Zones", r53_cnt])

    return results


# =========================================================
# WRITE EXCEL
# =========================================================
def write_excel(path, rows):
    df = pd.DataFrame(rows, columns=[
        "AWS Account", "Region", "Resource Type", "Count"
    ])
    df.to_excel(path, index=False)


# =========================================================
# MAIN
# =========================================================
def main(profile, output, threads):
    session = get_session(profile)

    sts = session.client("sts")
    account_id = sts.get_caller_identity().get("Account")

    if output.endswith(".xlsx"):
        outfile = output.replace(".xlsx", f"_{profile}.xlsx")
    else:
        outfile = f"{output}_{profile}.xlsx"

    regions = list_regions(session)
    all_rows = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {
            ex.submit(worker, session, account_id, region): region
            for region in regions
        }

        for f in as_completed(futs):
            region = futs[f]
            try:
                rows = f.result()
                with lock:
                    all_rows.extend(rows)
                logger.info(f"{region} done")
            except Exception as e:
                logger.error(f"worker_failed:{region}:{e}")

    write_excel(outfile, all_rows)
    logger.info(f"Excel written: {outfile}")


# =========================================================
# ENTRY POINT
# =========================================================
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument("--profile", "-p", default=DEFAULT_PROFILE)
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    p.add_argument("--threads", "-t", type=int, default=MAX_THREADS)
    a = p.parse_args()
    main(a.profile, a.output, a.threads)
