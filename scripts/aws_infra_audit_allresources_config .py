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
# SESSION
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
    except (ClientError, BotoCoreError, EndpointConnectionError):
        return default
    except Exception as e:
        logger.error(f"AWS Error: {e}")
        return default

# =========================================================
# SERVICE AVAILABILITY CHECK
# =========================================================
def service_available(fn):
    try:
        fn()
        return True
    except EndpointConnectionError:
        return False
    except Exception:
        return True

# =========================================================
# REGIONS
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

    # -------------------- COMPUTE / NETWORK --------------------
    ec2_cnt = safe_call(lambda: sum(
        len(r["Instances"]) for r in client("ec2").describe_instances()["Reservations"]
    ))
    if ec2_cnt > 0:
        results.append([account_id, region, "EC2 Instances", ec2_cnt])

    vpc_cnt = safe_call(lambda: len(client("ec2").describe_vpcs()["Vpcs"]))
    if vpc_cnt > 0:
        results.append([account_id, region, "VPCs", vpc_cnt])

    elb_cnt = safe_call(lambda: len(client("elbv2").describe_load_balancers()["LoadBalancers"]))
    if elb_cnt > 0:
        results.append([account_id, region, "Load Balancers", elb_cnt])

    # -------------------- SERVERLESS / CONTAINERS --------------------
    lambda_cnt = safe_call(lambda: len(client("lambda").list_functions()["Functions"]))
    if lambda_cnt > 0:
        results.append([account_id, region, "Lambda Functions", lambda_cnt])

    ecs_cnt = safe_call(lambda: len(client("ecs").list_clusters()["clusterArns"]))
    if ecs_cnt > 0:
        results.append([account_id, region, "ECS Clusters", ecs_cnt])

    ecr_cnt = safe_call(lambda: len(client("ecr").describe_repositories()["repositories"]))
    if ecr_cnt > 0:
        results.append([account_id, region, "ECR Repositories", ecr_cnt])

    # -------------------- STORAGE --------------------
    if region == "us-east-1":
        s3_cnt = safe_call(lambda: len(session.client("s3").list_buckets()["Buckets"]))
        if s3_cnt > 0:
            results.append([account_id, region, "S3 Buckets", s3_cnt])

    # -------------------- DATABASES --------------------
    rds_cnt = safe_call(lambda: len(client("rds").describe_db_instances()["DBInstances"]))
    if rds_cnt > 0:
        results.append([account_id, region, "RDS Instances", rds_cnt])

    # RDS Snapshots
    rds_snap_cnt = safe_call(lambda: len(client("rds").describe_db_snapshots()["DBSnapshots"]))
    if rds_snap_cnt > 0:
        results.append([account_id, region, "RDS Snapshots", rds_snap_cnt])

    aurora_snap_cnt = safe_call(lambda: len(
        client("rds").describe_db_cluster_snapshots()["DBClusterSnapshots"]
    ))
    if aurora_snap_cnt > 0:
        results.append([account_id, region, "RDS Cluster Snapshots", aurora_snap_cnt])

    # -------------------- AWS BACKUP --------------------
    if service_available(lambda: client("backup")):
        vault_cnt = safe_call(lambda: len(
            client("backup").list_backup_vaults()["BackupVaultList"]
        ))
        if vault_cnt > 0:
            results.append([account_id, region, "Backup Vaults", vault_cnt])

        try:
            total_rp = 0
            vaults = client("backup").list_backup_vaults()["BackupVaultList"]
            for v in vaults:
                rp = safe_call(lambda: len(
                    client("backup").list_recovery_points_by_backup_vault(
                        BackupVaultName=v["BackupVaultName"]
                    )["RecoveryPoints"]
                ))
                total_rp += rp
            if total_rp > 0:
                results.append([account_id, region, "Backup Recovery Points", total_rp])
        except Exception:
            pass

    # -------------------- SECURITY --------------------
    kms_cnt = safe_call(lambda: len(client("kms").list_keys()["Keys"]))
    if kms_cnt > 0:
        results.append([account_id, region, "KMS Keys", kms_cnt])

    secrets_cnt = safe_call(lambda: len(client("secretsmanager").list_secrets()["SecretList"]))
    if secrets_cnt > 0:
        results.append([account_id, region, "Secrets Manager Secrets", secrets_cnt])

    # ACM ACTIVE ONLY
    def active_acm():
        paginator = client("acm").get_paginator("list_certificates")
        certs = []
        for p in paginator.paginate(CertificateStatuses=["ISSUED"]):
            certs.extend(p["CertificateSummaryList"])
        return len(certs)

    acm_cnt = safe_call(active_acm)
    if acm_cnt > 0:
        results.append([account_id, region, "ACM Active Certificates", acm_cnt])

    # -------------------- GLOBAL SERVICES --------------------
    if region == "us-east-1":
        r53_cnt = safe_call(lambda: len(
            session.client("route53").list_hosted_zones()["HostedZones"]
        ))
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
    account_id = session.client("sts").get_caller_identity()["Account"]

    outfile = f"{output}_{profile}.xlsx"
    regions = list_regions(session)

    all_rows = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, session, account_id, r): r for r in regions}
        for f in as_completed(futures):
            try:
                rows = f.result()
                with lock:
                    all_rows.extend(rows)
                logger.info(f"{futures[f]} done")
            except Exception as e:
                logger.error(f"worker_failed:{e}")

    write_excel(outfile, all_rows)
    logger.info(f"Excel written: {outfile}")

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
