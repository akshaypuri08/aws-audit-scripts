from __future__ import annotations

import boto3
import pandas as pd
import os
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# =============================
# CONFIG
# =============================
MAX_THREADS = int(os.getenv("MAX_THREADS", 15))
DEFAULT_PROFILE = os.getenv("DEFAULT_PROFILE", "linko")
DEFAULT_OUTPUT = os.getenv("DEFAULT_OUTPUT", "ebs-backup-audit-linko.xlsx")

TARGET_REGIONS = {
    "us-east-1": "N. Virginia",
    "eu-west-1": "Ireland",
    "ap-southeast-2": "Sydney",
    "ca-central-1": "Canada Central",
}

lock = threading.Lock()

# =============================
# LOGGING
# =============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
)
logger = logging.getLogger(__name__)

# =============================
# HELPERS
# =============================
def aws_session(profile, region):
    return boto3.Session(profile_name=profile, region_name=region)


def to_naive(dt):
    if isinstance(dt, datetime) and dt.tzinfo:
        return dt.replace(tzinfo=None)
    return dt


def days_ago(dt):
    return (datetime.now(timezone.utc) - dt).days if dt else ""


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# =============================
# SNAPSHOTS
# =============================
def get_snapshots(ec2, volume_id):
    snaps = []
    paginator = ec2.get_paginator("describe_snapshots")

    for page in paginator.paginate(
        OwnerIds=["self"],
        Filters=[{"Name": "volume-id", "Values": [volume_id]}],
    ):
        snaps.extend(page["Snapshots"])

    return snaps


def classify_snapshots(snaps):
    aws_backup, dlm, manual = [], [], []

    for s in snaps:
        tags = {t["Key"]: t["Value"] for t in s.get("Tags", [])}

        if "aws:backup:source-resource" in tags:
            aws_backup.append(s)
        elif "aws:dlm:lifecycle-policy-id" in tags:
            dlm.append(s)
        else:
            manual.append(s)

    return aws_backup, dlm, manual


# =============================
# AWS BACKUP RETENTION (FIXED)
# =============================
def get_aws_backup_retention(session, region, volume_arn):
    backup = session.client("backup", region)

    try:
        protected = backup.list_protected_resources()["Results"]

        for res in protected:
            if res["ResourceArn"] == volume_arn:
                plan_id = res["BackupPlanId"]
                plan = backup.get_backup_plan(BackupPlanId=plan_id)
                rules = plan["BackupPlan"]["Rules"]

                if rules:
                    lifecycle = rules[0].get("Lifecycle", {})
                    return lifecycle.get("DeleteAfterDays", "-")

        return "-"
    except Exception as e:
        logger.warning(f"[{region}] AWS Backup retention lookup failed: {e}")
        return "-"


# =============================
# DLM RETENTION
# =============================
def get_dlm_retention(session, region, policy_id):
    dlm = session.client("dlm", region)
    try:
        policy = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]
        schedules = policy["PolicyDetails"]["Schedules"]
        return schedules[0]["RetainRule"].get("Count", "-")
    except Exception:
        return "-"


# =============================
# PROCESS REGION
# =============================
def process_region(region, profile):
    rows = []

    try:
        sess = aws_session(profile, region)
        ec2 = sess.client("ec2")
        account_id = get_account_id(sess)

        volumes = ec2.describe_volumes()["Volumes"]
        logger.info(f"[{region}] Found {len(volumes)} volumes")

        for volume in volumes:
            volume_id = volume["VolumeId"]
            volume_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}"

            attachments = volume.get("Attachments", [])
            attached = "Yes" if attachments else "No"
            resource_type = "EC2" if attachments else ""
            resource_name = attachments[0]["InstanceId"] if attachments else ""

            snaps = get_snapshots(ec2, volume_id)
            aws_backup_snaps, dlm_snaps, manual_snaps = classify_snapshots(snaps)

            automatic_count = len(aws_backup_snaps) + len(dlm_snaps)
            manual_count = len(manual_snaps)
            total_count = automatic_count + manual_count

            latest_snapshot = max(snaps, key=lambda x: x["StartTime"], default=None)
            oldest_snapshot = min(snaps, key=lambda x: x["StartTime"], default=None)

            retention_days = "-"
            if aws_backup_snaps:
                retention_days = get_aws_backup_retention(sess, region, volume_arn)
            elif dlm_snaps:
                tags = {t["Key"]: t["Value"] for t in dlm_snaps[0].get("Tags", [])}
                retention_days = get_dlm_retention(
                    sess, region, tags.get("aws:dlm:lifecycle-policy-id")
                )

            rows.append(
                {
                    "Region": region,
                    "VolumeId": volume_id,
                    "State": volume["State"],
                    "SizeGiB": volume["Size"],
                    "VolumeType": volume["VolumeType"],
                    "Encrypted": volume["Encrypted"],

                    "Attached": attached,
                    "ResourceType": resource_type,
                    "ResourceName": resource_name,

                    "HasAnyBackup": "YES" if total_count > 0 else "NO",
                    "HasAWSBackup": "YES" if aws_backup_snaps else "NO",
                    "HasDLMBackup": "YES" if dlm_snaps else "NO",
                    "HasManualSnapshot": "YES" if manual_snaps else "NO",

                    "AutomaticSnapshotCount": automatic_count,
                    "ManualSnapshotCount": manual_count,
                    "TotalSnapshots": total_count,

                    "RetentionDays": retention_days,
                    "OldestBackupDays": days_ago(oldest_snapshot["StartTime"]) if oldest_snapshot else "",
                    "LatestBackupDays": days_ago(latest_snapshot["StartTime"]) if latest_snapshot else "",
                    "LatestSnapshotDate": to_naive(latest_snapshot["StartTime"]) if latest_snapshot else "",
                }
            )

    except Exception as e:
        logger.exception(f"[{region}] Error processing region: {e}")

    return rows


# =============================
# MAIN
# =============================
def run_audit():
    logger.info(f"Starting EBS backup audit using profile [{DEFAULT_PROFILE}]")
    all_rows = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(process_region, r, DEFAULT_PROFILE): r
            for r in TARGET_REGIONS
        }

        for future in as_completed(futures):
            with lock:
                all_rows.extend(future.result())

    return all_rows


# =============================
# EXCEL OUTPUT
# =============================
def write_excel(rows):
    df = pd.DataFrame(rows)
    with pd.ExcelWriter(DEFAULT_OUTPUT, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="EBS_Backup_Audit", index=False)
    logger.info(f"Report written to {DEFAULT_OUTPUT}")


# =============================
# ENTRYPOINT
# =============================
if __name__ == "__main__":
    try:
        data = run_audit()
        write_excel(data)
        logger.info("EBS backup audit completed successfully")
    except Exception as e:
        logger.exception(f"Fatal error during audit: {e}")
