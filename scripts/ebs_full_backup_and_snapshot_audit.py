from __future__ import annotations

import os
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import boto3
import pandas as pd
from botocore.exceptions import ClientError, BotoCoreError

# =========================================================
# CONFIG (ENV OVERRIDES)
# =========================================================
MAX_THREADS = int(os.getenv("MAX_THREADS", 15))
DEFAULT_PROFILE = os.getenv("AWS_PROFILE", "aqi")
DEFAULT_OUTPUT = os.getenv(
    "DEFAULT_OUTPUT",
    "ebs_backup_and_snapshot_audit_aqi.xlsx"
)

# TARGET_REGIONS = {
#     "us-east-1": "N. Virginia",
#     "eu-west-1": "Ireland",
#     "ap-southeast-2": "Sydney",
#     "ca-central-1": "Canada Central",
# }

TARGET_REGIONS = {
    "us-east-1": "N. Virginia",
    "us-west-1": "N. california",
    "eu-west-1": "Ireland",
    "ap-southeast-1": "singapore",
    "ap-southeast-2": "Sydney",
    "ca-central-1": "Canada Central",
}


# =========================================================
# LOGGING
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)
lock = threading.Lock()

# =========================================================
# COMMON HELPERS
# =========================================================
def strip_tz(dt):
    return dt.replace(tzinfo=None) if dt else None


def classify_snapshot(snapshot: dict) -> str:
    tags = {t["Key"]: t["Value"] for t in snapshot.get("Tags", [])}
    if "aws:backup:source-resource" in tags:
        return "AWS Backup"
    if "aws:dlm:lifecycle-policy-id" in tags:
        return "DLM"
    return "Manual"


def volume_exists(ec2, volume_id: str) -> bool:
    try:
        ec2.describe_volumes(VolumeIds=[volume_id])
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidVolume.NotFound":
            return False
        raise

# =========================================================
# SHEET 1 — EBS VOLUME BACKUP AUDIT
# =========================================================
def audit_volumes(session, region, region_name):
    ec2 = session.client("ec2", region_name=region)
    backup = session.client("backup", region_name=region)

    volumes = []
    snapshots = []

    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        volumes.extend(page["Volumes"])

    paginator = ec2.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"]):
        snapshots.extend(page["Snapshots"])

    snap_map = {}
    for s in snapshots:
        snap_map.setdefault(s["VolumeId"], []).append(s)

    results = []

    for vol in volumes:
        vol_id = vol["VolumeId"]
        snaps = snap_map.get(vol_id, [])

        aws_snaps = []
        dlm_snaps = []
        manual_snaps = []

        for s in snaps:
            stype = classify_snapshot(s)
            if stype == "AWS Backup":
                aws_snaps.append(s)
            elif stype == "DLM":
                dlm_snaps.append(s)
            else:
                manual_snaps.append(s)

        all_snaps = snaps
        now = datetime.now(timezone.utc)

        oldest_days = (
            min((now - s["StartTime"]).days for s in all_snaps)
            if all_snaps else "-"
        )
        latest_days = (
            min((now - s["StartTime"]).days for s in all_snaps)
            if all_snaps else "-"
        )

        latest_snapshot_date = (
            strip_tz(max(s["StartTime"] for s in all_snaps))
            if all_snaps else "-"
        )

        # Retention (AWS Backup only)
        retention_days = "-"
        if aws_snaps:
            try:
                plans = backup.list_backup_plans()["BackupPlansList"]
                if plans:
                    plan = backup.get_backup_plan(
                        BackupPlanId=plans[0]["BackupPlanId"]
                    )
                    rule = plan["BackupPlan"]["Rules"][0]
                    retention_days = rule["Lifecycle"].get("DeleteAfterDays", "-")
            except Exception:
                retention_days = "-"

        attachment = vol.get("Attachments", [])
        attached = "YES" if attachment else "NO"
        resource_type = "EC2" if attachment else "-"
        resource_id = attachment[0]["InstanceId"] if attachment else "-"

        results.append({
            "Region": region,
            "RegionName": region_name,
            "VolumeId": vol_id,
            "State": vol["State"],
            "SizeGiB": vol["Size"],
            "VolumeType": vol["VolumeType"],
            "Encrypted": vol["Encrypted"],
            "AttachedToResource": attached,
            "ResourceType": resource_type,
            "ResourceId": resource_id,

            "HasAnyBackup": "YES" if all_snaps else "NO",
            "HasAWSBackup": "YES" if aws_snaps else "NO",
            "HasDLMBackup": "YES" if dlm_snaps else "NO",
            "HasManualSnapshot": "YES" if manual_snaps else "NO",

            "RetentionDays": retention_days,
            "AutomaticSnapshotCount": len(aws_snaps) + len(dlm_snaps),
            "ManualSnapshotCount": len(manual_snaps),
            "TotalSnapshots": len(all_snaps),
            "OldestBackupDays": oldest_days,
            "LatestBackupDays": latest_days,
            "LatestSnapshotDate": latest_snapshot_date,
        })

    return results

# =========================================================
# SHEET 2 — ORPHANED SNAPSHOT AUDIT
# =========================================================
def audit_snapshots(session, region, region_name):
    ec2 = session.client("ec2", region_name=region)
    results = []

    paginator = ec2.get_paginator("describe_snapshots")
    snapshots = []
    for page in paginator.paginate(OwnerIds=["self"]):
        snapshots.extend(page["Snapshots"])

    def worker(snapshot):
        try:
            vol_id = snapshot.get("VolumeId")
            exists = volume_exists(ec2, vol_id) if vol_id else False
            age_days = (datetime.now(timezone.utc) - snapshot["StartTime"]).days

            return {
                "Region": region,
                "RegionName": region_name,
                "SnapshotId": snapshot["SnapshotId"],
                "VolumeId": vol_id or "-",
                "VolumeExists": "YES" if exists else "NO",
                "OrphanedSnapshot": "NO" if exists else "YES",
                "SnapshotType": classify_snapshot(snapshot),
                "SnapshotAgeDays": age_days,
                "StartTime": strip_tz(snapshot["StartTime"]),
                "SizeGiB": snapshot["VolumeSize"],
                "Encrypted": snapshot["Encrypted"],
                "State": snapshot["State"],
            }
        except Exception as e:
            logger.error(f"[{region}] Snapshot error: {e}")
            return None

    with ThreadPoolExecutor(MAX_THREADS) as exe:
        for f in as_completed([exe.submit(worker, s) for s in snapshots]):
            r = f.result()
            if r:
                results.append(r)

    return results

# =========================================================
# MAIN
# =========================================================
def main():
    logger.info(f"Starting combined EBS audit using profile [{DEFAULT_PROFILE}]")
    session = boto3.Session(profile_name=DEFAULT_PROFILE)

    volume_rows = []
    snapshot_rows = []

    for region, region_name in TARGET_REGIONS.items():
        logger.info(f"Processing region: {region}")
        volume_rows.extend(audit_volumes(session, region, region_name))
        snapshot_rows.extend(audit_snapshots(session, region, region_name))

    df_vol = pd.DataFrame(volume_rows)
    df_snap = pd.DataFrame(snapshot_rows)

    with pd.ExcelWriter(DEFAULT_OUTPUT, engine="xlsxwriter") as writer:
        df_vol.to_excel(writer, sheet_name="EBS_Volume_Backup_Audit", index=False)
        df_snap.to_excel(writer, sheet_name="Orphaned_EBS_Snapshots", index=False)

    logger.info(f"Excel report generated: {DEFAULT_OUTPUT}")


if __name__ == "__main__":
    main()
