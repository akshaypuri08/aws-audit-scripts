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
# CONFIG
# =========================================================
MAX_THREADS = int(os.getenv("MAX_THREADS", 15))
DEFAULT_PROFILE = os.getenv("AWS_PROFILE", "watertrax")
DEFAULT_OUTPUT = os.getenv(
    "DEFAULT_OUTPUT",
    "orphaned_ebs_snapshots_watertrax.xlsx"
)

TARGET_REGIONS = {
    "us-east-1": "N. Virginia",
    "eu-west-1": "Ireland",
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
# HELPERS
# =========================================================
def snapshot_type(snapshot: dict) -> str:
    tags = {t["Key"]: t["Value"] for t in snapshot.get("Tags", [])}

    if "aws:backup:source-resource" in tags:
        return "AWS Backup"
    if "aws:dlm:lifecycle-policy-id" in tags:
        return "DLM"
    return "Manual"


def volume_exists(ec2_client, volume_id: str) -> bool:
    try:
        ec2_client.describe_volumes(VolumeIds=[volume_id])
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidVolume.NotFound":
            return False
        raise


def process_snapshot(ec2_client, snapshot: dict, region: str, region_name: str) -> dict | None:
    try:
        volume_id = snapshot.get("VolumeId")
        snap_time = snapshot["StartTime"]

        exists = volume_exists(ec2_client, volume_id) if volume_id else False

        age_days = (datetime.now(timezone.utc) - snap_time).days

        return {
            "Region": region,
            "RegionName": region_name,
            "SnapshotId": snapshot["SnapshotId"],
            "VolumeId": volume_id or "-",
            "VolumeExists": "YES" if exists else "NO",
            "OrphanedSnapshot": "NO" if exists else "YES",
            "SnapshotType": snapshot_type(snapshot),
            "StartTime": snap_time.replace(tzinfo=None),
            "SnapshotAgeDays": age_days,
            "State": snapshot["State"],
            "Encrypted": snapshot["Encrypted"],
            "SizeGiB": snapshot["VolumeSize"],
            "Description": snapshot.get("Description", ""),
        }

    except (ClientError, BotoCoreError, Exception) as e:
        logger.error(
            f"[{region}] Failed processing snapshot {snapshot.get('SnapshotId')}: {e}"
        )
        return None


# =========================================================
# MAIN
# =========================================================
def main():
    logger.info(f"Starting orphaned EBS snapshot audit using profile [{DEFAULT_PROFILE}]")

    session = boto3.Session(profile_name=DEFAULT_PROFILE)

    all_results = []

    for region, region_name in TARGET_REGIONS.items():
        logger.info(f"Processing region: {region} ({region_name})")

        ec2 = session.client("ec2", region_name=region)
        snapshots = []

        try:
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                snapshots.extend(page["Snapshots"])
        except ClientError as e:
            logger.error(f"[{region}] Failed to list snapshots: {e}")
            continue

        logger.info(f"[{region}] Total snapshots discovered: {len(snapshots)}")

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [
                executor.submit(process_snapshot, ec2, s, region, region_name)
                for s in snapshots
            ]

            for future in as_completed(futures):
                record = future.result()
                if record:
                    with lock:
                        all_results.append(record)

    if not all_results:
        logger.warning("No snapshot data collected")
        return

    df = pd.DataFrame(all_results)

    # Sort for audit readability
    df.sort_values(
        by=["Region", "OrphanedSnapshot", "SnapshotType", "SnapshotAgeDays"],
        ascending=[True, False, True, False],
        inplace=True,
    )

    # Summary
    summary = pd.DataFrame(
        {
            "Metric": [
                "TotalSnapshots",
                "OrphanedSnapshots",
                "ManualSnapshots",
                "AWSBackupSnapshots",
                "DLMSnapshots",
            ],
            "Value": [
                len(df),
                len(df[df["OrphanedSnapshot"] == "YES"]),
                len(df[df["SnapshotType"] == "Manual"]),
                len(df[df["SnapshotType"] == "AWS Backup"]),
                len(df[df["SnapshotType"] == "DLM"]),
            ],
        }
    )

    with pd.ExcelWriter(DEFAULT_OUTPUT, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Snapshots")
        summary.to_excel(writer, index=False, sheet_name="Summary")

    logger.info(f"Report generated successfully: {DEFAULT_OUTPUT}")


if __name__ == "__main__":
    main()
