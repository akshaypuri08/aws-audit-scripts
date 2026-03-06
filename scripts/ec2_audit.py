import os
import boto3
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ---------------- CONFIG ----------------
MAX_THREADS = int(os.getenv("MAX_THREADS", 15))
DEFAULT_PROFILE = os.getenv("AWS_PROFILE", "aqi")
DEFAULT_OUTPUT = os.getenv("DEFAULT_OUTPUT", "ec2_audit_aqi.xlsx")
# ----------------------------------------

# Create boto3 session using profile
session = boto3.Session(profile_name=DEFAULT_PROFILE)

def get_all_regions():
    ec2 = session.client("ec2")
    response = ec2.describe_regions(AllRegions=True)
    return [
        r["RegionName"]
        for r in response["Regions"]
        if r["OptInStatus"] != "not-opted-in"
    ]

def fetch_instances(region):
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_instances")

    instances = []

    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instances.append({
                    "Region": region,
                    "InstanceId": instance.get("InstanceId"),
                    "Name": next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        ""
                    ),
                    "State": instance["State"]["Name"],
                    "InstanceType": instance.get("InstanceType"),
                    "PrivateIP": instance.get("PrivateIpAddress"),
                    "PublicIP": instance.get("PublicIpAddress"),
                    "AZ": instance["Placement"]["AvailabilityZone"],
                    "LaunchTime": instance.get("LaunchTime"),
                })

    return instances

def main():
    print(f"Using AWS profile: {DEFAULT_PROFILE}")
    print(f"Max threads: {MAX_THREADS}")

    regions = get_all_regions()
    print(f"Discovered {len(regions)} regions")

    all_instances = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_map = {executor.submit(fetch_instances, r): r for r in regions}

        for future in as_completed(future_map):
            region = future_map[future]
            try:
                data = future.result()
                all_instances.extend(data)
                print(f"{region}: {len(data)} instances")
            except Exception as e:
                print(f"ERROR in {region}: {e}")

    df = pd.DataFrame(all_instances)

    # ---------- FIX TIMEZONE + AGE ----------
    if not df.empty and "LaunchTime" in df.columns:
        # Ensure UTC and Excel-safe
        df["LaunchTime"] = pd.to_datetime(df["LaunchTime"], utc=True)
        df["LaunchTime"] = df["LaunchTime"].dt.tz_localize(None)

        # Instance age in days
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        df["InstanceAgeDays"] = (now_utc - df["LaunchTime"]).dt.days
    # ----------------------------------------

    running_df = df[df["State"] == "running"]
    stopped_df = df[df["State"] == "stopped"]

    with pd.ExcelWriter(DEFAULT_OUTPUT, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="All Instances", index=False)
        running_df.to_excel(writer, sheet_name="Running Instances", index=False)
        stopped_df.to_excel(writer, sheet_name="Stopped Instances", index=False)

    print("\n✅ EC2 audit completed successfully")
    print(f"Output file: {DEFAULT_OUTPUT}")
    print(f"Total: {len(df)} | Running: {len(running_df)} | Stopped: {len(stopped_df)}")

if __name__ == "__main__":
    main()
