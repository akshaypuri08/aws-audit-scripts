from __future__ import annotations
import argparse
import csv
import datetime
import math
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Configuration
MAX_THREADS = 5
DEFAULT_PROFILE = "sandbox-bcc"
DEFAULT_OUTPUT = "s3_buckets_report.csv"

lock = threading.Lock()


def human_readable_size(num_bytes: int) -> str:
    if num_bytes < 0:
        return "-"
    if num_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = int(math.floor(math.log(num_bytes, 1024)))
    idx = min(idx, len(units) - 1)
    value = num_bytes / (1024 ** idx)
    return f"{value:.2f} {units[idx]}"


def get_s3_session(profile_name: str):
    try:
        session = boto3.Session(profile_name=profile_name)
    except Exception:
        # fallback to default session if profile not found
        session = boto3.Session()
    return session


def list_buckets(s3_client) -> List[Dict]:
    resp = s3_client.list_buckets()
    return resp.get("Buckets", [])


def get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        resp = s3_client.get_bucket_location(Bucket=bucket_name)
        # LocationConstraint may be None for us-east-1
        loc = resp.get("LocationConstraint")
        if loc is None:
            return "us-east-1"
        # For some regions AWS returns strings like 'EU' historically; handle common edge-cases
        return loc
    except ClientError as e:
        return f"error: {e.response.get('Error', {}).get('Message', str(e))}"


def compute_bucket_size(s3_client, bucket_name: str) -> Tuple[int, int]:
    """Return (total_bytes, object_count) for the given bucket by paginating list_objects_v2."""
    paginator = s3_client.get_paginator("list_objects_v2")
    kwargs = {"Bucket": bucket_name}
    total_size = 0
    total_count = 0
    try:
        for page in paginator.paginate(**kwargs):
            contents = page.get("Contents")
            if not contents:
                continue
            for obj in contents:
                total_count += 1
                total_size += int(obj.get("Size", 0))
    except ClientError as e:
        # bubble up as negative sizes to indicate error
        raise
    return total_size, total_count


def worker_process_bucket(s3_client, bucket_meta: Dict) -> Dict:
    name = bucket_meta.get("Name")
    creation = bucket_meta.get("CreationDate")
    creation_str = (
        creation.isoformat() if isinstance(creation, datetime.datetime) else str(creation)
    )
    result = {
        "bucket_name": name,
        "creation_date": creation_str,
        "region": "",
        "object_count": 0,
        "total_size_bytes": 0,
        "total_size_human": "0 B",
        "comments": "",
    }

    try:
        region = get_bucket_region(s3_client, name)
        result["region"] = region
    except Exception as e:
        result["comments"] = f"region_error: {e}"
        return result

    try:
        size, count = compute_bucket_size(s3_client, name)
        result["object_count"] = count
        result["total_size_bytes"] = size
        result["total_size_human"] = human_readable_size(size)
    except ClientError as e:
        err = e.response.get("Error", {}).get("Message", str(e))
        result["comments"] = f"list_error: {err}"
    except BotoCoreError as e:
        result["comments"] = f"boto_error: {str(e)}"
    except Exception as e:
        result["comments"] = f"unknown_error: {str(e)}"

    return result


def write_csv(filename: str, rows: List[Dict]):
    fieldnames = [
        "bucket_name",
        "creation_date",
        "region",
        "object_count",
        "total_size_bytes",
        "total_size_human",
        "comments",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main(profile: str, output: str, max_threads: int):
    session = get_s3_session(profile)
    s3_client = session.client("s3")

    try:
        buckets = list_buckets(s3_client)
    except ClientError as e:
        print(f"Failed to list buckets: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(buckets)} buckets. Processing with max {max_threads} threads...")

    results: List[Dict] = []

    # Use ThreadPoolExecutor for I/O-bound concurrency
    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        futures = {}
        for b in buckets:
            # create a fresh client for each worker to avoid threading issues with botocore
            worker_session = get_s3_session(profile)
            worker_client = worker_session.client("s3")
            fut = ex.submit(worker_process_bucket, worker_client, b)
            futures[fut] = b.get("Name")

        for fut in as_completed(futures):
            bucket_name = futures[fut]
            try:
                res = fut.result()
                print(
                    f"{bucket_name}: {res['object_count']} objects, {res['total_size_human']}"
                )
            except Exception as e:
                res = {
                    "bucket_name": bucket_name,
                    "creation_date": "",
                    "region": "",
                    "object_count": 0,
                    "total_size_bytes": 0,
                    "total_size_human": "0 B",
                    "comments": f"worker_failed: {str(e)}",
                }
                print(f"{bucket_name}: ERROR - {e}")

            # protect append with a lock just in case
            with lock:
                results.append(res)

    # Sort results by bucket name
    results.sort(key=lambda r: r["bucket_name"].lower())

    write_csv(output, results)
    print(f"Written CSV to {output}. Total buckets: {len(results)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export S3 buckets and sizes to CSV")
    parser.add_argument(
        "--profile",
        "-p",
        default=DEFAULT_PROFILE,
        help=f"AWS profile name (default: {DEFAULT_PROFILE})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Output CSV filename (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=MAX_THREADS,
        help=f"Max concurrent threads (default: {MAX_THREADS})",
    )
    args = parser.parse_args()
    main(args.profile, args.output, max(1, args.threads))
