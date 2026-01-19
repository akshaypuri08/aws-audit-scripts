from __future__ import annotations              

import argparse
import csv
import math
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import logging

import boto3
from botocore.exceptions import ClientError

MAX_THREADS = 15
DEFAULT_PROFILE = "gaia-dev"
DEFAULT_OUTPUT = "s3_buckets_report-gaia-dev.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

lock = threading.Lock()


# -------------------- helpers --------------------

def human_readable_size(num_bytes: int) -> str:
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = min(int(math.log(num_bytes, 1024)), len(units) - 1)
    return f"{num_bytes / (1024 ** idx):.2f} {units[idx]}"


def get_s3_session(profile: str):
    try:
        return boto3.Session(profile_name=profile)
    except Exception:
        return boto3.Session()


def load_bucket_names(path: str) -> List[str]:
    """Load bucket names from a text file (one per line)."""
    with open(path, "r", encoding="utf-8") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


# -------------------- bucket checks --------------------

def get_bucket_region(c, bucket):
    try:
        r = c.get_bucket_location(Bucket=bucket)
        return r.get("LocationConstraint") or "us-east-1"
    except Exception as e:
        return f"error: {e}"


def get_lifecycle(c, bucket):
    try:
        c.get_bucket_lifecycle_configuration(Bucket=bucket)
        return "true"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
            return "false"
        return f"error: {e}"


def get_versioning(c, bucket):
    try:
        v = c.get_bucket_versioning(Bucket=bucket)
        return v.get("Status", "Disabled")
    except Exception as e:
        return f"error: {e}"


def get_encryption(c, bucket):
    try:
        e = c.get_bucket_encryption(Bucket=bucket)
        rules = e["ServerSideEncryptionConfiguration"]["Rules"]
        return rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return "None"
        return f"error: {e}"


def get_public_access(c, bucket):
    try:
        p = c.get_public_access_block(Bucket=bucket)
        cfg = p["PublicAccessBlockConfiguration"]
        return ";".join(f"{k}:{v}" for k, v in cfg.items())
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return "None"
        return f"error: {e}"


def compute_storage_breakdown(c, bucket):
    paginator = c.get_paginator("list_objects_v2")
    breakdown = {}
    total = 0
    count = 0

    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            sc = obj.get("StorageClass", "STANDARD")
            size = obj.get("Size", 0)
            breakdown[sc] = breakdown.get(sc, 0) + size
            total += size
            count += 1

    return total, count, breakdown


# -------------------- worker --------------------

def worker(c, meta):
    bucket = meta["Name"]
    created = meta["CreationDate"].isoformat()

    r = {
        "bucket_name": bucket,
        "creation_date": created,
        "region": "",
        "object_count": 0,
        "total_size_bytes": 0,
        "total_size_human": "0 B",
        "lifecycle": "",
        "versioning": "",
        "encryption": "",
        "public_access": "",
        "storage_classes": "",
        "comments": "",
    }

    try:
        r["region"] = get_bucket_region(c, bucket)
        r["lifecycle"] = get_lifecycle(c, bucket)
        r["versioning"] = get_versioning(c, bucket)
        r["encryption"] = get_encryption(c, bucket)
        r["public_access"] = get_public_access(c, bucket)

        total, count, breakdown = compute_storage_breakdown(c, bucket)
        r["object_count"] = count
        r["total_size_bytes"] = total
        r["total_size_human"] = human_readable_size(total)
        r["storage_classes"] = ";".join(
            f"{k}:{human_readable_size(v)}" for k, v in breakdown.items()
        )

    except Exception as e:
        r["comments"] = f"error:{e}"

    return r


# -------------------- output --------------------

def write_csv(path, rows):
    fields = [
        "bucket_name",
        "creation_date",
        "region",
        "object_count",
        "total_size_bytes",
        "total_size_human",
        "lifecycle",
        "versioning",
        "encryption",
        "public_access",
        "storage_classes",
        "comments",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for x in rows:
            w.writerow(x)


# -------------------- main --------------------

def main(profile, output, threads, buckets_file=None):
    session = get_s3_session(profile)
    c = session.client("s3")

    try:
        all_buckets = c.list_buckets().get("Buckets", [])
    except Exception as e:
        logger.error(f"Cannot list buckets: {e}")
        sys.exit(1)

    if buckets_file:
        wanted = set(load_bucket_names(buckets_file))
        buckets = [b for b in all_buckets if b["Name"] in wanted]

        missing = wanted - {b["Name"] for b in buckets}
        if missing:
            logger.warning(f"Buckets not found: {', '.join(missing)}")
    else:
        buckets = all_buckets

    if not buckets:
        logger.error("No buckets to process")
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {}
        for b in buckets:
            wc = get_s3_session(profile).client("s3")
            futures[ex.submit(worker, wc, b)] = b["Name"]

        for f in as_completed(futures):
            name = futures[f]
            try:
                res = f.result()
                logger.info(f"{name} done")
            except Exception as e:
                res = {"bucket_name": name, "comments": f"worker_failed:{e}"}
            with lock:
                results.append(res)

    results.sort(key=lambda x: x["bucket_name"])
    write_csv(output, results)
    logger.info(f"CSV written: {output}")


# -------------------- cli --------------------

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--profile", "-p", default=DEFAULT_PROFILE)
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    p.add_argument("--threads", "-t", type=int, default=MAX_THREADS)
    p.add_argument(
        "--buckets-file",
        "-b",
        help="Text file containing bucket names (one per line)",
    )

    a = p.parse_args()
    main(a.profile, a.output, a.threads, a.buckets_file)
