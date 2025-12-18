from __future__ import annotations
import argparse
import csv
import datetime
import math
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple
import logging

import boto3
from botocore.exceptions import ClientError, BotoCoreError

MAX_THREADS = 15
DEFAULT_PROFILE = "awsgov"
DEFAULT_OUTPUT = "s3_buckets_reportawsgov.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

lock = threading.Lock()

def human_readable_size(num_bytes: int) -> str:
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = min(int(math.log(num_bytes, 1024)), len(units) - 1)
    return f"{num_bytes / (1024**idx):.2f} {units[idx]}"

def get_s3_session(profile: str):
    try:
        return boto3.Session(profile_name=profile)
    except Exception:
        return boto3.Session()

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
        if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
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
        rules = e['ServerSideEncryptionConfiguration']['Rules']
        algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        return algo
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return "None"
        return f"error: {e}"

def get_public_access(c, bucket):
    try:
        p = c.get_public_access_block(Bucket=bucket)
        cfg = p['PublicAccessBlockConfiguration']
        return ";".join(f"{k}:{v}" for k, v in cfg.items())
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return "None"
        return f"error: {e}"

def compute_storage_breakdown(c, bucket):
    paginator = c.get_paginator("list_objects_v2")
    breakdown = {}
    total = 0
    count = 0
    try:
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []) :
                sc = obj.get("StorageClass", "STANDARD")
                breakdown.setdefault(sc, 0)
                breakdown[sc] += obj.get("Size", 0)
                total += obj.get("Size", 0)
                count += 1
    except Exception as e:
        raise
    return total, count, breakdown

def worker(c, meta):
    bucket = meta['Name']
    created = meta['CreationDate'].isoformat()

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

    try: r["region"] = get_bucket_region(c, bucket)
    except Exception as e: r["comments"] = f"region_error:{e}"; return r

    try: r["lifecycle"] = get_lifecycle(c, bucket)
    except Exception as e: r["comments"] = f"lifecycle_error:{e}";

    try: r["versioning"] = get_versioning(c, bucket)
    except Exception as e: r["comments"] = f"versioning_error:{e}";

    try: r["encryption"] = get_encryption(c, bucket)
    except Exception as e: r["comments"] = f"enc_error:{e}";

    try: r["public_access"] = get_public_access(c, bucket)
    except Exception as e: r["comments"] = f"public_access_error:{e}";

    try:
        total, count, breakdown = compute_storage_breakdown(c, bucket)
        r["object_count"] = count
        r["total_size_bytes"] = total
        r["total_size_human"] = human_readable_size(total)
        r["storage_classes"] = ";".join(f"{k}:{v}" for k,v in breakdown.items())
    except Exception as e:
        r["comments"] = f"list_error:{e}"

    return r

def write_csv(path, rows):
    fields = [
        "bucket_name","creation_date","region","object_count","total_size_bytes",
        "total_size_human","lifecycle","versioning","encryption","public_access",
        "storage_classes","comments"
    ]
    with open(path, "w", newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for x in rows: w.writerow(x)

def main(profile, output, threads):
    session = get_s3_session(profile)
    c = session.client("s3")

    try: buckets = c.list_buckets().get("Buckets", [])
    except Exception as e:
        logger.error(f"Cannot list buckets: {e}")
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {}
        for b in buckets:
            wc = get_s3_session(profile).client("s3")
            futs[ex.submit(worker, wc, b)] = b['Name']

        for f in as_completed(futs):
            name = futs[f]
            try: res = f.result(); logger.info(f"{name} done")
            except Exception as e:
                res = {"bucket_name":name,"comments":f"worker_failed:{e}"}
            with lock: results.append(res)

    results.sort(key=lambda x: x["bucket_name"])
    write_csv(output, results)
    logger.info(f"CSV written: {output}")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument("--profile","-p",default=DEFAULT_PROFILE)
    p.add_argument("--output","-o",default=DEFAULT_OUTPUT)
    p.add_argument("--threads","-t",type=int,default=MAX_THREADS)
    a = p.parse_args()
    main(a.profile,a.output,a.threads)
