import boto3
import os
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError, BotoCoreError
from openpyxl import Workbook

# =====================================================
# CONFIG
# =====================================================

MAX_THREADS = int(os.getenv("MAX_THREADS", 15))
DEFAULT_PROFILE = os.getenv("AWS_PROFILE", "aqi")
DEFAULT_OUTPUT = os.getenv("DEFAULT_OUTPUT", "s3_audit_aqi.xlsx")

BUCKET_NAME = "ai.corporate.backup"

# =====================================================
# LOGGING SETUP
# =====================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("s3_audit.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# =====================================================
# AWS SESSION
# =====================================================

try:
    session = boto3.Session(profile_name=DEFAULT_PROFILE)
    s3 = session.client("s3")
    logger.info(f"AWS session created using profile: {DEFAULT_PROFILE}")
except Exception as e:
    logger.error(f"Failed to create AWS session: {e}")
    raise

NOW = datetime.now(timezone.utc)

# =====================================================
# HELPERS
# =====================================================

def get_top_prefix(key):
    parts = key.split("/")
    return parts[0] if len(parts) > 1 else "ROOT"

def get_age_days(last_modified):
    return (NOW - last_modified).days

def age_category(days):
    if days <= 90:
        return "HOT (0-90 days)"
    elif days <= 365:
        return "WARM (90-365 days)"
    elif days <= 1095:
        return "OLD (1-3 years)"
    return "VERY OLD (3+ years)"

def is_large_file(size_bytes):
    return "YES" if size_bytes > 1024**3 else "NO"

def detect_pattern(key):
    k = key.lower()
    if any(x in k for x in ["backup", ".bak", "dump", "snapshot"]):
        return "BACKUP"
    elif any(x in k for x in ["archive", "legacy", "old"]):
        return "ARCHIVE"
    elif ".log" in k:
        return "LOG"
    return "NORMAL"

def recommendation(age_cat, pattern, large):
    if age_cat == "VERY OLD (3+ years)" and pattern in ["BACKUP", "LOG"]:
        return "Strong Archive/Delete Candidate"
    elif age_cat in ["OLD (1-3 years)", "VERY OLD (3+ years)"]:
        return "Review for Glacier"
    elif large == "YES":
        return "Large File - Review"
    return "Keep"

# =====================================================
# LIST OBJECTS
# =====================================================

def list_objects():
    """Safely list S3 objects using paginator"""
    try:
        paginator = s3.get_paginator("list_objects_v2")

        for page in paginator.paginate(Bucket=BUCKET_NAME):
            if "Contents" in page:
                for obj in page["Contents"]:
                    yield obj

    except (ClientError, BotoCoreError) as e:
        logger.error(f"AWS error while listing objects: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error listing objects: {e}")
        raise

# =====================================================
# PROCESS OBJECT
# =====================================================

def process_object(obj):
    """Process single object safely"""
    try:
        key = obj["Key"]
        size_bytes = obj["Size"]
        size_mb = round(size_bytes / (1024 * 1024), 2)
        last_modified = obj["LastModified"]
        storage_class = obj.get("StorageClass", "STANDARD")

        age_days = get_age_days(last_modified)
        age_cat = age_category(age_days)
        large = is_large_file(size_bytes)
        pattern = detect_pattern(key)

        return [
            key,
            size_mb,
            last_modified.strftime("%Y-%m-%d"),
            age_days,
            age_cat,
            storage_class,
            get_top_prefix(key),
            large,
            pattern,
            recommendation(age_cat, pattern, large),
        ]

    except Exception as e:
        logger.error(f"Error processing object {obj.get('Key','UNKNOWN')}: {e}")
        return None

# =====================================================
# MAIN
# =====================================================

def main():
    logger.info(f"Starting S3 audit for bucket: {BUCKET_NAME}")

    wb = Workbook()
    ws = wb.active
    ws.title = "S3 Audit"

    headers = [
        "Key",
        "Size_MB",
        "LastModified",
        "Age_Days",
        "Age_Category",
        "StorageClass",
        "TopPrefix",
        "LargeFile_GT_1GB",
        "DetectedPattern",
        "Recommendation",
    ]
    ws.append(headers)

    total = 0

    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for row in executor.map(process_object, list_objects()):

                if row:
                    ws.append(row)
                    total += 1

                    if total % 5000 == 0:
                        logger.info(f"Processed {total} objects...")

    except Exception as e:
        logger.error(f"Error during processing: {e}")
        raise

    # Save Excel safely
    try:
        wb.save(DEFAULT_OUTPUT)
        logger.info("Audit completed successfully")
        logger.info(f"Total objects scanned: {total}")
        logger.info(f"Excel generated: {DEFAULT_OUTPUT}")

    except Exception as e:
        logger.error(f"Failed to save Excel file: {e}")
        raise

# =====================================================

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Script failed: {e}")
