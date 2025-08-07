import boto3
import logging
import os
import sys
from modules.nacl_review import review_nacls
from botocore.exceptions import ClientError

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/nacl_review.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
)

def get_all_regions(session):
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in response['Regions']]
        return regions
    except ClientError as e:
        logging.error(f"Failed to fetch AWS regions: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.error("Usage: python main.py <aws_profile_name>")
        sys.exit(1)

    AWS_PROFILE = sys.argv[1]

    try:
        session = boto3.Session(profile_name=AWS_PROFILE)
    except Exception as e:
        logging.error(f"Failed to create session with profile '{AWS_PROFILE}': {e}")
        sys.exit(1)

    regions = get_all_regions(session)

    if not regions:
        logging.error("No regions found. Exiting.")
        sys.exit(1)

    for region in regions:
        logging.info(f"\n\n========= Scanning region: {region} =========")
        review_nacls(session, region)
