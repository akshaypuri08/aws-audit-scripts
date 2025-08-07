# main.py

import boto3
import logging
import sys
import os

from modules.nacl_review import review_nacls


# === CONFIGURATION ===
AWS_REGION = "us-east-1"  # You can modify this or make it dynamic if needed

# === LOGGING SETUP ===
os.makedirs("logs", exist_ok=True)  # Ensure logs directory exists

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/nacl_review.log"),
        logging.StreamHandler()
    ]
)

# === ENTRY POINT ===
if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("Usage: python main.py <aws_profile>")
        sys.exit(1)

    aws_profile = sys.argv[1]
    logging.info(f"Using AWS profile: {aws_profile}")
    logging.info(f"Target AWS region: {AWS_REGION}")

    try:
        session = boto3.Session(profile_name=aws_profile, region_name=AWS_REGION)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        logging.info(f"Connected as: {identity['Arn']} (Account: {identity['Account']})")
    except Exception as e:
        logging.error(f"Failed to initialize AWS session: {e}")
        sys.exit(1)

    # === Call Review Modules ===
    review_nacls(session, AWS_REGION)
