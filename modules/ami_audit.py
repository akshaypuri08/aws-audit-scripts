import boto3
import logging
from botocore.exceptions import ClientError
import os

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Setup AMI-specific logger
ami_logger = logging.getLogger("AMIReviewLogger")
ami_logger.setLevel(logging.INFO)

if not ami_logger.handlers:
    handler = logging.FileHandler("logs/ami_review.log", encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    ami_logger.addHandler(handler)

ami_logger.info(f"\n========= Scanning Started =========")
def audit_amis(session, region):
    try:
        ami_logger.info(f"\n========= Scanning region: {region} =========")
        ec2_client = session.client("ec2", region_name=region)

        response = ec2_client.describe_images(Owners=["self"])
        images = response.get("Images", [])

        if not images:
            ami_logger.info(f"No AMIs found in region: {region}")
            return

        for image in images:
            ami_id = image.get("ImageId")
            name = image.get("Name", "N/A")
            creation_date = image.get("CreationDate", "N/A")
            state = image.get("State", "N/A")

            ami_logger.info(f"AMI ID: {ami_id}")
            ami_logger.info(f"Name: {name}")
            ami_logger.info(f"State: {state}")
            ami_logger.info(f"Creation Date: {creation_date}")

            if state != "available":
                ami_logger.warning(f"AMI {ami_id} is in state '{state}' — investigate if unexpected.")

            ami_logger.info("-" * 60)

    except ClientError as e:
        ami_logger.error("Error retrieving AMIs in region %s: %s", region, e)
    except Exception as ex:
        ami_logger.exception("Unexpected error while auditing AMIs in region %s: %s", region, ex)
