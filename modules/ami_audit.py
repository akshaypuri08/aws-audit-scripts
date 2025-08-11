import boto3
import logging
import os

# Ensure logs directory exists
os.makedirs("./logs", exist_ok=True)

# Logger for AMI audits
logger = logging.getLogger("AMI_Audit")
logger.setLevel(logging.INFO)

# File handler for AMI logs (overwrite mode)
ami_log_file = "./logs/ami_audit.log"
file_handler = logging.FileHandler(ami_log_file, mode="w")
file_handler.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers if not already present
if not logger.hasHandlers():
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def audit_amis(session, profile):
    logger.info(f"Using AWS profile: {profile}")

    sts = session.client("sts")
    identity = sts.get_caller_identity()
    logger.info(f"Connected as: {identity['Arn']} (Account: {identity['Account']})")

    ec2 = session.client("ec2")
    regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

    report = {}
    for region in regions:
        logger.info(f"Target AWS region: {region}")
        ec2_region = session.client("ec2", region_name=region)
        amis = ec2_region.describe_images(Owners=["self"])["Images"]
        logger.info(f"Retrieved {len(amis)} AMI(s) from region '{region}'")

        for ami in amis:
            logger.info(f"AMI ID: {ami['ImageId']} | Name: {ami.get('Name', 'N/A')} | Creation Date: {ami['CreationDate']}")

        report[region] = amis

    return {"profile": profile, "ami_report": report}
