import logging
import os

# Logger setup
logger = logging.getLogger("ami_logger")
logger.setLevel(logging.INFO)

# Prevent duplicate handlers
if not logger.handlers:
    os.makedirs("logs", exist_ok=True)
    file_handler = logging.FileHandler("logs/ami_review.log", encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def audit_amis(session, region):
    try:
        ec2 = session.client("ec2", region_name=region)
        instances = ec2.describe_instances()

        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance.get('InstanceId', 'N/A')
                ami_id = instance.get('ImageId', 'N/A')
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'Unnamed')

                logger.info(f"Instance ID: {instance_id} | Name: {name} | AMI ID: {ami_id}")
    except Exception as e:
        logger.error(f"Error auditing AMIs in region {region}: {e}")
