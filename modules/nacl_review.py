import boto3
import logging
import os
from botocore.exceptions import ClientError

# Logger setup
logger = logging.getLogger("nacl_logger")
logger.setLevel(logging.INFO)

if not logger.handlers:
    os.makedirs("logs", exist_ok=True)

    # File handler
    file_handler = logging.FileHandler("logs/nacl_review.log", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)


def review_nacls(session, region):
    try:
        logger.info("========= Scanning region: %s =========", region)

        ec2_client = session.client("ec2", region_name=region)
        nacls = ec2_client.describe_network_acls()

        if not nacls['NetworkAcls']:
            logger.info("No NACLs found in region: %s", region)
            return

        for nacl in nacls['NetworkAcls']:
            nacl_id = nacl.get("NetworkAclId")
            logger.info("\n=== NACL ID: %s ===", nacl_id)

            for entry in nacl.get("Entries", []):
                rule_number = entry.get("RuleNumber")
                protocol = entry.get("Protocol")
                egress = entry.get("Egress")
                rule_action = entry.get("RuleAction")
                port_range = entry.get("PortRange", {})
                cidr_block = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "N/A")

                from_port = port_range.get("From", "ALL")
                to_port = port_range.get("To", "ALL")

                direction = "Outbound" if egress else "Inbound"
                log_msg = (
                    f"{direction} Rule #{rule_number} | {rule_action.upper()} | "
                    f"Protocol: {protocol} | Port: {from_port} - {to_port} | CIDR: {cidr_block}"
                )
                logger.info(log_msg)

                # Simple rule review
                recommendation = []

                if not egress and rule_action == "allow":
                    if cidr_block in ["0.0.0.0/0", "::/0"]:
                        recommendation.append("Open to all IPs - consider restricting CIDR")

                if egress and rule_action == "allow":
                    if cidr_block in ["0.0.0.0/0", "::/0"]:
                        recommendation.append("Generally OK for outbound")

                if recommendation:
                    logger.info("  Recommendation: " + " | ".join(recommendation))

    except ClientError as e:
        logger.error("Error retrieving NACLs: %s", e)
    except Exception as ex:
        logger.exception("Unexpected error occurred while reviewing NACLs: %s", ex)
