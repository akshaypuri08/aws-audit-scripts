import boto3
import logging
import os

# Ensure logs directory exists
os.makedirs("./logs", exist_ok=True)

# Logger for NACL audits
logger = logging.getLogger("NACL_Audit")
logger.setLevel(logging.INFO)

# File handler for NACL logs (overwrite mode)
nacl_log_file = "./logs/nacl_audit.log"
file_handler = logging.FileHandler(nacl_log_file, mode="w")
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


def audit_nacls(session, profile):
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
        nacls = ec2_region.describe_network_acls()["NetworkAcls"]
        logger.info(f"Retrieved {len(nacls)} NACL(s) from region '{region}'")

        report[region] = []
        for nacl in nacls:
            logger.info(f"\n=== NACL ID: {nacl['NetworkAclId']} ===")
            for entry in nacl["Entries"]:
                direction = "Outbound" if entry["Egress"] else "Inbound"
                port_range = "ALL - ALL" if "PortRange" not in entry else f"{entry['PortRange']['From']} - {entry['PortRange']['To']}"
                cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "N/A")
                logger.info(f"{direction} Rule #{entry['RuleNumber']} | {entry['RuleAction'].upper()} | "
                            f"Protocol: {entry['Protocol']} | Port: {port_range} | CIDR: {cidr}")

            report[region].append(nacl)

    return {"profile": profile, "nacl_report": report}
