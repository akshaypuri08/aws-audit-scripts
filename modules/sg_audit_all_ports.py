import boto3
import botocore
import logging
import os
import csv

# Ensure logs directory exists
os.makedirs("./logs", exist_ok=True)

# Logger for SG audits
logger = logging.getLogger("SG_Audit_AllPorts")
logger.setLevel(logging.INFO)

# File handler for SG logs (overwrite mode)
sg_log_file = "./logs/sg_audit_all_ports.log"
file_handler = logging.FileHandler(sg_log_file, mode="w")
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


def audit_security_groups_all_ports(session, profile):
    logger.info(f"Using AWS profile: {profile}")

    sts = session.client("sts")
    identity = sts.get_caller_identity()
    logger.info(f"Connected as: {identity['Arn']} (Account: {identity['Account']})")

    ec2 = session.client("ec2")
    regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

    report_rows = []

    for region in regions:
        logger.info(f"Target AWS region: {region}")
        ec2_region = session.client("ec2", region_name=region)

        try:
            sgs = ec2_region.describe_security_groups()["SecurityGroups"]
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "AuthFailure":
                logger.warning(f"Skipping {region} - AuthFailure")
                continue
            else:
                raise

        logger.info(f"Retrieved {len(sgs)} Security Group(s) from region '{region}'")

        for sg in sgs:
            logger.info(f"\n=== SG ID: {sg['GroupId']} | Name: {sg.get('GroupName', 'Unnamed')} ===")

            for perm in sg.get("IpPermissions", []):
                ip_protocol = perm.get("IpProtocol", "all")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")

                if from_port is None or to_port is None:
                    port_range = "ALL"
                elif from_port == to_port:
                    port_range = str(from_port)
                else:
                    port_range = f"{from_port}-{to_port}"

                # Check IPv4 ranges
                for ip_range in perm.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if cidr:
                        logger.info(f"Inbound | Protocol: {ip_protocol} | Ports: {port_range} | IPv4 CIDR: {cidr}")
                        report_rows.append([region, sg["GroupId"], sg.get("GroupName", "Unnamed"),
                                            ip_protocol, port_range, cidr, "IPv4"])

                # Check IPv6 ranges
                for ip_range in perm.get("Ipv6Ranges", []):
                    cidr = ip_range.get("CidrIpv6")
                    if cidr:
                        logger.info(f"Inbound | Protocol: {ip_protocol} | Ports: {port_range} | IPv6 CIDR: {cidr}")
                        report_rows.append([region, sg["GroupId"], sg.get("GroupName", "Unnamed"),
                                            ip_protocol, port_range, cidr, "IPv6"])

    # Save CSV
    csv_file = "./logs/sg_audit_all_ports.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Region", "SecurityGroupId", "SecurityGroupName",
                         "Protocol", "PortRange", "CIDR", "IP_Version"])
        writer.writerows(report_rows)

    logger.info(f"CSV report saved to {csv_file}")
    return {"profile": profile, "csv_report": csv_file, "rows_found": len(report_rows)}
