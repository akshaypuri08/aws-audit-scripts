import boto3
import botocore
import logging
import os
import csv
import traceback

# Ensure logs directory exists
os.makedirs("./logs", exist_ok=True)

# Logger for selected-ports SG audits
logger = logging.getLogger("SG_Audit_SelectedPorts")
logger.setLevel(logging.INFO)

# File handler for SG logs (overwrite mode)
sg_log_file = "./logs/sg_audit_selected_ports.log"
file_handler = logging.FileHandler(sg_log_file, mode="w")
file_handler.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

if not logger.hasHandlers():
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


TARGET_PORTS = {20, 21, 22, 3389, 5432}


def get_devsecops_comment(cidr, port_range):
    """Return security comment based on CIDR and port range (no emojis)."""
    if cidr in ("0.0.0.0/0", "::/0"):
        if port_range in ("22", "3389"):
            return "High risk: Admin port open to the world"
        elif port_range == "ALL":
            return "All ports open to the world — critical risk"
        else:
            return "Open to the world — review necessity"
    else:
        return "Restricted access — verify if justified"


def permission_contains_target_ports(permission, target_ports):
    """Return True if permission port range contains any of target_ports."""
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    # If permission has no port info (e.g., protocol -1), treat it as matching
    if from_port is None or to_port is None:
        return True

    try:
        start = int(from_port)
        end = int(to_port)
    except (TypeError, ValueError):
        return False

    return any(start <= p <= end for p in target_ports)


def audit_security_groups_selected_ports(session, profile):
    """
    Scan all regions for security group rules that include any TARGET_PORTS.
    Returns dict: { profile, csv_report, rows_found } and logs to ./logs.
    The function is defensive: it catches exceptions and returns an error field
    instead of raising.
    """
    csv_file = "./logs/sg_audit_selected_ports.csv"
    rows = []

    try:
        logger.info(f"Using AWS profile: {profile}")
        # Validate session by calling STS
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            logger.info(f"Connected as: {identity.get('Arn')} (Account: {identity.get('Account')})")
        except botocore.exceptions.ClientError as e:
            logger.exception("Failed to validate AWS session/sts.get_caller_identity()")
            return {"profile": profile, "csv_report": None, "rows_found": 0, "error": str(e)}

        # Get regions
        try:
            ec2 = session.client("ec2")
            regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        except botocore.exceptions.ClientError as e:
            logger.exception("Failed to describe regions")
            return {"profile": profile, "csv_report": None, "rows_found": 0, "error": str(e)}

        logger.info(f"Scanning regions: {len(regions)} total")

        for region in regions:
            logger.info(f"Scanning region: {region}")
            try:
                ec2_region = session.client("ec2", region_name=region)
                paginator = ec2_region.get_paginator("describe_security_groups")
                page_iter = paginator.paginate()
            except botocore.exceptions.ClientError as e:
                if e.response.get("Error", {}).get("Code") == "AuthFailure":
                    logger.warning(f"Skipping region {region} due to AuthFailure")
                    continue
                logger.exception(f"Failed to create client/paginator for region {region}")
                continue

            for page in page_iter:
                sgs = page.get("SecurityGroups", [])
                logger.info(f"Retrieved {len(sgs)} security groups from {region}")

                for sg in sgs:
                    sg_id = sg.get("GroupId")
                    sg_name = sg.get("GroupName", "Unnamed")

                    for perm in sg.get("IpPermissions", []):
                        try:
                            if not permission_contains_target_ports(perm, TARGET_PORTS):
                                continue

                            # Build port range string
                            from_port = perm.get("FromPort")
                            to_port = perm.get("ToPort")
                            if from_port is None or to_port is None:
                                port_range = "ALL"
                            elif from_port == to_port:
                                port_range = str(from_port)
                            else:
                                port_range = f"{from_port}-{to_port}"

                            ip_protocol = perm.get("IpProtocol", "all")

                            # IPv4 ranges
                            for ipr in perm.get("IpRanges", []):
                                cidr = ipr.get("CidrIp")
                                if not cidr:
                                    continue
                                comment = get_devsecops_comment(cidr, port_range)
                                logger.info(f"{region} | {sg_id} | {sg_name} | {ip_protocol} | {port_range} | {cidr} | IPv4 | {comment}")
                                rows.append({
                                    "Region": region,
                                    "SecurityGroupId": sg_id,
                                    "SecurityGroupName": sg_name,
                                    "Protocol": ip_protocol,
                                    "PortRange": port_range,
                                    "CIDR": cidr,
                                    "IP_Version": "IPv4",
                                    "Comment": comment
                                })

                            # IPv6 ranges
                            for ipr6 in perm.get("Ipv6Ranges", []):
                                cidr6 = ipr6.get("CidrIpv6")
                                if not cidr6:
                                    continue
                                comment = get_devsecops_comment(cidr6, port_range)
                                logger.info(f"{region} | {sg_id} | {sg_name} | {ip_protocol} | {port_range} | {cidr6} | IPv6 | {comment}")
                                rows.append({
                                    "Region": region,
                                    "SecurityGroupId": sg_id,
                                    "SecurityGroupName": sg_name,
                                    "Protocol": ip_protocol,
                                    "PortRange": port_range,
                                    "CIDR": cidr6,
                                    "IP_Version": "IPv6",
                                    "Comment": comment
                                })
                        except Exception:
                            logger.exception(f"Error processing permission for SG {sg.get('GroupId')}")
                            # continue to next permission

        # Write CSV (always write header, even if rows empty)
        fieldnames = ["Region", "SecurityGroupId", "SecurityGroupName", "Protocol", "PortRange", "CIDR", "IP_Version", "Comment"]
        try:
            with open(csv_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
            logger.info(f"Selected-ports CSV saved to {csv_file} ({len(rows)} rows)")
        except Exception:
            logger.exception("Failed to write CSV")
            return {"profile": profile, "csv_report": None, "rows_found": 0, "error": "Failed to write CSV"}

        return {"profile": profile, "csv_report": csv_file, "rows_found": len(rows)}

    except Exception as e:
        logger.exception("Unexpected error during selected-ports audit")
        tb = traceback.format_exc()
        return {"profile": profile, "csv_report": None, "rows_found": 0, "error": str(e), "traceback": tb}
