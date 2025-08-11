import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def audit_nacls(session, profile):
    logger.info(f"Starting NACL audit for profile: {profile}")

    ec2_client = session.client("ec2")
    try:
        regions_response = ec2_client.describe_regions(AllRegions=True)
        regions = [
            region["RegionName"]
            for region in regions_response["Regions"]
            if region["OptInStatus"] != "not-opted-in"
        ]
        logger.info(f"Found {len(regions)} regions to scan")
    except ClientError as e:
        logger.error(f"Failed to describe regions: {e}")
        return {"error": str(e)}

    report = {}
    for region in regions:
        logger.info(f"Auditing NACLs in region: {region}")
        regional_client = session.client("ec2", region_name=region)
        try:
            nacls_response = regional_client.describe_network_acls()
            nacls = nacls_response.get("NetworkAcls", [])
            logger.info(f"Found {len(nacls)} NACLs in {region}")

            region_report = []
            for nacl in nacls:
                nacl_info = {
                    "NetworkAclId": nacl.get("NetworkAclId"),
                    "VpcId": nacl.get("VpcId"),
                    "IsDefault": nacl.get("IsDefault"),
                    "Entries": []
                }
                for entry in nacl.get("Entries", []):
                    nacl_info["Entries"].append({
                        "RuleNumber": entry.get("RuleNumber"),
                        "Protocol": entry.get("Protocol"),
                        "RuleAction": entry.get("RuleAction"),
                        "Egress": entry.get("Egress"),
                        "CidrBlock": entry.get("CidrBlock"),
                        "Ipv6CidrBlock": entry.get("Ipv6CidrBlock", None),
                        "PortRange": entry.get("PortRange", None)
                    })
                region_report.append(nacl_info)
            report[region] = region_report
        except ClientError as e:
            logger.error(f"Error fetching NACLs for {region}: {e}")
            report[region] = {"error": str(e)}

    logger.info(f"NACL audit completed for profile: {profile}")
    return {"profile": profile, "nacl_report": report}
