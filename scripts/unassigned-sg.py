import boto3
import csv
import logging
from botocore.exceptions import ClientError, NoCredentialsError

# ------------------- CONFIG -------------------
PROFILE_NAME = "aqcn"
OUTPUT_CSV = "unused_security_groups.csv"
ROLE_SESSION_NAME = "cross_account_sg_audit"
# -----------------------------------------------

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger()

def get_all_regions(session):
    """Fetch all AWS regions."""
    try:
        ec2_client = session.client("ec2", region_name="us-east-1")
        regions = [r["RegionName"] for r in ec2_client.describe_regions(AllRegions=True)["Regions"] if r["OptInStatus"] in ["opt-in-not-required", "opted-in"]]
        logger.info(f"Found {len(regions)} regions: {regions}")
        return regions
    except ClientError as e:
        logger.error(f"Error getting regions: {e}")
        return []

def get_unused_security_groups(session, region):
    """Get all unused security groups in the region."""
    try:
        ec2 = session.client("ec2", region_name=region)
        
        # Get all security groups
        all_sgs = ec2.describe_security_groups()["SecurityGroups"]
        
        # Get all ENIs to check attachments
        enis = ec2.describe_network_interfaces()["NetworkInterfaces"]
        attached_sg_ids = {sg["GroupId"] for eni in enis for sg in eni["Groups"]}
        
        # Filter unused SGs
        unused_sgs = [sg for sg in all_sgs if sg["GroupId"] not in attached_sg_ids]
        
        results = []
        for sg in unused_sgs:
            sg_name = sg.get("GroupName", "")
            sg_id = sg["GroupId"]
            # If no ingress rules, still record with empty protocol/port/CIDR
            if not sg.get("IpPermissions"):
                results.append([region, sg_id, sg_name, "", "", "", "", "No ingress rules"])
            else:
                for rule in sg["IpPermissions"]:
                    ip_protocol = rule.get("IpProtocol", "")
                    if ip_protocol == "-1":
                        protocol = "ALL"
                        port_range = "ALL"
                    else:
                        protocol = ip_protocol
                        from_port = rule.get("FromPort", "")
                        to_port = rule.get("ToPort", "")
                        port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                    
                    for ip_range in rule.get("IpRanges", []):
                        results.append([
                            region,
                            sg_id,
                            sg_name,
                            protocol,
                            port_range,
                            ip_range.get("CidrIp", ""),
                            "IPv4",
                            ip_range.get("Description", "")
                        ])
                    for ip_range in rule.get("Ipv6Ranges", []):
                        results.append([
                            region,
                            sg_id,
                            sg_name,
                            protocol,
                            port_range,
                            ip_range.get("CidrIpv6", ""),
                            "IPv6",
                            ip_range.get("Description", "")
                        ])
        return results
    except ClientError as e:
        logger.error(f"[{region}] Error fetching security groups: {e}")
        return []
    except Exception as e:
        logger.error(f"[{region}] Unexpected error: {e}")
        return []

def main():
    try:
        # Create boto3 session with profile
        base_session = boto3.Session(profile_name=PROFILE_NAME)
        
        # Get all regions
        regions = get_all_regions(base_session)
        
        all_results = []
        for region in regions:
            logger.info(f"Processing region: {region}")
            all_results.extend(get_unused_security_groups(base_session, region))
        
        # Write to CSV
        with open(OUTPUT_CSV, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Region", "SecurityGroupId", "SecurityGroupName", "Protocol", "PortRange", "CIDR", "IP_Version", "Comment"])
            writer.writerows(all_results)
        
        logger.info(f"CSV generated: {OUTPUT_CSV}")
    except NoCredentialsError:
        logger.error("AWS credentials not found. Check your profile and config.")
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")

if __name__ == "__main__":
    main()
