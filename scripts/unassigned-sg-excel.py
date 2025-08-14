import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError
from openpyxl import Workbook
from openpyxl.styles import Font

# ------------------- CONFIG -------------------
PROFILE_NAME = "aqcn"
OUTPUT_XLSX = "unused_security_groups.xlsx"
# -----------------------------------------------

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger()

def get_all_regions(session):
    """Fetch all AWS regions."""
    try:
        ec2_client = session.client("ec2", region_name="us-east-1")
        regions = [
            r["RegionName"]
            for r in ec2_client.describe_regions(AllRegions=True)["Regions"]
            if r["OptInStatus"] in ["opt-in-not-required", "opted-in"]
        ]
        logger.info(f"Found {len(regions)} regions: {regions}")
        return regions
    except ClientError as e:
        logger.error(f"Error getting regions: {e}")
        return []

def get_unused_security_groups(session, region):
    """Get all unused security groups in the region."""
    try:
        ec2 = session.client("ec2", region_name=region)
        
        all_sgs = ec2.describe_security_groups()["SecurityGroups"]
        enis = ec2.describe_network_interfaces()["NetworkInterfaces"]
        attached_sg_ids = {sg["GroupId"] for eni in enis for sg in eni["Groups"]}
        
        unused_sgs = [sg for sg in all_sgs if sg["GroupId"] not in attached_sg_ids]
        
        results = []
        for sg in unused_sgs:
            sg_name = sg.get("GroupName", "")
            sg_id = sg["GroupId"]
            
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
                            region, sg_id, sg_name, protocol, port_range,
                            ip_range.get("CidrIp", ""), "IPv4",
                            ip_range.get("Description", "")
                        ])
                    for ip_range in rule.get("Ipv6Ranges", []):
                        results.append([
                            region, sg_id, sg_name, protocol, port_range,
                            ip_range.get("CidrIpv6", ""), "IPv6",
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
        base_session = boto3.Session(profile_name=PROFILE_NAME)
        regions = get_all_regions(base_session)
        
        all_results = []
        for region in regions:
            logger.info(f"Processing region: {region}")
            all_results.extend(get_unused_security_groups(base_session, region))
        
        # Create Excel file
        wb = Workbook()
        ws = wb.active
        ws.title = "Unused Security Groups"
        
        headers = ["Region", "SecurityGroupId", "SecurityGroupName", "Protocol", "PortRange", "CIDR", "IP_Version", "Comment"]
        ws.append(headers)
        
        # Make headers bold
        for cell in ws[1]:
            cell.font = Font(bold=True)
        
        # Add data rows
        for row in all_results:
            ws.append(row)
        
        # Auto column width
        for col in ws.columns:
            max_length = max(len(str(cell.value)) if cell.value else 0 for cell in col)
            ws.column_dimensions[col[0].column_letter].width = max_length + 2
        
        wb.save(OUTPUT_XLSX)
        logger.info(f"Excel file generated: {OUTPUT_XLSX}")
    
    except NoCredentialsError:
        logger.error("AWS credentials not found. Check your profile and config.")
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")

if __name__ == "__main__":
    main()
