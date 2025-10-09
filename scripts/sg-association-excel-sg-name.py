import boto3
import logging
import pandas as pd
import concurrent.futures
from botocore.exceptions import ClientError, BotoCoreError

# ==========================
# CONFIGURATION
# ==========================
AWS_PROFILE = "aqcn"
INBOUND_FILE = "security_groups_inbound.xlsx"
OUTBOUND_FILE = "security_groups_outbound.xlsx"
MAX_THREADS = 5

# Security Group names to search
SECURITY_GROUP_NAMES = [
    "k8s-elb-a5e993977878a48a198cd07166530fd8",
    "SG060-nlb",
    "k8s-elb-aaa0c7b9e7d2640a698b9e30f7fb87c5",
    "k8s-elb-a84d6bc5d34d940cfa7f23540a6beb2e",
    "AIOffice",
    "cicd-elb",
    "all-access-jenkins-cicd-for-dsun-sg",
    "k8s-elb-afbdb09fbe649455d83108c3c5c04951"
]

# ==========================
# LOGGING SETUP
# ==========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ==========================
# BOTO3 SESSION
# ==========================
session = boto3.Session(profile_name=AWS_PROFILE)
ec2 = session.client("ec2")
elbv2 = session.client("elbv2")

# ==========================
# HELPERS
# ==========================
def get_sg_details():
    """Return all security groups that match SECURITY_GROUP_NAMES."""
    try:
        response = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": SECURITY_GROUP_NAMES}]
        )
        return response.get("SecurityGroups", [])
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Error describing SGs: {e}")
        return []

def get_sg_resources(sg):
    """Return ENIs, Load balancers, and Subnet info for the SG."""
    sg_id = sg["GroupId"]
    sg_name = sg["GroupName"]
    sg_desc = sg["Description"]

    results = []

    try:
        # Find ENIs associated with this SG
        eni_resp = ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        )

        for eni in eni_resp.get("NetworkInterfaces", []):
            subnet_id = eni.get("SubnetId", "")
            subnet_name = ""
            subnet_type = ""

            if subnet_id:
                try:
                    subnet_info = ec2.describe_subnets(SubnetIds=[subnet_id])
                    if subnet_info["Subnets"]:
                        tags = subnet_info["Subnets"][0].get("Tags", [])
                        subnet_name = next((t["Value"] for t in tags if t["Key"] == "Name"), "")
                        subnet_type = subnet_info["Subnets"][0]["MapPublicIpOnLaunch"]
                        subnet_type = "public" if subnet_type else "private"
                except Exception as e:
                    logger.warning(f"Could not fetch subnet {subnet_id}: {e}")

            results.append({
                "Region": session.region_name,
                "SG ID": sg_id,
                "SG Name": sg_name,
                "SG Description": sg_desc,
                "Resource Type": "ENI",
                "Resource ID": eni["NetworkInterfaceId"],
                "Resource Name": eni.get("Description", ""),
                "Subnet Name": subnet_name,
                "Subnet ID": subnet_id,
                "Subnet Type": subnet_type
            })
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Error fetching ENIs for {sg_id}: {e}")

    # Could add ELBv2 lookup (load balancers) here if needed:
    try:
        lbs = elbv2.describe_load_balancers()
        for lb in lbs.get("LoadBalancers", []):
            if sg_id in lb.get("SecurityGroups", []):
                subnet_ids = lb.get("AvailabilityZones", [])
                for az in subnet_ids:
                    results.append({
                        "Region": session.region_name,
                        "SG ID": sg_id,
                        "SG Name": sg_name,
                        "SG Description": sg_desc,
                        "Resource Type": lb["Type"].upper(),
                        "Resource ID": lb["LoadBalancerArn"],
                        "Resource Name": lb["LoadBalancerName"],
                        "Subnet Name": "",
                        "Subnet ID": az.get("SubnetId", ""),
                        "Subnet Type": ""
                    })
    except Exception as e:
        logger.warning(f"Could not fetch Load Balancers: {e}")

    return results

def extract_rules(sg, direction="inbound"):
    """Extract inbound/outbound rules for the SG."""
    rules = sg["IpPermissions"] if direction == "inbound" else sg["IpPermissionsEgress"]
    results = []
    for r in rules:
        protocol = r.get("IpProtocol", "-1")
        port_range = ""
        if "FromPort" in r and "ToPort" in r:
            port_range = f"{r['FromPort']}-{r['ToPort']}"
        cidrs = [ip["CidrIp"] for ip in r.get("IpRanges", [])]
        sg_refs = [sgref["GroupId"] for sgref in r.get("UserIdGroupPairs", [])]

        results.append({
            "Protocol": protocol,
            "Port(s)": port_range,
            "CIDR/Reference field": ",".join(cidrs + sg_refs)
        })
    return results

# ==========================
# MAIN
# ==========================
def process_sg(sg):
    try:
        resources = get_sg_resources(sg)

        inbound_rules = extract_rules(sg, "inbound")
        outbound_rules = extract_rules(sg, "outbound")

        inbound = []
        outbound = []

        for res in resources:
            for rule in inbound_rules:
                inbound.append({**res, **rule})
            for rule in outbound_rules:
                outbound.append({**res, **rule})

        return inbound, outbound

    except Exception as e:
        logger.error(f"Error processing SG {sg['GroupId']}: {e}")
        return [], []

def main():
    logger.info("Fetching SG details...")
    sgs = get_sg_details()

    inbound_all = []
    outbound_all = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(process_sg, sg): sg for sg in sgs}
        for future in concurrent.futures.as_completed(futures):
            sg = futures[future]
            try:
                inbound, outbound = future.result()
                inbound_all.extend(inbound)
                outbound_all.extend(outbound)
            except Exception as e:
                logger.error(f"Failed to process SG {sg['GroupId']}: {e}")

    if inbound_all:
        pd.DataFrame(inbound_all).to_excel(INBOUND_FILE, index=False)
        logger.info(f"Inbound rules written to {INBOUND_FILE}")
    else:
        logger.warning("No inbound data found")

    if outbound_all:
        pd.DataFrame(outbound_all).to_excel(OUTBOUND_FILE, index=False)
        logger.info(f"Outbound rules written to {OUTBOUND_FILE}")
    else:
        logger.warning("No outbound data found")

if __name__ == "__main__":
    main()
