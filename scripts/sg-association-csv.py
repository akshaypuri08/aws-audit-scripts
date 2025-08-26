import boto3
import csv
import logging
from botocore.exceptions import ClientError

# ---------------- Logging Setup ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

PROFILE_NAME = "aqcn"
OUTPUT_FILE = "in_use_security_groups_all.csv"

# ---------------- AWS Session ----------------
try:
    boto3.setup_default_session(profile_name=PROFILE_NAME)
    session = boto3.Session(profile_name=PROFILE_NAME)
    logging.info(f"Using AWS profile: {PROFILE_NAME}")
except Exception as e:
    logging.error(f"Failed to create AWS session: {e}")
    raise

# ---------------- Get all regions ----------------
try:
    ec2_client = session.client("ec2")
    regions = [r["RegionName"] for r in ec2_client.describe_regions()["Regions"]]
    logging.info(f"Found {len(regions)} AWS regions.")
except ClientError as e:
    logging.error(f"Error fetching regions: {e}")
    raise

# ---------------- CSV Setup ----------------
csv_header = [
    "Region", "SecurityGroupId", "SecurityGroupName", "Protocol", "PortRange",
    "CIDR", "IP_Version", "Resource_Type", "ResourceId", "Resource_Name"
]
results = []

# ---------------- Helper: Extract Name tag ----------------
def get_name_from_tags(tags):
    if not tags:
        return ""
    for tag in tags:
        if tag["Key"].lower() == "name":
            return tag["Value"]
    return ""

# ---------------- Iterate over regions ----------------
for region in regions:
    logging.info(f"Scanning region: {region}")
    try:
        ec2 = session.client("ec2", region_name=region)

        # Get all SGs in region
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        # Get ENIs
        nis = ec2.describe_network_interfaces()["NetworkInterfaces"]

        # Map: SG ID → List of resources
        sg_resources = {sg["GroupId"]: [] for sg in sgs}

        # ----- EC2 Instances -----
        try:
            ec2_instances = ec2.describe_instances()
            for res in ec2_instances["Reservations"]:
                for inst in res["Instances"]:
                    for sg in inst.get("SecurityGroups", []):
                        sg_resources[sg["GroupId"]].append(
                            ("EC2", inst["InstanceId"], get_name_from_tags(inst.get("Tags", [])))
                        )
        except Exception as e:
            logging.warning(f"EC2 fetch failed in {region}: {e}")

        # ----- Network Interfaces -----
        for ni in nis:
            for sg in ni.get("Groups", []):
                sg_resources[sg["GroupId"]].append(
                    ("NetworkInterface", ni["NetworkInterfaceId"], ni.get("Description", ""))
                )

        # ----- Classic Load Balancers -----
        try:
            elb = session.client("elb", region_name=region)
            lbs = elb.describe_load_balancers()["LoadBalancerDescriptions"]
            for lb in lbs:
                for sg_id in lb.get("SecurityGroups", []):
                    sg_resources[sg_id].append(("ClassicELB", lb["LoadBalancerName"], lb["DNSName"]))
        except Exception as e:
            logging.warning(f"Classic ELB fetch failed in {region}: {e}")

        # ----- ALB/NLB -----
        try:
            elbv2 = session.client("elbv2", region_name=region)
            lbs_v2 = elbv2.describe_load_balancers()["LoadBalancers"]
            for lb in lbs_v2:
                for sg_id in lb.get("SecurityGroups", []):
                    sg_resources[sg_id].append((lb["Type"] + " (ELBv2)", lb["LoadBalancerArn"], lb["DNSName"]))
        except Exception as e:
            logging.warning(f"ALB/NLB fetch failed in {region}: {e}")

        # ----- RDS Instances & Clusters -----
        try:
            rds = session.client("rds", region_name=region)
            dbs = rds.describe_db_instances()["DBInstances"]
            for db in dbs:
                for sg in db.get("VpcSecurityGroups", []):
                    sg_resources[sg["VpcSecurityGroupId"]].append(
                        ("RDS Instance", db["DBInstanceIdentifier"], db["Endpoint"]["Address"])
                    )
            clusters = rds.describe_db_clusters()["DBClusters"]
            for cl in clusters:
                for sg in cl.get("VpcSecurityGroups", []):
                    sg_resources[sg["VpcSecurityGroupId"]].append(
                        ("RDS Cluster", cl["DBClusterIdentifier"], cl.get("Endpoint", ""))
                    )
        except Exception as e:
            logging.warning(f"RDS fetch failed in {region}: {e}")

        # ----- Elasticache -----
        try:
            elasticache = session.client("elasticache", region_name=region)
            caches = elasticache.describe_cache_clusters(ShowCacheNodeInfo=False)["CacheClusters"]
            for cache in caches:
                for sg_id in cache.get("SecurityGroups", []):
                    sg_resources[sg_id["SecurityGroupId"]].append(
                        ("ElastiCache", cache["CacheClusterId"], cache["Engine"])
                    )
        except Exception as e:
            logging.warning(f"ElastiCache fetch failed in {region}: {e}")

        # ----- Redshift -----
        try:
            redshift = session.client("redshift", region_name=region)
            clusters = redshift.describe_clusters()["Clusters"]
            for cl in clusters:
                for sg in cl.get("VpcSecurityGroups", []):
                    sg_resources[sg["VpcSecurityGroupId"]].append(
                        ("Redshift", cl["ClusterIdentifier"], cl.get("Endpoint", {}).get("Address", ""))
                    )
        except Exception as e:
            logging.warning(f"Redshift fetch failed in {region}: {e}")

        # ----- Lambda in VPC -----
        try:
            lam = session.client("lambda", region_name=region)
            funcs = lam.list_functions()["Functions"]
            for fn in funcs:
                if "VpcConfig" in fn and "SecurityGroupIds" in fn["VpcConfig"]:
                    for sg_id in fn["VpcConfig"]["SecurityGroupIds"]:
                        sg_resources[sg_id].append(
                            ("Lambda", fn["FunctionName"], fn.get("Description", ""))
                        )
        except Exception as e:
            logging.warning(f"Lambda fetch failed in {region}: {e}")

        # ----- Build CSV rows -----
        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            if sg_id not in sg_resources or not sg_resources[sg_id]:
                continue  # Skip unused SGs

            for perm in sg.get("IpPermissions", []):
                protocol = perm.get("IpProtocol", "-1")
                from_port = perm.get("FromPort", "All") if "FromPort" in perm else "All"
                to_port = perm.get("ToPort", "All") if "ToPort" in perm else "All"
                port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)

                # IPv4
                for cidr in perm.get("IpRanges", []):
                    for res_type, res_id, res_name in sg_resources[sg_id]:
                        results.append([
                            region, sg_id, sg_name, protocol, port_range,
                            cidr.get("CidrIp", ""), "IPv4", res_type, res_id, res_name
                        ])

                # IPv6
                for cidr in perm.get("Ipv6Ranges", []):
                    for res_type, res_id, res_name in sg_resources[sg_id]:
                        results.append([
                            region, sg_id, sg_name, protocol, port_range,
                            cidr.get("CidrIpv6", ""), "IPv6", res_type, res_id, res_name
                        ])

    except Exception as e:
        logging.error(f"Unexpected error in region {region}: {e}")

# ---------------- Save to CSV ----------------
try:
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(csv_header)
        writer.writerows(results)

    logging.info(f"CSV file saved: {OUTPUT_FILE}")
except Exception as e:
    logging.error(f"Failed to write CSV: {e}")
