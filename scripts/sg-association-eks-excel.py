import boto3
import botocore
import pandas as pd
from openpyxl import load_workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment
import datetime

# =======================
# CONFIGURATION VARIABLES
# =======================
AWS_PROFILE   = "aqcn"          # AWS CLI profile name
AWS_REGION    = "us-east-1"     # AWS region
CLUSTER_NAME  = ""              # Leave blank to prompt
MAX_THREADS   = 5               # Reserved for future multithreading

INBOUND_FILE  = ""
OUTBOUND_FILE = ""

# =======================
# CORE FUNCTIONS
# =======================

def input_with_default(prompt, default):
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else default

def create_session(profile, region):
    return boto3.Session(profile_name=profile, region_name=region)

def is_public_subnet(ec2, subnet_id):
    """Determine if subnet has an IGW route (public) or not (private)."""
    rtbs = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    ).get("RouteTables", [])

    if not rtbs:
        # fallback to route tables by VPC
        subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        vpc_id = subnet["VpcId"]
        rtbs = ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["RouteTables"]

    for rtb in rtbs:
        for route in rtb.get("Routes", []):
            if route.get("GatewayId", "").startswith("igw-"):
                return "Public"
    return "Private"

def merge_cells(workbook_path, sheet_name):
    """Merge repeated cells for better readability."""
    wb = load_workbook(workbook_path)
    ws = wb[sheet_name]
    merge_cols = [1, 2, 3, 4, 5, 6, 7]  # Region, SG ID, SG Name, SG Desc, Resource fields
    for col_idx in merge_cols:
        col_letter = get_column_letter(col_idx)
        start = 2
        prev = ws[f"{col_letter}2"].value
        for row in range(3, ws.max_row + 2):
            val = ws[f"{col_letter}{row}"].value
            if val != prev or row == ws.max_row + 1:
                if row - 1 > start:
                    ws.merge_cells(f"{col_letter}{start}:{col_letter}{row-1}")
                    ws[f"{col_letter}{start}"].alignment = Alignment(vertical="top")
                start = row
                prev = val
    wb.save(workbook_path)

# =======================
# MAIN LOGIC
# =======================

def main():
    global AWS_PROFILE, AWS_REGION, CLUSTER_NAME, INBOUND_FILE, OUTBOUND_FILE

    print("\n=== EKS Security Group Scanner ===\n")

    if not AWS_PROFILE:
        AWS_PROFILE = input_with_default("AWS profile", "default")
    if not AWS_REGION:
        AWS_REGION = input_with_default("Region (e.g. us-east-1)", "us-east-1")
    if not CLUSTER_NAME:
        CLUSTER_NAME = input("EKS cluster name: ").strip()

    date_str = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    if not INBOUND_FILE:
        INBOUND_FILE = f"eks_sg_{CLUSTER_NAME}_{AWS_REGION}_inbound.xlsx"
    if not OUTBOUND_FILE:
        OUTBOUND_FILE = f"eks_sg_{CLUSTER_NAME}_{AWS_REGION}_outbound.xlsx"

    print(f"\nProfile: {AWS_PROFILE}")
    print(f"Region: {AWS_REGION}")
    print(f"Cluster: {CLUSTER_NAME}")
    print(f"Inbound file: {INBOUND_FILE}")
    print(f"Outbound file: {OUTBOUND_FILE}\n")

    session = create_session(AWS_PROFILE, AWS_REGION)
    eks = session.client("eks")
    ec2 = session.client("ec2")

    # --- Fetch EKS Cluster ---
    print(f"Fetching cluster details for {CLUSTER_NAME}...")
    cluster_info = eks.describe_cluster(name=CLUSTER_NAME)["cluster"]
    vpc_id = cluster_info["resourcesVpcConfig"]["vpcId"]
    sg_ids = set(cluster_info["resourcesVpcConfig"]["securityGroupIds"])
    print(f"Cluster SGs: {', '.join(sg_ids)}")

    # --- Nodegroups ---
    print("Fetching nodegroups...")
    for ng in eks.list_nodegroups(clusterName=CLUSTER_NAME)["nodegroups"]:
        desc = eks.describe_nodegroup(clusterName=CLUSTER_NAME, nodegroupName=ng)["nodegroup"]
        sg_ids.update(desc["resources"]["securityGroups"])

    # --- Fargate Profiles ---
    print("Fetching Fargate profiles...")
    for fp in eks.list_fargate_profiles(clusterName=CLUSTER_NAME)["fargateProfileNames"]:
        desc = eks.describe_fargate_profile(clusterName=CLUSTER_NAME, fargateProfileName=fp)["fargateProfile"]
        for sg in desc.get("selectors", []):
            sg_ids.update(desc.get("podExecutionRoleArn", "").split())

    # --- ENIs ---
    print("Scanning EC2 network interfaces...")
    enis = ec2.describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": list(sg_ids)}]
    )["NetworkInterfaces"]

    inbound_data, outbound_data = [], []

    for eni in enis:
        subnet_id = eni["SubnetId"]
        subnet_type = is_public_subnet(ec2, subnet_id)
        subnet_info = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        subnet_name = next((t["Value"] for t in subnet_info.get("Tags", []) if t["Key"] == "Name"), "")
        resource_type = eni.get("InterfaceType", "eni")
        resource_id = eni["NetworkInterfaceId"]
        resource_name = eni.get("Description", "")

        for sg in eni["Groups"]:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]
            sg_details = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
            sg_desc = sg_details.get("Description", "")

            # Ingress
            for rule in sg_details.get("IpPermissions", []):
                proto = rule.get("IpProtocol", "all")
                port_from = rule.get("FromPort", "")
                port_to = rule.get("ToPort", "")
                port = f"{port_from}-{port_to}" if port_from != port_to else str(port_from)
                for ipr in rule.get("IpRanges", []):
                    inbound_data.append([
                        AWS_REGION, sg_id, sg_name, sg_desc,
                        resource_type, resource_id, resource_name,
                        s
