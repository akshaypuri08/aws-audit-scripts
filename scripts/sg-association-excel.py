import boto3
import pandas as pd
from openpyxl import load_workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment

# -------------------------
# CONFIG
# -------------------------
AWS_PROFILE = "aqcn"   # Change this
TARGET_PORTS = {20, 21, 22, 3389, 5432}
INBOUND_FILE = "sg_inbound_rules.xlsx"
OUTBOUND_FILE = "sg_outbound_rules.xlsx"
# -------------------------

session = boto3.Session(profile_name=AWS_PROFILE)
ec2_client = session.client("ec2")


def merge_cells_excel(file_path):
    """Merge repeated cells in Excel for readability"""
    wb = load_workbook(file_path)
    ws = wb.active

    for col in range(1, ws.max_column + 1):
        col_letter = get_column_letter(col)
        start_row = 2
        prev_val = ws[f"{col_letter}{start_row}"].value
        merge_start = start_row

        for row in range(start_row + 1, ws.max_row + 1):
            val = ws[f"{col_letter}{row}"].value
            if val != prev_val:
                if merge_start < row - 1 and prev_val is not None:
                    ws.merge_cells(f"{col_letter}{merge_start}:{col_letter}{row - 1}")
                    ws[f"{col_letter}{merge_start}"].alignment = Alignment(vertical="center", horizontal="center")
                merge_start = row
                prev_val = val
        if merge_start < ws.max_row and prev_val is not None:
            ws.merge_cells(f"{col_letter}{merge_start}:{col_letter}{ws.max_row}")
            ws[f"{col_letter}{merge_start}"].alignment = Alignment(vertical="center", horizontal="center")

    wb.save(file_path)


def rule_matches_ports(rule):
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return any(from_port <= port <= to_port for port in TARGET_PORTS)


def collect_rules(sg, direction="inbound"):
    rules = sg["IpPermissions"] if direction == "inbound" else sg["IpPermissionsEgress"]
    results = []
    for rule in rules:
        if not rule_matches_ports(rule):
            continue
        ip_protocol = rule.get("IpProtocol")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        for ip_range in rule.get("IpRanges", []):
            results.append((ip_protocol, from_port, to_port, ip_range["CidrIp"], "IPv4", ip_range.get("Description", "")))
        for ip_range in rule.get("Ipv6Ranges", []):
            results.append((ip_protocol, from_port, to_port, ip_range["CidrIpv6"], "IPv6", ip_range.get("Description", "")))
    return results


def get_resource_associations(region, sg_id):
    """Collect resources associated with a Security Group"""
    resources = []
    ec2 = session.client("ec2", region_name=region)

    # EC2 instances
    reservations = ec2.describe_instances(Filters=[{"Name": "instance.group-id", "Values": [sg_id]}])["Reservations"]
    for res in reservations:
        for inst in res["Instances"]:
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
            resources.append(("EC2", inst["InstanceId"], name))

    # ENIs
    enis = ec2.describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [sg_id]}])["NetworkInterfaces"]
    for eni in enis:
        desc = eni.get("Description", "")
        name = next((t["Value"] for t in eni.get("TagSet", []) if t["Key"] == "Name"), "")
        resources.append(("ENI", eni["NetworkInterfaceId"], desc or name))

    # Classic ELB
    elb = session.client("elb", region_name=region)
    try:
        for lb in elb.describe_load_balancers()["LoadBalancerDescriptions"]:
            if sg_id in lb.get("SecurityGroups", []):
                resources.append(("ELB", lb["LoadBalancerName"], lb.get("DNSName", "")))
    except:
        pass

    # ALB/NLB
    elbv2 = session.client("elbv2", region_name=region)
    try:
        for lb in elbv2.describe_load_balancers()["LoadBalancers"]:
            if sg_id in lb.get("SecurityGroups", []):
                resources.append(("ALB/NLB", lb["LoadBalancerName"], lb.get("DNSName", "")))
    except:
        pass

    # RDS
    rds = session.client("rds", region_name=region)
    try:
        for db in rds.describe_db_instances()["DBInstances"]:
            for vpcsg in db["VpcSecurityGroups"]:
                if vpcsg["VpcSecurityGroupId"] == sg_id:
                    name = next((t["Value"] for t in db.get("TagList", []) if t["Key"] == "Name"), "")
                    resources.append(("RDS Instance", db["DBInstanceIdentifier"], name))
        for cluster in rds.describe_db_clusters()["DBClusters"]:
            for vpcsg in cluster["VpcSecurityGroups"]:
                if vpcsg["VpcSecurityGroupId"] == sg_id:
                    resources.append(("RDS Cluster", cluster["DBClusterIdentifier"], ""))
    except:
        pass

    # ElastiCache
    elasticache = session.client("elasticache", region_name=region)
    try:
        clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True)["CacheClusters"]
        for cl in clusters:
            for vpcsg in cl.get("SecurityGroups", []):
                if vpcsg["SecurityGroupId"] == sg_id:
                    resources.append(("ElastiCache", cl["CacheClusterId"], ""))
    except:
        pass

    # Redshift
    redshift = session.client("redshift", region_name=region)
    try:
        for cluster in redshift.describe_clusters()["Clusters"]:
            for vpcsg in cluster.get("VpcSecurityGroups", []):
                if vpcsg["VpcSecurityGroupId"] == sg_id:
                    resources.append(("Redshift", cluster["ClusterIdentifier"], ""))
    except:
        pass

    # EFS
    efs = session.client("efs", region_name=region)
    try:
        for fs in efs.describe_file_systems()["FileSystems"]:
            mnts = efs.describe_mount_targets(FileSystemId=fs["FileSystemId"])["MountTargets"]
            for m in mnts:
                sg_list = efs.describe_mount_target_security_groups(MountTargetId=m["MountTargetId"])["SecurityGroups"]
                if sg_id in sg_list:
                    resources.append(("EFS", fs["FileSystemId"], ""))
    except:
        pass

    # MQ
    mq = session.client("mq", region_name=region)
    try:
        for broker in mq.list_brokers()["BrokerSummaries"]:
            details = mq.describe_broker(BrokerId=broker["BrokerId"])
            for vpcsg in details.get("SecurityGroups", []):
                if vpcsg == sg_id:
                    resources.append(("MQ", broker["BrokerName"], ""))
    except:
        pass

    # SageMaker
    sm = session.client("sagemaker", region_name=region)
    try:
        for nb in sm.list_notebook_instances()["NotebookInstances"]:
            details = sm.describe_notebook_instance(NotebookInstanceName=nb["NotebookInstanceName"])
            for vpcsg in details.get("SecurityGroups", []):
                if vpcsg == sg_id:
                    resources.append(("SageMaker Notebook", nb["NotebookInstanceName"], ""))
        for ep in sm.list_endpoints()["Endpoints"]:
            details = sm.describe_endpoint(EndpointName=ep["EndpointName"])
            for vpcsg in details.get("VpcConfig", {}).get("SecurityGroupIds", []):
                if vpcsg == sg_id:
                    resources.append(("SageMaker Endpoint", ep["EndpointName"], ""))
    except:
        pass

    # Lambda (VPC-enabled)
    lambda_client = session.client("lambda", region_name=region)
    try:
        for fn in lambda_client.list_functions()["Functions"]:
            cfg = lambda_client.get_function_configuration(FunctionName=fn["FunctionName"])
            for sg in cfg.get("VpcConfig", {}).get("SecurityGroupIds", []):
                if sg == sg_id:
                    resources.append(("Lambda", fn["FunctionName"], ""))
    except:
        pass

    # MSK
    msk = session.client("kafka", region_name=region)
    try:
        for cluster in msk.list_clusters()["ClusterInfoList"]:
            details = msk.describe_cluster(ClusterArn=cluster["ClusterArn"])["ClusterInfo"]
            for sg in details.get("BrokerNodeGroupInfo", {}).get("ClientSubnets", []):
                if sg == sg_id:
                    resources.append(("MSK", cluster["ClusterName"], ""))
    except:
        pass

    # You can continue adding similar blocks for Glue, App Runner, Transit Gateway, DocumentDB, OpenSearch, DMS, Neptune, WorkSpaces, AppStream, DataSync
    # by using the corresponding boto3 clients and checking VPC security groups / ENIs.

    return resources


def main():
    inbound_data = []
    outbound_data = []
    regions = [r["RegionName"] for r in ec2_client.describe_regions()["Regions"]]

    for region in regions:
        print(f"Scanning region: {region}")
        ec2 = session.client("ec2", region_name=region)
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            sg_desc = sg.get("Description", "")
            resources = get_resource_associations(region, sg_id)
            if not resources:
                continue
            inbound_rules = collect_rules(sg, "inbound")
            outbound_rules = collect_rules(sg, "outbound")
            for res_type, res_id, res_name in resources:
                for proto, fport, tport, cidr, ip_ver, desc in inbound_rules:
                    inbound_data.append([region, sg_id, sg_name, sg_desc, res_type, res_id, res_name,
                                         proto, fport, tport, cidr, ip_ver, desc])
                for proto, fport, tport, cidr, ip_ver, desc in outbound_rules:
                    outbound_data.append([region, sg_id, sg_name, sg_desc, res_type, res_id, res_name,
                                          proto, fport, tport, cidr, ip_ver, desc])

    inbound_df = pd.DataFrame(inbound_data, columns=[
        "Region", "SG ID", "SG Name", "SG Description", "Resource Type", "Resource ID", "Resource Name",
        "Protocol", "FromPort", "ToPort", "CIDR", "IP Version", "Rule Description"])
    outbound_df = pd.DataFrame(outbound_data, columns=inbound_df.columns)

    inbound_df.to_excel(INBOUND_FILE, index=False)
    outbound_df.to_excel(OUTBOUND_FILE, index=False)

    merge_cells_excel(INBOUND_FILE)
    merge_cells_excel(OUTBOUND_FILE)
    print(f"Exported results to {INBOUND_FILE} and {OUTBOUND_FILE}")


if __name__ == "__main__":
    main()
