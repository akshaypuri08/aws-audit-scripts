import subprocess
import json
import csv
from datetime import datetime, UTC

# ===================================================
# HARD-CODED DUMMY SERVICE PRINCIPAL CREDENTIALS
# ===================================================

CLIENT_ID = "0e08c3c0-0970-4e64-9f92-cb421f937c69"
CLIENT_SECRET = ""
TENANT_ID = "2c518df7-6644-41f8-8350-3f75e61362ac"

CLIENT_SECRET_ESCAPED = CLIENT_SECRET.replace('"', '\\"')

print("Authenticating with Azure using Service Principal...")

login_cmd = (
    f'az login --service-principal '
    f'--username "{CLIENT_ID}" '
    f'--password "{CLIENT_SECRET_ESCAPED}" '
    f'--tenant "{TENANT_ID}"'
)

subprocess.run(login_cmd, shell=True, check=True)
print("Authentication successful.\n")

# ===================================================
# SET TARGET SUBSCRIPTION (aqi-prod)
# ===================================================

SUBSCRIPTION_NAME = "aqi-prod"
print(f"Setting subscription: {SUBSCRIPTION_NAME}")

subprocess.run(
    f'az account set --subscription "{SUBSCRIPTION_NAME}"',
    shell=True, check=True
)

print("Subscription set.\n")

# ===================================================
# HELPER FUNCTION
# ===================================================

def run(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        try:
            return json.loads(out)
        except:
            return out
    except subprocess.CalledProcessError as e:
        return {"error": e.output}

# ===================================================
# GET SERVICE FABRIC CLUSTERS
# ===================================================

print("Retrieving Service Fabric clusters...")

clusters_raw = run("az sf cluster list")

if isinstance(clusters_raw, str):
    clusters_raw = json.loads(clusters_raw)

clusters = [{"name": c.get("name"), "rg": c.get("resourceGroup")} for c in clusters_raw]

if not clusters:
    print("No Service Fabric clusters found.")
    exit()

print(f"Found clusters: {[c['name'] for c in clusters]}\n")

# ===================================================
# INIT OUTPUT FILES
# ===================================================

CSV_FILE = "sf_inbound_access_report.csv"
MD_FILE = "sf_inbound_access_report.md"

csv_headers = ["Cluster", "ResourceGroup", "Component", "Source", "Port", "Access", "Details"]
csv_file = open(CSV_FILE, "w", newline="", encoding="utf-8")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(csv_headers)

md = open(MD_FILE, "w", encoding="utf-8")
md.write("# Service Fabric Inbound Access Security Report\n")
md.write(f"Generated: {datetime.now(UTC)}\n\n")
md.write("---\n\n")

def add_record(cluster, rg, component, source, port, access, details):
    csv_writer.writerow([cluster, rg, component, source, port, access, details])
    md.write(f"- {component} | Source: {source} | Port: {port} | Access: {access} | Rule: {details}\n")

# ===================================================
# PROCESS EACH CLUSTER
# ===================================================

for c in clusters:
    cluster = c["name"]
    rg = c["rg"]

    print(f"Processing cluster: {cluster} ({rg})")
    
    md.write(f"\n## Cluster: {cluster}\n")
    md.write(f"Resource Group: {rg}\n\n")

    # ================= LOAD BALANCERS =================
    lbs = run(f'az network lb list -g "{rg}"')
    if isinstance(lbs, dict) and "error" in lbs:
        md.write("\nCould not retrieve Load Balancers due to insufficient permissions.\n")
        continue

    for lb in lbs:
        lb_name = lb["name"]
        rules = run(f'az network lb rule list -g "{rg}" --lb-name "{lb_name}"')

        if isinstance(rules, dict) and "error" in rules:
            md.write("Cannot read Load Balancer rules.\n")
            continue

        for r in rules:
            add_record(cluster, rg, "LoadBalancer", "LB-Frontend",
                       f"{r.get('frontendPort')}/{r.get('backendPort')}",
                       "Allow", r.get("name"))

    # ================= NSG RULES =================
    nsgs = run(f'az network nsg list -g "{rg}"')
    if isinstance(nsgs, dict) and "error" in nsgs:
        md.write("\nCannot retrieve NSGs.\n")
        continue

    for nsg in nsgs:
        md.write(f"\n### NSG: {nsg['name']}\n")

        nsg_data = run(f'az network nsg show -g "{rg}" -n "{nsg["name"]}"')

        if isinstance(nsg_data, dict) and "error" in nsg_data:
            md.write("Cannot read NSG rules.\n")
            continue

        for r in nsg_data.get("securityRules", []):
            add_record(cluster, rg, "NSG",
                       r.get("sourceAddressPrefix"),
                       r.get("destinationPortRange"),
                       r.get("access"),
                       r.get("name"))

    # ================= EFFECTIVE NSG (SKIPPED FOR READER ROLE) =================
    md.write("\nSkipping Effective NSG evaluation - insufficient permissions (Reader role).\n")

    # ================= VNET PEERING =================
    vnets = run(f'az network vnet list -g "{rg}"')
    if isinstance(vnets, dict) and "error" in vnets:
        md.write("\nCannot retrieve VNets.\n")
        continue

    for vnet in vnets:
        peers = run(f'az network vnet peering list -g "{rg}" --vnet-name "{vnet["name"]}"')

        if isinstance(peers, dict) and "error" in peers:
            md.write("Cannot read VNet peerings.\n")
            continue

        for p in peers:
            add_record(cluster, rg, "VNetPeering",
                       p.get("remoteVirtualNetwork", {}).get("id"),
                       "-",
                       "Allow" if p.get("allowVirtualNetworkAccess") else "Deny",
                       p.get("name"))

    # ================= VPN CONNECTIONS =================
    vpns = run(f'az network vpn-connection list -g "{rg}"')

    if isinstance(vpns, dict) and "error" in vpns:
        md.write("\nCannot retrieve VPN connections.\n")
        continue

    for v in vpns:
        add_record(cluster, rg, "VPN",
                   v.get("remoteVpnSite", {}).get("id"),
                   "-",
                   v.get("connectionType"),
                   v.get("name"))

# ===================================================
# SAVE OUTPUT
# ===================================================

csv_file.close()
md.close()

print("\n===================================================")
print(f"CSV Output Saved: {CSV_FILE}")
print(f"Markdown Output Saved: {MD_FILE}")
print("===================================================")
