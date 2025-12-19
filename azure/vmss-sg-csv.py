import subprocess
import json
import csv
from datetime import datetime, UTC

# ===================================================
# HARD-CODED SERVICE PRINCIPAL CREDENTIALS
# ===================================================

CLIENT_ID = "0e08c3c0-0970-4e64-9f92-cb421f937c69"
CLIENT_SECRET = "BO58Q~~prMX-5Far9jpk06swf4nosSg2.zGceaVi"
TENANT_ID = "2c518df7-6644-41f8-8350-3f75e61362ac"

CLIENT_SECRET_ESCAPED = CLIENT_SECRET.replace('"', '\\"')

print("Authenticating with Azure using Service Principal...")

subprocess.run(
    f'az login --service-principal --username "{CLIENT_ID}" '
    f'--password "{CLIENT_SECRET_ESCAPED}" --tenant "{TENANT_ID}"',
    shell=True, check=True
)
print("Authentication successful.\n")

# ===================================================
# SET TARGET SUBSCRIPTION
# ===================================================

SUBSCRIPTION_NAME = "aqi-prod"

print(f"Setting subscription: {SUBSCRIPTION_NAME}")
subprocess.run(
    f'az account set --subscription "{SUBSCRIPTION_NAME}"',
    shell=True, check=True
)
print("Subscription set.\n")


# ===================================================
# HELPER FUNCTION TO RUN AZURE CLI
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
# GET ALL VM SCALE SETS
# ===================================================

print("Retrieving VM Scale Sets...")

vmss_raw = run("az vmss list")

if isinstance(vmss_raw, str):
    vmss_raw = json.loads(vmss_raw)

vmss_list = [{"name": v.get("name"), "rg": v.get("resourceGroup")} for v in vmss_raw]

if not vmss_list:
    print("No VM Scale Sets found.")
    exit()

print(f"Found VM Scale Sets: {[v['name'] for v in vmss_list]}\n")


# ===================================================
# INIT OUTPUT FILES
# ===================================================

CSV_FILE = "vmss_access_report.csv"
MD_FILE = "vmss_access_report.md"

csv_headers = ["VMSS Name", "ResourceGroup", "Component", "Source", "Port", "Access", "Details"]

csv_file = open(CSV_FILE, "w", newline="", encoding="utf-8")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(csv_headers)

md = open(MD_FILE, "w", encoding="utf-8")
md.write("# VM Scale Set Inbound Access Report\n")
md.write(f"Generated: {datetime.now(UTC)}\n\n")
md.write("---\n\n")

def add_record(vmss, rg, component, source, port, access, details):
    csv_writer.writerow([vmss, rg, component, source, port, access, details])
    md.write(f"- {component} | Source: {source} | Port: {port} | Access: {access} | Rule: {details}\n")


# ===================================================
# PROCESS EACH VM SCALE SET
# ===================================================

for vmss in vmss_list:
    name = vmss["name"]
    rg = vmss["rg"]

    print(f"Processing VM Scale Set: {name} ({rg})")

    md.write(f"\n## VM Scale Set: {name}\n")
    md.write(f"Resource Group: {rg}\n\n")

    # ================= LOAD BALANCERS =================
    lbs = run(f'az network lb list -g "{rg}"')

    if not (isinstance(lbs, dict) and "error" in lbs):
        for lb in lbs:
            rules = run(f'az network lb rule list -g "{rg}" --lb-name "{lb["name"]}"')

            if isinstance(rules, dict) and "error" in rules:
                continue

            for r in rules:
                add_record(
                    name, rg, "LoadBalancer", "LB Frontend",
                    f"{r.get('frontendPort')}/{r.get('backendPort')}",
                    "Allow",
                    r.get("name")
                )

    # ================= NSG RULES =================
    nic_ids = run(f'az vmss nic list -g "{rg}" --vmss-name "{name}"')

    if isinstance(nic_ids, dict) and "error" in nic_ids:
        md.write("Cannot retrieve NICs for this VMSS.\n")
        continue

    for nic in nic_ids:
        nic_name = nic["id"].split("/")[-1]

        nic_data = run(f'az network nic show -g "{rg}" -n "{nic_name}"')

        if isinstance(nic_data, dict) and "error" in nic_data:
            continue

        nsg = nic_data.get("networkSecurityGroup")

        if nsg:
            nsg_name = nsg["id"].split("/")[-1]

            nsg_data = run(f'az network nsg show -g "{rg}" -n "{nsg_name}"')

            if isinstance(nsg_data, dict) and "error" not in nsg_data:
                for r in nsg_data.get("securityRules", []):
                    add_record(
                        name, rg, "NSG",
                        r.get("sourceAddressPrefix"),
                        r.get("destinationPortRange"),
                        r.get("access"),
                        r.get("name")
                    )

    # ================= EFFECTIVE NSG — SKIPPED (Reader role) =================
    md.write("\nSkipping Effective NSG evaluation - insufficient permissions (Reader role).\n")

    # ================= VNET PEERING =================
    vnets = run(f'az network vnet list -g "{rg}"')

    if isinstance(vnets, dict) and "error" in vnets:
        continue

    for vnet in vnets:
        peers = run(f'az network vnet peering list -g "{rg}" --vnet-name "{vnet["name"]}"')

        if isinstance(peers, dict) and "error" in peers:
            continue

        for p in peers:
            add_record(
                name, rg, "VNetPeering",
                p.get("remoteVirtualNetwork", {}).get("id"),
                "-",
                "Allow" if p.get("allowVirtualNetworkAccess") else "Deny",
                p.get("name")
            )

    # ================= VPN CONNECTIONS =================
    vpns = run(f'az network vpn-connection list -g "{rg}"')

    if not (isinstance(vpns, dict) and "error" in vpns):
        for v in vpns:
            add_record(
                name, rg, "VPN",
                v.get("remoteVpnSite", {}).get("id"),
                "-",
                v.get("connectionType"),
                v.get("name")
            )


# ===================================================
# SAVE OUTPUT
# ===================================================

csv_file.close()
md.close()

print("\n===================================================")
print(f"CSV Output Saved: {CSV_FILE}")
print(f"Markdown Output Saved: {MD_FILE}")
print("===================================================")
