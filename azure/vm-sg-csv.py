import subprocess
import json
import csv
from datetime import datetime, UTC

# ===================================================
# HARD-CODED DUMMY SERVICE PRINCIPAL CREDENTIALS
# ===================================================

CLIENT_ID = ""
CLIENT_SECRET = ""
TENANT_ID = ""

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

SUBSCRIPTION_NAME = ""
print(f"Setting subscription to: {SUBSCRIPTION_NAME}")

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
# GET ALL VMS IN SUBSCRIPTION
# ===================================================

print("Retrieving VMs...")

vms_raw = run("az vm list")
if isinstance(vms_raw, str):
    vms_raw = json.loads(vms_raw)

vms = []
for v in vms_raw:
    vms.append({
        "name": v.get("name"),
        "rg": v.get("resourceGroup"),
        "id": v.get("id")
    })

if not vms:
    print("No VMs found in subscription.")
    exit()

print(f"Found VMs: {[v['name'] for v in vms]}\n")


# ===================================================
# INIT OUTPUT FILES
# ===================================================

CSV_FILE = "vm_access_report.csv"
MD_FILE = "vm_access_report.md"

csv_headers = ["VM Name", "ResourceGroup", "Component", "Source", "Port", "Access", "Details"]
csv_file = open(CSV_FILE, "w", newline="", encoding="utf-8")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(csv_headers)

md = open(MD_FILE, "w", encoding="utf-8")
md.write("# VM Inbound Access Report\n")
md.write(f"Generated: {datetime.now(UTC)}\n\n")
md.write("---\n\n")

def add_record(vm, rg, component, source, port, access, details):
    csv_writer.writerow([vm, rg, component, source, port, access, details])
    md.write(f"- {component} | Source: {source} | Port: {port} | Access: {access} | Rule: {details}\n")


# ===================================================
# PROCESS EACH VM
# ===================================================

for vm in vms:
    name = vm["name"]
    rg = vm["rg"]

    print(f"Processing VM: {name} ({rg})")

    md.write(f"\n## VM: {name}\n")
    md.write(f"Resource Group: {rg}\n\n")

    # ================= PUBLIC IPs =================
    nic_data = run(f'az vm show -g "{rg}" -n "{name}" --show-details')
    if isinstance(nic_data, dict) and "publicIps" in nic_data:
        public_ip = nic_data["publicIps"]
        if public_ip:
            add_record(name, rg, "PublicIP", public_ip, "All", "Allow", "Direct Public Access")

    # ================= LOAD BALANCERS =================
    lbs = run(f'az network lb list -g "{rg}"')
    if not (isinstance(lbs, dict) and "error" in lbs):
        for lb in lbs:
            rules = run(f'az network lb rule list -g "{rg}" --lb-name "{lb["name"]}"')

            if isinstance(rules, dict) and "error" in rules:
                continue

            for r in rules:
                add_record(
                    name, rg, "LoadBalancer",
                    "LB Frontend",
                    f"{r.get('frontendPort')}/{r.get('backendPort')}",
                    "Allow",
                    r.get("name")
                )

    # ================= NSG RULES =================
    nics = run(f'az vm nic list -g "{rg}" --vm-name "{name}"')
    if isinstance(nics, dict) and "error" in nics:
        md.write("Cannot retrieve NICs.\n")
        continue

    for nic in nics:
        nic_name = nic["id"].split("/")[-1]

        nic_full = run(f'az network nic show -g "{rg}" -n "{nic_name}"')
        if isinstance(nic_full, dict) and "error" in nic_full:
            continue

        nsg = nic_full.get("networkSecurityGroup", {})
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

    # ================= EFFECTIVE NSG (NO PERMISSION) =================
    md.write("\nSkipping Effective NSG evaluation - Reader role cannot access effective NSGs.\n")

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
