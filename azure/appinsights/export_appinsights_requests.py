import requests
import pandas as pd
from datetime import datetime, timedelta

# === CONFIGURATION ===
WORKSPACE_ID = "47640420-7b89-4dfd-8814-0840703bc498"  # Log Analytics workspace ID
TENANT_ID = "2c518df7-6644-41f8-8350-3f75e61362ac"
CLIENT_ID = "0e08c3c0-0970-4e64-9f92-cb421f937c69"
CLIENT_SECRET = ""

START_DATE = datetime(2024, 8, 1)
END_DATE = datetime(2024, 8, 31)
OUTPUT_FILE = "requests_august.csv"


def get_token(tenant_id, client_id, client_secret):
    """Authenticate with Azure AD and get access token."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://api.loganalytics.io/.default",
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


def run_query(token, workspace_id, query):
    """Execute Kusto query against Log Analytics workspace."""
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    resp = requests.post(url, headers=headers, json={"query": query})
    if resp.status_code != 200:
        print(f"❌ Query failed with status {resp.status_code}: {resp.text}")
    resp.raise_for_status()
    return resp.json()


def daterange(start, end):
    """Generate (start, end) tuples for each day."""
    current = start
    while current <= end:
        yield current, current + timedelta(days=1) - timedelta(seconds=1)
        current += timedelta(days=1)


def main():
    print("🔐 Authenticating to Azure...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    all_data = []

    for start, end in daterange(START_DATE, END_DATE):
        start_str = start.strftime("%Y-%m-%dT00:00:00Z")
        end_str = end.strftime("%Y-%m-%dT23:59:59Z")

        query = (
            "AppRequests"
            f"| where timestamp >= datetime('{start_str}') "
            f"| where timestamp <= datetime('{end_str}')"
        )

        print(f"📅 Fetching data for {start.strftime('%Y-%m-%d')} ...")

        result = run_query(token, WORKSPACE_ID, query)

        if "tables" in result and result["tables"]:
            table = result["tables"][0]
            columns = [col["name"] for col in table["columns"]]
            rows = table["rows"]

            if rows:
                df = pd.DataFrame(rows, columns=columns)
                all_data.append(df)
                print(f"   ✅ Retrieved {len(df)} rows")
            else:
                print(f"   ⚠️ No data found")
        else:
            print(f"   ⚠️ No tables in result")

    if all_data:
        final_df = pd.concat(all_data, ignore_index=True)
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n✅ Export complete: {OUTPUT_FILE} ({len(final_df)} total rows)")
    else:
        print("\n⚠️ No data retrieved for any date range.")


if __name__ == "__main__":
    main()
