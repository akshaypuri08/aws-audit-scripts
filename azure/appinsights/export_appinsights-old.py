import requests
import pandas as pd
from datetime import datetime, timedelta

# === CONFIGURATION ===
TENANT_ID = "2c518df7-6644-41f8-8350-3f75e61362ac"
CLIENT_ID = "0e08c3c0-0970-4e64-9f92-cb421f937c69"
CLIENT_SECRET = ""
APP_ID= "e2cf410e-2ed8-40e9-9427-c4593dc82b9f"

START_DATE = datetime(2025, 8, 1)
END_DATE = datetime(2025, 8, 31)
OUTPUT_FILE = "requests_26oct.csv"


def get_token(tenant_id, client_id, client_secret):
    """Authenticate with Azure AD and get token for Application Insights API."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://api.applicationinsights.io/.default",
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


def run_query(token, app_id, query):
    """Run a Kusto query against the Application Insights Query API."""
    url = f"https://api.applicationinsights.io/v1/apps/{app_id}/query"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, params={"query": query})
    if resp.status_code != 200:
        print(f"❌ Query failed with status {resp.status_code}: {resp.text}")
    resp.raise_for_status()
    return resp.json()


def daterange(start, end):
    """Generate one-day ranges."""
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
            "performanceCounters "
            f"| where timestamp >= datetime('{start_str}') "
            f"| where timestamp <= datetime('{end_str}')"
        )

        print(f"📅 Fetching data for {start.strftime('%Y-%m-%d')} ...")
        result = run_query(token, APP_ID, query)

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

    if all_data:
        final_df = pd.concat(all_data, ignore_index=True)
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n✅ Export complete: {OUTPUT_FILE} ({len(final_df)} rows)")
    else:
        print("\n⚠️ No data retrieved for any date range.")


if __name__ == "__main__":
    main()
