import requests
import pandas as pd
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# === CONFIGURATION ===
TENANT_ID = "2c518df7-6644-41f8-8350-3f75e61362ac"
CLIENT_ID = "0e08c3c0-0970-4e64-9f92-cb421f937c69"
CLIENT_SECRET = ""
APP_ID= "e2cf410e-2ed8-40e9-9427-c4593dc82b9f"

START_DATE = datetime(2024, 8, 1)
END_DATE = datetime(2024, 8, 31)
OUTPUT_FILE = "performance_counters_august.csv"
MAX_WORKERS = 5  # Number of days fetched in parallel


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
    resp.raise_for_status()
    return resp.json()


def daterange(start, end):
    """Generate one-day ranges."""
    current = start
    while current <= end:
        yield current, current + timedelta(days=1) - timedelta(seconds=1)
        current += timedelta(days=1)


def fetch_day(token, app_id, start, end):
    """Fetch performance counters for a single day."""
    start_str = start.strftime("%Y-%m-%dT00:00:00Z")
    end_str = end.strftime("%Y-%m-%dT23:59:59Z")

    # 👇 Query performanceCounters table
    query = (
        "AppPerformanceCounters "
        f"| where timestamp >= datetime('{start_str}') "
        f"| where timestamp <= datetime('{end_str}') "
        "| project timestamp, name, category, counter, instance, value "
        "| order by timestamp asc"
    )

    try:
        result = run_query(token, app_id, query)
        if "tables" in result and result["tables"]:
            table = result["tables"][0]
            columns = [col["name"] for col in table["columns"]]
            rows = table["rows"]
            if rows:
                df = pd.DataFrame(rows, columns=columns)
                print(f"✅ {start.strftime('%Y-%m-%d')} - {len(df)} rows")
                return df
            else:
                print(f"⚠️ {start.strftime('%Y-%m-%d')} - no data")
    except Exception as e:
        print(f"❌ Error fetching {start.strftime('%Y-%m-%d')}: {e}")
    return None


def main():
    print("🔐 Authenticating to Azure...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    print("🚀 Starting parallel fetch for performanceCounters...")
    all_data = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_day, token, APP_ID, start, end): start
            for start, end in daterange(START_DATE, END_DATE)
        }

        for future in as_completed(futures):
            df = future.result()
            if df is not None:
                all_data.append(df)

    if all_data:
        final_df = pd.concat(all_data, ignore_index=True)
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n✅ Export complete: {OUTPUT_FILE} ({len(final_df)} total rows)")
    else:
        print("\n⚠️ No data retrieved for any date range.")


if __name__ == "__main__":
    main()
