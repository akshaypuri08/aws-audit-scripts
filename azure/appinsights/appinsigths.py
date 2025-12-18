import pandas as pd
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient
from tenacity import retry, stop_after_attempt, wait_exponential
import traceback

# ===============================
# CONFIGURATION
# ===============================

CONFIG = {
    "tenant_id": "2c518df7-6644-41f8-8350-3f75e61362ac",
    "client_id": "0e08c3c0-0970-4e64-9f92-cb421f937c69",
    "client_secret": "",
    "workspaces": {
        "app1_us_east": "47640420-7b89-4dfd-8814-0840703bc498",
    },
    "tables": [
        "customMetrics",
        "requests",
        "dependencies",
        "exceptions",
        "traces",
        "availabilityResults",
        "pageViews",
        "browserTimings"
    ],
    "start_date": "2025-01-01",
    "end_date": "2025-09-30",
    "max_workers": 5
}

# ===============================
# AUTH & CLIENT
# ===============================

print("🔐 Authenticating with Azure...")
credential = ClientSecretCredential(
    tenant_id=CONFIG["tenant_id"],
    client_id=CONFIG["client_id"],
    client_secret=CONFIG["client_secret"]
)
client = LogsQueryClient(credential)

# ===============================
# HELPER FUNCTIONS
# ===============================

def generate_date_ranges(start_date, end_date):
    ranges = []
    current = start_date
    while current < end_date:
        next_day = current + timedelta(days=1)
        ranges.append((current, next_day))
        current = next_day
    return ranges


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=4, max=20))
def query_logs(workspace_id, query, table, start, end):
    result = client.query_workspace(
        workspace_id,
        query,
        timespan=(start, end)
    )

    if not result.tables:
        print(f"[WARN] No data for {table} ({start.date()} → {end.date()})")
        return pd.DataFrame()

    df = pd.DataFrame(result.tables[0].rows, columns=[col.name for col in result.tables[0].columns])
    print(f"[OK] {table}: {len(df)} rows for {start.date()}")
    return df


def process_table(workspace_name, workspace_id, table, start_date, end_date):
    try:
        date_ranges = generate_date_ranges(start_date, end_date)
        output_filename = f"{table}_{start_date.date()}_{end_date.date()}.xlsx"
        all_data = []

        print(f"▶️ Exporting {workspace_name} - {table} ({start_date.date()} → {end_date.date()})")

        for start, end in date_ranges:
            query = f"{table} | where timestamp >= datetime({start}) and timestamp < datetime({end})"
            try:
                df = query_logs(workspace_id, query, table, start, end)
                if not df.empty:
                    all_data.append(df)
            except Exception as e:
                print(f"[ERROR] Failed {table} for {start.date()} → {end.date()}: {e}")
                traceback.print_exc()

        if all_data:
            final_df = pd.concat(all_data, ignore_index=True)
            final_df.to_excel(output_filename, index=False)
            print(f"✅ Saved {output_filename} ({len(final_df)} rows)")
        else:
            print(f"[INFO] No data collected for {table}")

    except Exception as e:
        print(f"[FATAL] Error processing {workspace_name}:{table} → {e}")
        traceback.print_exc()


# ===============================
# MAIN EXECUTION
# ===============================

def main():
    start_date = datetime.fromisoformat(CONFIG["start_date"])
    end_date = datetime.fromisoformat(CONFIG["end_date"])

    print("🚀 Starting parallel Application Insights export...")

    tasks = []
    with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
        for workspace_name, workspace_id in CONFIG["workspaces"].items():
            for table in CONFIG["tables"]:
                tasks.append(executor.submit(process_table, workspace_name, workspace_id, table, start_date, end_date))

        for future in as_completed(tasks):
            try:
                future.result()
            except Exception as e:
                print(f"[ERROR] Task failed: {e}")

    print("✅ All exports completed.")


if __name__ == "__main__":
    main()
