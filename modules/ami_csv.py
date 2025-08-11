import pandas as pd
import os

def ami_report_to_excel(ami_report, output_path="./logs/ami_audit.xlsx"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    all_data = []
    for region, amis in ami_report.items():
        for ami in amis:
            row = {"Region": region}
            row.update(ami)
            all_data.append(row)
    df = pd.DataFrame(all_data)
    df.to_excel(output_path, index=False)
