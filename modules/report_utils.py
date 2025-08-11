import csv
from openpyxl import Workbook
from datetime import datetime
import os

def save_to_csv(headers, rows, prefix, logger):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{prefix}_report_{timestamp}.csv"
    os.makedirs("reports", exist_ok=True)

    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    logger.info(f"CSV report saved: {filename}")
    return filename

def save_to_excel(headers, rows, prefix, logger):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{prefix}_report_{timestamp}.xlsx"
    os.makedirs("reports", exist_ok=True)

    wb = Workbook()
    ws = wb.active
    ws.append(headers)
    for row in rows:
        ws.append(row)

    wb.save(filename)
    logger.info(f"Excel report saved: {filename}")
    return filename
