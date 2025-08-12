from fastapi import FastAPI, Query
import boto3
import logging
import os
from modules.nacl_review import audit_nacls
from modules.ami_audit import audit_amis
from modules.ami_csv import ami_report_to_excel
from modules.sg_audit_all_ports import audit_security_groups_all_ports  # NEW import

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Logger setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("./logs/app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI()

@app.get("/")
async def root():
    return {
        "message": "Welcome to the AWS Audit API 🚀",
        "usage_examples": [
            "GET /nacl?profile=<aws_profile_name>",
            "GET /ami?profile=<aws_profile_name>",
            "GET /sg?profile=<aws_profile_name>"  # Added example
        ],
        "note": "Ensure AWS CLI profiles are configured properly."
    }

@app.get("/nacl")
async def nacl_audit(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    logger.info(f"Running NACL audit for profile: {profile}")
    report = audit_nacls(session, profile)
    return {"profile": profile, "nacl_report": report}

@app.get("/ami")
async def ami_audit(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    logger.info(f"Running AMI audit for profile: {profile}")
    report = audit_amis(session, profile)
    output_path = "./logs/ami_audit.xlsx"
    ami_report_to_excel(report, output_path)
    logger.info(f"AMI audit exported to {output_path}")
    return {"message": f"CSV export complete. File saved to {output_path}"}

@app.get("/sg")
async def sg_audit_all_ports(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    logger.info(f"Running Security Group all-ports audit for profile: {profile}")
    report = audit_security_groups_all_ports(session, profile)
    logger.info(f"Security Group all-ports audit complete. CSV saved to {report['csv_report']}")
    return {
        "message": f"Security Group audit complete. {report['rows_found']} records found.",
        "csv_file": report["csv_report"]

        
    }

@app.get("/sg2")
async def sg_audit_all_ports(profile: str = Query(..., description="AWS CLI profile name")):
    print(f"[DEBUG] Received request to run SG audit for profile: {profile}")  # Console log

    session = boto3.Session(profile_name=profile)
    logger.info(f"Running Security Group all-ports audit for profile: {profile}")

    print("[DEBUG] Starting SG audit function...")  # Console log
    report = audit_security_groups_all_ports(session, profile)
    print("[DEBUG] SG audit function completed.")  # Console log

    logger.info(f"Security Group all-ports audit complete. CSV saved to {report['csv_report']}")
    print(f"[DEBUG] CSV file saved at: {report['csv_report']}")  # Console log
    print(f"[DEBUG] Total records found: {report['rows_found']}")  # Console log

    return {
        "message": f"Security Group audit complete. {report['rows_found']} records found.",
        "csv_file": report["csv_report"]
    }

