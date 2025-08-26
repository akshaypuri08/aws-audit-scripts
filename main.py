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
@app.get("/sgport")
async def sg_audit_selected_ports(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    logger.info(f"Running Security Group selected-ports audit for profile: {profile}")
    report = audit_security_groups_selected_ports(session, profile)
    if report.get("csv_report"):
        logger.info(f"Selected-ports audit complete. CSV saved to {report['csv_report']}")
    else:
        logger.error(f"Selected-ports audit failed: {report.get('error')}")
    return {
        "message": f"Security Group selected-port audit complete. {report.get('rows_found',0)} records found.",
        "csv_file": report.get("csv_report"),
        "error": report.get("error")
    }

