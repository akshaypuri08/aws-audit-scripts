from fastapi import FastAPI, Query
import boto3
import logging
from modules import nacl_review, ami_audit

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

app = FastAPI(title="AWS Audit API")

@app.get("/")
async def root():
    return {
        "message": "Welcome to the AWS Audit API",
        "usage_examples": [
            "GET /nacl?profile=<aws_profile_name>",
            "GET /ami?profile=<aws_profile_name>"
        ],
        "note": "Ensure AWS CLI profiles are configured properly."
    }

@app.get("/nacl")
async def audit_nacl(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    return nacl_review.audit_nacls(session, profile)

@app.get("/ami")
async def audit_ami(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    return ami_audit.audit_amis(session, profile)
