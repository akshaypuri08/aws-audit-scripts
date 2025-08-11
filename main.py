from fastapi import FastAPI, Query
import boto3
from modules.nacl_review import audit_nacls
from modules.ami_audit import audit_amis

app = FastAPI(
    title="AWS Audit Tool",
    version="1.0",
    description="Audits AWS NACL and AMI configurations across all available regions."
)

@app.get("/")
async def root():
    return {
        "message": "Welcome to the AWS Audit API",
        "usage_examples": [
            "GET /nacl?profile=<aws_profile_name>",
            "GET /ami?profile=<aws_profile_name>"
        ],
        "note": "Ensure AWS CLI profiles are configured properly in ~/.aws/credentials."
    }

@app.get("/nacl")
def run_nacl_audit(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    return audit_nacls(session, profile)

@app.get("/ami")
def run_ami_audit(profile: str = Query(..., description="AWS CLI profile name")):
    session = boto3.Session(profile_name=profile)
    return audit_amis(session, profile)
