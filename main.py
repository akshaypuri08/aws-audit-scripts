from fastapi import FastAPI, Query
import boto3
from modules.nacl_review import review_nacls
from modules.ec2_ami_audit import audit_amis

app = FastAPI()

def get_session(profile_name: str):
    return boto3.Session(profile_name=profile_name)

def get_all_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r['RegionName'] for r in response['Regions']]

@app.get("/nacl")
def run_nacl(profile: str = Query(..., description="AWS profile name")):
    session = get_session(profile)
    for region in get_all_regions(session):
        review_nacls(session, region)
    return {"status": "NACL audit completed"}

@app.get("/ami")
def run_ami(profile: str = Query(..., description="AWS profile name")):
    session = get_session(profile)
    for region in get_all_regions(session):
        audit_amis(session, region)
    return {"status": "AMI audit completed"}
