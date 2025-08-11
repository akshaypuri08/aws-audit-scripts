from fastapi import FastAPI, Request
import boto3
from modules.ami_audit import audit_amis
from modules.ami_csv import ami_report_to_excel
import botocore

app = FastAPI()

@app.get("/ami")
async def ami_audit(profile: str):
    try:
        session = boto3.Session(profile_name=profile)
        report = audit_amis(session, profile)
        ami_report_to_excel(report, profile)
        return {"message": f"CSV export done for profile {profile}"}
    except botocore.exceptions.ClientError as e:
        return {"error": f"AWS ClientError: {e.response['Error']['Code']} - {e.response['Error']['Message']}"}
    except botocore.exceptions.NoCredentialsError:
        return {"error": f"No AWS credentials found for profile {profile}"}
    except botocore.exceptions.PartialCredentialsError:
        return {"error": f"Incomplete AWS credentials for profile {profile}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
