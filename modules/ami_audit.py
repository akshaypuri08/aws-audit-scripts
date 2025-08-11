import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def audit_amis(session, profile):
    logger.info(f"Starting AMI audit for profile: {profile}")

    ec2_client = session.client("ec2")
    try:
        regions_response = ec2_client.describe_regions(AllRegions=True)
        regions = [
            region["RegionName"]
            for region in regions_response["Regions"]
            if region["OptInStatus"] != "not-opted-in"
        ]
        logger.info(f"Found {len(regions)} regions to scan")
    except ClientError as e:
        logger.error(f"Failed to describe regions: {e}")
        return {"error": str(e)}

    report = {}
    for region in regions:
        logger.info(f"Auditing AMIs in region: {region}")
        regional_client = session.client("ec2", region_name=region)
        try:
            amis_response = regional_client.describe_images(Owners=["self"])
            amis = amis_response.get("Images", [])
            logger.info(f"Found {len(amis)} AMIs in {region}")

            region_report = []
            for ami in amis:
                region_report.append({
                    "ImageId": ami.get("ImageId"),
                    "Name": ami.get("Name"),
                    "CreationDate": ami.get("CreationDate"),
                    "State": ami.get("State"),
                    "Public": ami.get("Public")
                })
            report[region] = region_report
        except ClientError as e:
            logger.error(f"Error fetching AMIs for {region}: {e}")
            report[region] = {"error": str(e)}

    logger.info(f"AMI audit completed for profile: {profile}")
    return {"profile": profile, "ami_report": report}
