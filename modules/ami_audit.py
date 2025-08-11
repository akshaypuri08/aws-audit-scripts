import boto3
import botocore

def audit_amis(session, profile):
    ec2_regions = session.get_available_regions("ec2")
    report = []

    for region in ec2_regions:
        ec2 = session.client("ec2", region_name=region)
        print(f"Checking AMIs in {region}...")

        try:
            owned_images = ec2.describe_images(Owners=["self"])["Images"]
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "AuthFailure":
                print(f"Skipping {region} - AuthFailure")
                continue
            else:
                raise

        for ami in owned_images:
            is_public = ami.get("Public", False)
            name = ami.get("Name", "Unnamed")
            ami_id = ami.get("ImageId")
            state = ami.get("State", "unknown")

            # Check usage
            used = False
            try:
                reservations = ec2.describe_instances(
                    Filters=[{"Name": "image-id", "Values": [ami_id]}]
                )["Reservations"]
                if reservations:
                    used = True
            except botocore.exceptions.ClientError:
                pass  # Skip usage check if not allowed

            # Add comment
            if not used and is_public:
                comment = "Public and unused"
            elif not used:
                comment = "Private and unused"
            elif is_public:
                comment = "Public and in use"
            else:
                comment = "Private and in use"

            report.append({
                "Region": region,
                "AMI Name": name,
                "AMI ID": ami_id,
                "Public": is_public,
                "Used": used,
                "Comment": comment
            })

    return report
