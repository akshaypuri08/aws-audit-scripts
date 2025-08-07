import boto3
import logging
from botocore.exceptions import ClientError


def review_nacls(session, region):
    try:
        ec2_client = session.client("ec2", region_name=region)
        nacls = ec2_client.describe_network_acls()

        if not nacls['NetworkAcls']:
            logging.info("No NACLs found in region: %s", region)
            return

        for nacl in nacls['NetworkAcls']:
            nacl_id = nacl.get("NetworkAclId")
            logging.info("\n=== NACL ID: %s ===", nacl_id)

            for entry in nacl.get("Entries", []):
                rule_number = entry.get("RuleNumber")
                protocol = entry.get("Protocol")
                egress = entry.get("Egress")
                rule_action = entry.get("RuleAction")
                port_range = entry.get("PortRange", {})
                cidr_block = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "N/A")

                from_port = port_range.get("From", "ALL")
                to_port = port_range.get("To", "ALL")

                direction = "Outbound" if egress else "Inbound"
                log_msg = f"{direction} Rule #{rule_number} | {rule_action.upper()} | Protocol: {protocol} | Port: {from_port} - {to_port} | CIDR: {cidr_block}"
                logging.info(log_msg)

                # Simple rule review
                recommendation = []

                if not egress and rule_action == "allow":
                    if cidr_block in ["0.0.0.0/0", "::/0"]:
                        recommendation.append("Open to all IPs - consider restricting CIDR")

                if egress and rule_action == "allow":
                    if cidr_block in ["0.0.0.0/0", "::/0"]:
                        recommendation.append("Generally OK for outbound")

                if recommendation:
                    logging.info("  Recommendation: " + " | ".join(recommendation))

    except ClientError as e:
        logging.error("Error retrieving NACLs: %s", e)
    except Exception as ex:
        logging.exception("Unexpected error occurred while reviewing NACLs: %s", ex)
