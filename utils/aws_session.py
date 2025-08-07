import boto3
import logging

def get_boto3_session(profile_name):
    try:
        session = boto3.Session(profile_name=profile_name)
        logging.info(f"Using AWS profile: {profile_name}")
        return session
    except Exception as e:
        logging.error(f"Error creating session with profile {profile_name}: {e}")
        return None

def get_identity(session):
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        logging.info(f"Connected as: {identity['Arn']} (Account: {identity['Account']})")
        return identity
    except Exception as e:
        logging.error(f"Error getting caller identity: {e}")
        return None