# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# https://aws.amazon.com/agreement
# SPDX-License-Identifier: MIT-0

import boto3
import logging

from os import environ
from traceback import print_exc

boto3_session = boto3.session.Session()
secretsmanager_client = boto3_session.client("secretsmanager")
sts_client = boto3_session.client("sts")

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def assume_role(source_account_id, entropy):
    """Assume, and return the credentials for, the "backup_assume_role" role
    found in the passed source account ID.
    """
    logger.info(f"Assuming role in account {source_account_id}...")

    return sts_client.assume_role(
        RoleArn=(
            f"arn:aws:iam::{source_account_id}:role/"
            "secrets_manager_backup/backup_assume_role"
        ),
        RoleSessionName=f"SecretsManagerBackup{entropy}"
    )["Credentials"]


def check_secret_exists(backup_secret_name):
    """Return positive or negative confirmation that the backup of the source
    secret exists.
    """
    logger.info(f"Checking for existence of secret \"{backup_secret_name}\"...")

    try:
        return secretsmanager_client.describe_secret(
            SecretId=backup_secret_name
        )

    except secretsmanager_client.exceptions.ResourceNotFoundException:
        return None

    except Exception:
        raise


def create_secret(backup_secret_name, secret_data, secret_value):
    """Create a new backup of the source secret and enable replication if
    regions for such a purpose are provided as an environment variable."""
    options = {
        "Description": secret_data.get("Description") or "",
        "KmsKeyId": environ["BACKUP_KMS_KEY_ID"],
        "Name": backup_secret_name,
        "Tags": secret_data["Tags"],
        **secret_value
    }

    env_backup_replication_regions = environ["BACKUP_REPLICATION_REGIONS"]

    if env_backup_replication_regions:
        options["AddReplicaRegions"] = [
            {
                "Region": region,
                "KmsKeyId": environ["BACKUP_KMS_KEY_ID"]
            } for region in env_backup_replication_regions.split(",")
        ]

    logger.info(f"  \"{backup_secret_name}\" does not exist.  Creating...")

    secretsmanager_client.create_secret(**options)

    logger.info(f"    \"{backup_secret_name}\" created.")


def describe_secret(remote_secretsmanager_client, secret_name):
    """Retrieve the source secret metadata."""
    logger.info(f"  Retrieving source secret metadata.")

    return remote_secretsmanager_client.describe_secret(
        SecretId=secret_name
    )


def get_secret_value(remote_secretsmanager_client, secret_name):
    """Retrieve the source secret value."""
    logger.info(f"  Retrieving source secret value.")

    secret_value = remote_secretsmanager_client.get_secret_value(
        SecretId=secret_name
    )

    return {
        "SecretString": secret_value["SecretString"]
    } if "SecretString" in secret_value else {
        "SecretBinary": secret_value["SecretBinary"]
    }


def handler(event, context):
    """React to a funneled Secrets Manager API event and create or update the
    backup secret accordingly.
    """
    try:
        entropy = event["id"].split("-")[-1]
        event_detail = event["detail"]
        event_name = event_detail["eventName"]

        source_account_id = event_detail["recipientAccountId"]
        source_account_region = event_detail["awsRegion"]

        secret_name = ""
        if event_name == "CreateSecret":
            secret_name = event_detail["requestParameters"]["name"]
        elif event_name in ("TagResource", "UntagResource", "UpdateSecret"):
            secret_name = event_detail["requestParameters"]["secretId"]
        elif event_name in ("PutSecretValue", "UpdateSecretVersionStage"):
            _secret_id = event_detail["requestParameters"]["secretId"]
            secret_name = _secret_id.split(":")[-1][:-7]

        backup_secret_name = (
            f"{source_account_id}/{source_account_region}/{secret_name}"
        )

        remote_secretsmanager_client = remote_client(
            source_account_id,
            source_account_region,
            entropy
        )

        secret_data = describe_secret(remote_secretsmanager_client, secret_name)
        secret_value = get_secret_value(
            remote_secretsmanager_client,
            secret_name
        )

        backup_secret_data = check_secret_exists(backup_secret_name)

        if backup_secret_data is not None:
            update_secret(
                backup_secret_name,
                backup_secret_data,
                secret_data,
                secret_value
            )
        else:
            create_secret(backup_secret_name, secret_data, secret_value)

    except Exception:
        print_exc()


def remote_client(source_account_id, source_account_region, entropy):
    """Establish a boto3 client used to access Secrets Manager in the source
    account."""
    credentials = assume_role(source_account_id, entropy)

    return boto3_session.client(
        "secretsmanager",
        source_account_region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )


def update_secret(
    backup_secret_name, backup_secret_data, secret_data, secret_value
):
    """Update the backup secret with the retrieved information."""
    logger.info(f"  \"{backup_secret_name}\" exists.  Updating...")

    secretsmanager_client.update_secret(
        Description=secret_data["Description"],
        SecretId=backup_secret_name,
        **secret_value
    )

    secretsmanager_client.untag_resource(
        SecretId=backup_secret_name,
        TagKeys=[tag["Key"] for tag in backup_secret_data["Tags"]]
    )

    secretsmanager_client.tag_resource(
        SecretId=backup_secret_name,
        Tags=secret_data["Tags"]
    )

    logger.info(f"    \"{backup_secret_name}\" updated.")
