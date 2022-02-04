# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# https://aws.amazon.com/agreement
# SPDX-License-Identifier: MIT-0

import boto3
import cfnresponse
import logging
import threading

from concurrent import futures
from time import sleep
from traceback import print_exc

logger = logging.getLogger()
logger.setLevel(logging.INFO)

thread_local = threading.local()


def get_key_policy(kms_key_id):
    """Retrieve the key policy for the passed KMS key ID."""
    kms_client = boto3.session.Session().client("kms")

    logger.info(f"Retrieving key policy for \"{kms_key_id}\".")

    return kms_client.get_key_policy(
        KeyId=kms_key_id,
        PolicyName="default"
    )["Policy"]


def get_kms_client():
    """Retrieve or create a shared thread safe boto3 KMS client."""
    if not hasattr(thread_local, "kms_client"):
        session = boto3.session.Session()
        thread_local.kms_client = session.client("kms")

    return thread_local.kms_client


def handler(event, context):
    """Generates a threaded operation that will create KMS key replicas in the
    list of regions passed to the CloudFormation custom resource.

    Will return an appropriate success or failure response to CloudFormation
    upon completion.
    """
    properties = event["ResourceProperties"]
    request_type = event["RequestType"]

    status = cfnresponse.SUCCESS

    kms_key_id = properties["KMSKeyID"]
    replication_regions = properties["ReplicationRegions"]

    try:
        if request_type == "Create":
            key_policy = get_key_policy(kms_key_id)

            with futures.ThreadPoolExecutor(max_workers=3) as executor:
                for future in executor.map(
                    lambda replication_region:
                        replicate_key(
                            kms_key_id,
                            replication_region,
                            key_policy
                        ),
                    replication_regions
                ):
                    __ = future

    except Exception:
        print_exc()

        status = cfnresponse.FAILED

    cfnresponse.send(event, context, status, {})


def replicate_key(kms_key_id, replication_region, key_policy):
    """Retrieves the KMS key policy for the primary key and creates a replica in
    the specified region.

    Waits until the replica status is "Enabled" before exiting.
    """
    kms_client = get_kms_client()

    logger.info(
        f"Replicating key \"{kms_key_id}\" to "
        f"\"{replication_region}\"..."
    )

    kms_client.replicate_key(
        BypassPolicyLockoutSafetyCheck=True,
        Description="KMS CMK used by the Secrets Manager Backup application.",
        KeyId=kms_key_id,
        Policy=key_policy,
        ReplicaRegion=replication_region,
    )

    kms_client = boto3.session.Session().client("kms", replication_region)

    while(kms_client.describe_key(
        KeyId=kms_key_id
    )["KeyMetadata"]["KeyState"] != "Enabled"):
        sleep(1)

    logger.info(
        f"\"{kms_key_id}\" replicated to \"{replication_region}\" successfully."
    )
