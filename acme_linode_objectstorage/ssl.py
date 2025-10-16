"""
High-level SSL/TLS certificate management for Linode Object Storage.
"""

import logging
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_linode_objectstorage import acme, linode, models
from acme_linode_objectstorage.certificate import finalize_order, upload_certificate
from acme_linode_objectstorage.challenge import (
    find_supported_challenge,
    process_challenge,
)
from acme_linode_objectstorage.validation import validate_bucket_for_ssl

logger = logging.getLogger(__name__)


def register_acme_account(
    acme_client: acme.AcmeClient, acme_agree_tos: bool
) -> models.Account | None:
    """
    Register an ACME account.

    Args:
        acme_client: ACME client for registration.
        acme_agree_tos: Whether to agree to the terms of service.

    Returns:
        models.Account | None: ACME account or None on failure.
    """
    logger.info("Registering ACME account")
    try:
        account = acme_client.new_account(terms_of_service_agreed=acme_agree_tos)
        if not account:
            logger.error("Failed to create ACME account")
            return None
        return account
    except requests.HTTPError as e:
        logger.error(f"Failed to create ACME account: {e}")
        return None


def perform_authorizations(
    object_storage: linode.LinodeObjectStorageClient,
    bucket: dict[str, Any],
    order: models.Order,
    account: models.Account,
) -> bool:
    """
    Perform ACME authorizations for an order.

    Args:
        object_storage: Object storage client.
        bucket: Bucket information.
        order: ACME order.
        account: ACME account.

    Returns:
        bool: True if successful, False otherwise.
    """
    logger.info("Performing authorizations")

    for authorization in order.authorizations:
        # Find a supported challenge
        challenge = find_supported_challenge(authorization)
        if not challenge:
            return False

        # Process the challenge
        try:
            process_challenge(object_storage, bucket, challenge, account)
        except Exception as e:
            logger.error(f"Failed to process challenge: {e}")
            return False

    return True


def register_and_update_cert(
    acme_client: acme.AcmeClient,
    object_storage: linode.LinodeObjectStorageClient,
    bucket: dict[str, Any],
    csr: x509.CertificateSigningRequest,
    private_key: rsa.RSAPrivateKeyWithSerialization,
    account: models.Account,
) -> int:
    """
    Complete certificate registration and upload workflow.

    Args:
        acme_client: ACME client.
        object_storage: Object storage client.
        bucket: Bucket information.
        csr: Certificate Signing Request.
        private_key: Private key for certificate.
        account: ACME account.

    Returns:
        int: 0 if successful, 1 on failure.
    """
    try:
        # Validate bucket
        is_valid, error_msg = validate_bucket_for_ssl(bucket)
        if not is_valid:
            logger.error(error_msg)
            return 1

        # Create ACME order
        # Include bucket hostname in order if it differs from custom domain
        additional_domains = []
        bucket_hostname = bucket.get("bucket_hostname")
        if bucket_hostname and bucket_hostname != bucket["hostname"]:
            additional_domains.append(bucket_hostname)
            logger.info(f"Creating ACME order for domains: {bucket['hostname']}, {bucket_hostname}")
        else:
            logger.info(f"Creating ACME order for domain: {bucket['hostname']}")

        order = acme_client.new_order(
            bucket["hostname"], additional_domains if additional_domains else None
        )
        if not order:
            logger.error(f"Failed to create ACME order for {bucket['hostname']}")
            return 1

        # Perform authorizations
        logger.info(f"Performing authorizations for {bucket['hostname']}")
        if not perform_authorizations(object_storage, bucket, order, account):
            logger.error(f"Authorization failed for {bucket['hostname']}")
            return 1

        # Finalize order
        logger.info(f"Finalizing order for {bucket['hostname']}")
        certificate = finalize_order(order, csr)
        if not certificate:
            logger.error(f"Failed to finalize order for {bucket['hostname']}")
            return 1

        # Upload certificate
        logger.info(f"Uploading certificate for {bucket['hostname']}")
        if not upload_certificate(object_storage, bucket, certificate, private_key):
            logger.error(f"Failed to upload certificate for {bucket['hostname']}")
            return 1

        logger.info(f"Successfully registered and updated certificate for {bucket['hostname']}")
        return 0

    except Exception as e:
        logger.exception(f"Unexpected error in certificate workflow: {e}")
        return 1
