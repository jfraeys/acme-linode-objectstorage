"""
Certificate management utilities.
"""

import logging
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_linode_objectstorage import linode, models, utils, validation

logger = logging.getLogger(__name__)

PUBLIC_EXPONENT = 65537


def generate_private_key(
    key_size: int, public_exponent: int = PUBLIC_EXPONENT
) -> rsa.RSAPrivateKeyWithSerialization:
    """
    Generate an RSA private key.

    Args:
        key_size: Size of the key in bits.
        public_exponent: Public exponent value.

    Returns:
        rsa.RSAPrivateKeyWithSerialization: Generated RSA private key.
    """
    logger.info(f"Generating {key_size}-bit RSA private key")
    return rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)


def generate_csr(
    domain: str, private_key: rsa.RSAPrivateKeyWithSerialization, additional_domains: list[str] | None = None
) -> x509.CertificateSigningRequest:
    """
    Generate a Certificate Signing Request (CSR).

    Args:
        domain: Primary domain name for the certificate (used as CN).
        private_key: RSA private key.
        additional_domains: Additional domains to include in SAN (optional).

    Returns:
        x509.CertificateSigningRequest: Generated CSR.
    """
    # Collect all domains for SAN
    san_domains = [domain]
    if additional_domains:
        # Add additional domains, avoiding duplicates
        for additional_domain in additional_domains:
            if additional_domain not in san_domains:
                san_domains.append(additional_domain)

    logger.info(f"Creating CSR for domains: {', '.join(san_domains)}")
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_domains]), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )


def finalize_order(order: models.Order, csr: x509.CertificateSigningRequest) -> str:
    """
    Finalize an ACME order and retrieve the certificate.

    Args:
        order: ACME order to finalize.
        csr: Certificate Signing Request.

    Returns:
        str: Certificate in PEM format, or empty string on failure.
    """
    logger.info("Finalizing order")

    # Wait for order to be ready
    try:
        order.poll_until_not({"pending"})
    except Exception as e:
        logger.error(f"Failed to poll order status: {e}")
        return ""

    # Finalize with CSR
    try:
        order.finalize(csr)
    except Exception as e:
        logger.error(f"Failed to finalize order: {e}")
        return ""

    # Wait for processing to complete
    try:
        order.poll_until_not({"processing"})
    except Exception as e:
        logger.error(f"Failed to poll order after finalization: {e}")
        return ""

    # Check final status
    if order.status != "valid":
        logger.error(f"Order finalization unsuccessful: {order.status}")
        return ""

    # Retrieve certificate
    try:
        certificate = order.certificate()
        logger.info("Certificate retrieved successfully")
        return certificate
    except Exception as e:
        logger.error(f"Failed to retrieve certificate: {e}")
        return ""


def upload_certificate(
    object_storage: linode.LinodeObjectStorageClient,
    bucket: dict[str, Any],
    certificate: str,
    private_key: rsa.RSAPrivateKeyWithSerialization,
) -> bool:
    """
    Upload SSL certificate to Linode Object Storage.

    Args:
        object_storage: Object storage client.
        bucket: Bucket information.
        certificate: Certificate in PEM format.
        private_key: Private key for the certificate.

    Returns:
        bool: True if successful, False otherwise.
    """
    # Validate certificate format
    is_valid, error = validation.validate_certificate_format(certificate)
    if not is_valid:
        logger.error(error)
        return False

    # Normalize certificate
    certificate = validation.normalize_certificate(certificate)

    # Validate certificate chain
    cert_count = certificate.count("-----BEGIN CERTIFICATE-----")
    logger.info(f"Certificate chain contains {cert_count} certificate(s)")

    # Validate that certificate covers the custom domain
    is_valid, error, _ = validation.validate_certificate_chain(
        certificate, bucket["hostname"]
    )
    if not is_valid:
        logger.error(error)
        return False

    # Also validate that certificate covers the bucket hostname if it differs
    bucket_hostname = bucket.get("bucket_hostname")
    if bucket_hostname and bucket_hostname != bucket["hostname"]:
        is_valid, error, _ = validation.validate_certificate_chain(
            certificate, bucket_hostname
        )
        if not is_valid:
            logger.error(f"Certificate does not cover bucket hostname: {error}")
            return False
        logger.info(f"Certificate validated successfully for {bucket['hostname']} and {bucket_hostname}")
    else:
        logger.info(f"Certificate validated successfully for {bucket['hostname']}")

    # Delete old certificate if exists
    try:
        current_ssl = object_storage.get_ssl(bucket["cluster"], bucket["label"])
        logger.debug(f"Current SSL config: {current_ssl}")

        if current_ssl.get("ssl"):
            object_storage.delete_ssl(bucket["cluster"], bucket["label"])
            logger.info("Deleted existing SSL certificate")
    except requests.HTTPError as e:
        logger.error(f"Failed to check/delete old certificate: {e}")
        return False

    # Upload new certificate
    try:
        private_key_pem = utils.private_key_to_pem(private_key)
        object_storage.create_ssl(
            bucket["cluster"], bucket["label"], certificate, private_key_pem
        )
        logger.info(f"Successfully uploaded SSL certificate for {bucket['label']}")
        return True
    except requests.HTTPError as e:
        logger.error(f"Failed to upload certificate: {e}")
        return False
