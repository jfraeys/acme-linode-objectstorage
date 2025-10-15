"""
Validation utilities for ACME Linode Object Storage.
"""

import logging
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)


def validate_bucket_for_ssl(bucket: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate that a bucket supports custom SSL certificates.

    Args:
        bucket (dict[str, Any]): Bucket information from Linode API.

    Returns:
        tuple[bool, str]: (is_valid, error_message)
                         If valid, error_message is empty.
                         If invalid, error_message explains why.
    """
    # endpoint_type = bucket.get("endpoint_type", "unknown")
    label = bucket.get("label", "unknown")

    # if endpoint_type == "E0":
    #     return (
    #         False,
    #         f"Bucket '{label}' has endpoint type E0, which does not support custom SSL certificates. "
    #         f"Only E1, E2, or E3 endpoints support custom SSL. "
    #         f"Please migrate this bucket to a supported endpoint type.",
    #     )
    #
    # if endpoint_type not in ["E1", "E2", "E3"]:
    #     return (
    #         False,
    #         f"Bucket '{label}' has unknown or unsupported endpoint type '{endpoint_type}'. "
    #         f"Custom SSL is only supported on E1, E2, and E3 endpoints.",
    #     )

    # Check for required fields
    if not bucket.get("hostname"):
        return (False, f"Bucket '{label}' is missing required 'hostname' field.")

    if not bucket.get("cluster"):
        return (False, f"Bucket '{label}' is missing required 'cluster' field.")

    return (True, "")


def validate_certificate_format(certificate: str) -> tuple[bool, str]:
    """
    Validate the format of a PEM certificate.

    Args:
        certificate (str): Certificate in PEM format.

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    if not certificate.strip().startswith("-----BEGIN CERTIFICATE-----"):
        return (False, "Certificate does not start with BEGIN CERTIFICATE marker")

    if not certificate.strip().endswith("-----END CERTIFICATE-----"):
        return (False, "Certificate does not end with END CERTIFICATE marker")

    return (True, "")


def normalize_certificate(certificate: str) -> str:
    """
    Normalize certificate line endings and ensure proper formatting.

    Args:
        certificate (str): Certificate in PEM format.

    Returns:
        str: Normalized certificate.
    """
    # Ensure proper line endings (some systems might have issues with \r\n)
    certificate = certificate.replace("\r\n", "\n").replace("\r", "\n")

    # Ensure certificate ends with a newline
    if not certificate.endswith("\n"):
        certificate = certificate + "\n"

    return certificate


def parse_certificate_chain(certificate: str) -> list[x509.Certificate]:
    """
    Parse a PEM certificate chain into individual certificate objects.

    Args:
        certificate (str): Certificate chain in PEM format.

    Returns:
        list[x509.Certificate]: List of parsed certificate objects.

    Raises:
        ValueError: If certificate parsing fails.
    """
    cert_blocks = certificate.split("-----BEGIN CERTIFICATE-----")
    certificates = []

    for i, block in enumerate(cert_blocks[1:], 1):  # Skip first empty block
        cert_pem = (
            "-----BEGIN CERTIFICATE-----"
            + block.split("-----END CERTIFICATE-----")[0]
            + "-----END CERTIFICATE-----"
        )
        try:
            cert_obj = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            certificates.append(cert_obj)
        except Exception as e:
            raise ValueError(f"Failed to parse certificate {i}: {e}")

    return certificates


def get_certificate_domains(cert: x509.Certificate) -> tuple[str | bytes, list[str]]:
    """
    Extract CN and SANs from a certificate.

    Args:
        cert (x509.Certificate): Certificate object.

    Returns:
        tuple[str, list[str]]: (common_name, subject_alternative_names)
    """
    # Get CN
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else "N/A"

    # Get SANs
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_value = san_ext.value

        if isinstance(san_value, x509.SubjectAlternativeName):
            sans = san_value.get_values_for_type(x509.DNSName)
    except Exception:
        pass  # No SAN extension

    return (cn, sans)


def verify_certificate_covers_domain(
    cert: x509.Certificate, domain: str
) -> tuple[bool, str]:
    """
    Verify that a certificate covers a specific domain.

    Args:
        cert (x509.Certificate): Certificate object.
        domain (str): Domain to verify.

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    cn, sans = get_certificate_domains(cert)

    if domain in sans or domain == cn:
        return (True, "")

    return (
        False,
        f"Certificate does not cover domain '{domain}'. "
        f"Certificate is for: CN={cn}, SANs={sans}",
    )


def validate_certificate_chain(
    certificate: str, expected_domain: str
) -> tuple[bool, str, int]:
    """
    Validate a complete certificate chain.

    Args:
        certificate (str): Certificate chain in PEM format.
        expected_domain (str): Domain that should be covered by the certificate.

    Returns:
        tuple[bool, str, int]: (is_valid, error_message, cert_count)
    """
    cert_count = certificate.count("-----BEGIN CERTIFICATE-----")

    if cert_count == 0:
        return (False, "No certificates found in chain", 0)

    try:
        certificates = parse_certificate_chain(certificate)

        if len(certificates) != cert_count:
            return (
                False,
                f"Certificate count mismatch: found {cert_count} markers but parsed {len(certificates)}",
                cert_count,
            )

        # Validate the leaf certificate (first one)
        leaf_cert = certificates[0]
        is_valid, error_msg = verify_certificate_covers_domain(
            leaf_cert, expected_domain
        )

        if not is_valid:
            return (False, error_msg, cert_count)

        # Log information about all certificates in the chain
        for i, cert in enumerate(certificates, 1):
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            logger.debug(f"Certificate {i}: Issued by {issuer_cn}")
        return (True, "", cert_count)
    except Exception as e:
        return (False, f"Failed to validate certificate chain: {e}", cert_count)
