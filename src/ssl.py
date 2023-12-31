#!/usr/bin/env python3
import logging
from urllib.parse import quote, urlunsplit

import requests
import requests.auth
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src import acme_utils, linode_utils

logging.getLogger(__name__).addHandler(logging.NullHandler())

PUBLIC_EXPONENT = 65537
SUPPORTED_CHALLENGES = ["http-01"]


def get_bucket_name(domain):
    return domain.split(".")[0]


def generate_private_key(
    key_size: int,
    public_exponent: int = PUBLIC_EXPONENT,
) -> rsa.RSAPrivateKeyWithSerialization:
    """
    Generate an RSA private key with the specified key size and optional public exponent.

    Args:
    - key_size (int): Size of the key in bits.
    - public_exponent (int): Public exponent value. Default is set to PUBLIC_EXPONENT.

    Returns:
    - rsa.RSAPrivateKeyWithSerialization: Generated RSA private key.
    """
    logging.info("Generating %d-bit RSA private key", key_size)
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent, key_size=key_size
    )

    return private_key


def generate_csr(
    s3_domain: str,
    private_key: rsa.RSAPrivateKeyWithSerialization,
) -> x509.CertificateSigningRequest:
    """
    Generate a Certificate Signing Request (CSR) for the specified S3 domain.

    Args:
    - s3_domain (str): S3 domain for which the CSR is generated.
    - private_key (rsa.RSAPrivateKeyWithSerialization): RSA private key.

    Returns:
    - x509.CertificateSigningRequest: Generated CSR.
    """
    logging.info("Creating CSR for %s", s3_domain)
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, s3_domain),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(s3_domain),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )


def register_acme_account(
    acme_client: acme_utils.AcmeClient,
    acme_agree_tos: bool,
) -> acme_utils.Account | int:
    """
    Register an ACME account with the specified client.

    Args:
    - acme_client (acme_utils.AcmeClient): ACME client for registration.
    - acme_agree_tos (bool): Whether to agree to the terms of service.

    Returns:
    - Union[acme_utils.Account, int]: ACME account or an error code.
    """
    logging.info("Registering account")
    try:
        account = acme_client.new_account(
            terms_of_service_agreed=acme_agree_tos,
        )
    except requests.HTTPError as e:
        logging.error(f"Failed to create account: {e.response.text}")
        return 1
    logging.debug("account: %s", account)

    return account


def register_order(
    acme_client: acme_utils.AcmeClient,
    domains: list[str],
) -> acme_utils.Order | int:
    """
    Register a new order for the specified domains.

    Args:
    - acme_client (acme_utils.AcmeClient): ACME client for order registration.
    - domains (list[str]): List of domain names.

    Returns:
    - acme_utils.Order | None: ACME order or None if failed.
    """
    logging.info("Creating new order for %s", domains)
    try:
        order = acme_client.new_order(domains)
        logging.debug("Order created successfully: %s", order)
        return order
    except requests.HTTPError as e:
        logging.error(f"Failed to create order: {e.response.text}")
        return 1


def _create_challenge_request_url(
    object_storage: linode_utils.LinodeObjectStorageClient,
    cluster: str,
    domain: str,
    obj_name: str,
) -> str:
    """
    Create a signed URL for the specified object in Linode Object Storage.

    Args:
    - object_storage (LinodeObjectStorageClient): Object storage client.
    - cluster (str): Linode cluster.
    - domain (str): Domain for the challenge.
    - obj_name (str): Object name.

    Returns:
    - str: The signed URL.
    """
    return object_storage.create_object_url(
        cluster,
        get_bucket_name(domain),
        "PUT",
        obj_name,
        "text/plain",
        expires_in=360,
    )


def _delete_challenge_request_url(
    object_storage: linode_utils.LinodeObjectStorageClient,
    cluster: str,
    domain: str,
    obj_name: str,
) -> str:
    """
    Create a signed URL for deleting the specified object in Linode Object Storage.

    Args:
    - object_storage (LinodeObjectStorageClient): Object storage client.
    - cluster (str): Linode cluster.
    - domain (str): Domain for the challenge.
    - obj_name (str): Object name.

    Returns:
    - str: The signed URL.
    """
    return object_storage.create_object_url(
        cluster,
        get_bucket_name(domain),
        "DELETE",
        obj_name,
        expires_in=360,
    )


def _request_challenge(
    put_url: str, request_data: str = "", request_headers: dict = {}
) -> int:
    """
    Send a PUT request to the specified URL with optional data and headers.

    Args:
    - put_url (str): URL for the PUT request.
    - request_data (str): Data to include in the request.
    - request_headers (dict): Headers to include in the request.

    Raises:
    - HTTPError: If the PUT request fails.
    """
    try:
        response = requests.put(put_url, data=request_data, headers=request_headers)
        response.raise_for_status()
    except requests.HTTPError as e:
        logging.error(f"Failed to create challenge resource: {e.response.text}")
        return 1
    return 0


def _validate_challenge_response(domain: str, obj_name: str) -> int:
    """
    Validate that the challenge response is accessible via a HEAD request.

    Args:
    - domain (str): Domain for the challenge.
    - obj_name (str): Object name.

    Raises:
    - HTTPError: If the HEAD request fails.
    """
    try:
        requests.head(urlunsplit(("http", domain, obj_name, "", ""))).raise_for_status()
    except requests.HTTPError as e:
        logging.error(f"Failed to read challenge: {e}")
        return 1
    return 0


def _respond_to_challenge(
    challenge: acme_utils.Challenge, account: acme_utils.Account
) -> int:
    """
    Respond to the challenge and poll until it's not in the "processing" state.

    Args:
    - challenge (Challenge): ACME challenge.
    - account (Account): ACME account.

    Raises:
    - HTTPError: If responding to the challenge fails.
    """
    try:
        challenge.respond()
        challenge.poll_until_not({"processing"})
    except requests.HTTPError as e:
        logging.error(f"Responding to challenge failed: {e.response.text}")
        return 1

    if challenge.status != "valid":
        logging.error(f"Challenge unsuccessful: {challenge.status}")
        return 1

    return 0


def _cleanup_challenge(
    object_storage: linode_utils.LinodeObjectStorageClient,
    cluster: str,
    domain: str,
    obj_name: str,
) -> int:
    """
    Clean up the challenge resource by sending a DELETE request to the specified URL.

    Args:
    - object_storage (LinodeObjectStorageClient): Object storage client.
    - cluster (str): Linode cluster.
    - domain (str): Domain for the challenge.
    - obj_name (str): Object name.

    Raises:
    - HTTPError: If the DELETE request fails.
    """
    try:
        delete_url = _delete_challenge_request_url(
            object_storage, cluster, domain, obj_name
        )
        _request_challenge(delete_url)
    except requests.HTTPError as e:
        logging.warning(f"Failed to cleanup challenge resource: {e.response.text}")
        return 1

    return 0


def create_challenge_resource(
    object_storage: linode_utils.LinodeObjectStorageClient,
    cluster: str,
    domain: str,
    challenge: acme_utils.Challenge,
    account: acme_utils.Account,
) -> int:
    """
    Create a challenge resource for ACME authorization.

    Args:
    - object_storage (LinodeObjectStorageClient): Object storage client.
    - cluster (str): Linode cluster.
    - domain (str): Domain for the challenge.
    - challenge (Challenge): ACME challenge.
    - account (Account): ACME account.
    """
    obj_name = f'/.well-known/acme-challenge/{quote(challenge["token"])}'
    url = _create_challenge_request_url(object_storage, cluster, domain, obj_name)
    data = f'{challenge["token"]}.{account.key_thumbprint}'
    headers = {"Content-Type": "text/plain"}

    _request_challenge(url, data, headers)

    try:
        if object_storage.get_object(cluster, get_bucket_name(domain), obj_name) == 1:
            return 1

        if _validate_challenge_response(domain, obj_name) == 1:
            return 1

        if _respond_to_challenge(challenge, account) == 1:
            return 1

    finally:
        if _cleanup_challenge(object_storage, cluster, domain, obj_name) == 1:
            return 1

    return 0


def _poll_order_until_not(order: acme_utils.Orderi, step: dict) -> int:
    """
    Poll the ACME order until it is no longer in the 'pending' state.

    Args:
    - order (Order): ACME order to be polled.

    Raises:
    - requests.HTTPError: If polling encounters an HTTP error.
    """
    try:
        order.poll_until_not(step)
    except requests.HTTPError as e:
        logging.error(f"Failed to poll order status: {e.response.text}")
        return 1

    return 0


def _finalize_order(
    order: acme_utils.Order, csr: x509.CertificateSigningRequest
) -> int:
    """
    Finalize an ACME order with the provided CSR.

    Args:
    - order (Order): ACME order to be finalized.
    - csr (x509.CertificateSigningRequest): CSR for finalization.

    Raises:
    - requests.HTTPError: If finalization encounters an HTTP error.
    """
    if _poll_order_until_not(order, {"pending"}) == 1:
        return 1

    try:
        order.finalize(csr)
    except requests.HTTPError as e:
        logging.error(f"Failed to finalize order: {e.response.text}")
        return 1

    if _poll_order_until_not(order, {"processing"}) == 1:
        return 1

    return 0


def _get_certificate(order: acme_utils.Order) -> str:
    """
    Retrieve the certificate associated with the finalized ACME order.

    Args:
    - order (Order): Finalized ACME order.

    Returns:
    - str: Certificate content.

    Raises:
    - requests.HTTPError: If fetching the certificate encounters an HTTP error.
    """
    try:
        return order.certificate()
    except requests.HTTPError as e:
        logging.error(f"Failed to fetch certificate: {e.response.text}")
        raise


def finalize_order(order: acme_utils.Order, csr: x509.CertificateSigningRequest) -> str:
    """
    Finalize an ACME order with the provided CSR.

    Args:
    - order (Order): ACME order to be finalized.
    - csr (x509.CertificateSigningRequest): CSR for finalization.

    Returns:
    - Union[str, int]: Certificate or error code.
    """
    logging.info("Finalizing order")
    if _finalize_order(order, csr) == 1:
        return 1

    if order.status != "valid":
        logging.error(f"Finalize unsuccessful: {order.status}")
        return 1

    try:
        return _get_certificate(order)
    except requests.HTTPError as e:
        logging.error(f"ERROR: Failed to fetch certificate: {e.response.text}")
        return 1


def update_certificates(
    object_storage: linode_utils.LinodeObjectStorageClient,
    cluster: str,
    domain: str,
    private_key: rsa.RSAPrivateKeyWithSerialization,
    certificate: str,
) -> int:
    """
    Update SSL certificates on the object storage.

    Args:
    - object_storage (linode_utils.LinodeObjectStorageClient): Object storage client.
    - args (argparse.Namespace): Command-line arguments.
    - private_key (rsa.RSAPrivateKeyWithSerialization): RSA private key.
    - certificate (str): SSL certificate.

    Returns:
    - int | None: Error code or None if successful.
    """
    try:
        object_storage.delete_ssl(cluster, domain)
    except requests.HTTPError as e:
        logging.error(f"Failed to delete old certificate: {e.response.text}")
        return 1

    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")

    try:
        object_storage.upload_ssl(
            cluster, get_bucket_name(domain), certificate, private_key_pem
        )
    except requests.HTTPError as e:
        logging.error(f"Failed to create certificate: {e.response.text}")
        return 1

    return 0


def perform_authorizations(
    object_storage: "linode_utils.LinodeObjectStorageClient",
    domain: str,
    cluster: str,
    order: acme_utils.Order,
    account: acme_utils.Account,
) -> int:
    """
    Perform authorizations for an ACME order.

    Args:
    - object_storage (linode_utils.LinodeObjectStorageClient): Object storage client.
    - args (argparse.Namespace): Command-line arguments.
    - order (acme_utils.Order): ACME order.
    - account (acme_utils.Account): ACME account.

    Returns:
    - int | None: Error code or None if successful.
    """
    logging.info("Performing authorizations")

    order.update()

    for authorization in order.authorizations:
        for challenge in authorization.challenges:
            if challenge.type in SUPPORTED_CHALLENGES:
                break
        else:
            logging.error("No supported challenges")
            return 1

        create_challenge_resource(object_storage, cluster, domain, challenge, account)

    return 0


def register_and_update_certs(
    acme: acme_utils.AcmeClient,
    object_storage: linode_utils.LinodeObjectStorageClient,
    cluster: str,
    domain: str,
    csr: x509.CertificateSigningRequest,
    private_key: rsa.RSAPrivateKeyWithSerialization,
    account: acme_utils.Account,
) -> int:
    """
    Registers an ACME account, performs authorizations, finalizes an order, and updates certificates.

    Args:
        acme (acme_utils.AcmeClient): The ACME client for interaction.
        object_storage (linode_utils.LinodeObjectStorageClient): Object storage client.
        args (argparse.Namespace): Command-line arguments.
        csr (x509.CertificateSigningRequest): Certificate Signing Request for the order.
        private_key (rsa.RSAPrivateKeyWithSerialization): RSA private key for certificate generation.
        account (acme_utils.Account): ACME account.

    Returns:
        int: 0 if successful, 1 if any step fails.
    """

    order = acme.new_order([domain])

    if perform_authorizations(object_storage, cluster, domain, order, account) == 1:
        return 1

    logging.info("Finalizing order")

    certificate = finalize_order(order, csr)

    if certificate == 1:
        return 1

    if (
        update_certificates(object_storage, cluster, domain, private_key, certificate)
        == 1
    ):
        return 1

    return 0
