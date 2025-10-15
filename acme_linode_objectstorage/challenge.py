"""
ACME challenge handling utilities.
"""

import logging
from typing import Any
from urllib.parse import quote, urlunsplit

import requests

from acme_linode_objectstorage import linode, models

logger = logging.getLogger(__name__)

SUPPORTED_CHALLENGES = ["http-01"]


def create_challenge_url(
    object_storage: linode.LinodeObjectStorageClient,
    cluster: str,
    label: str,
    obj_name: str,
    method: str = "PUT",
    expires_in: int = 360,
) -> str:
    """
    Create a signed URL for challenge operations.

    Args:
        object_storage: Object storage client.
        cluster: Linode cluster.
        label: Bucket label.
        obj_name: Object name.
        method: HTTP method (PUT or DELETE).
        expires_in: URL expiration time in seconds.

    Returns:
        str: The signed URL.
    """
    content_type = "text/plain" if method == "PUT" else ""
    return object_storage.create_object_url(
        cluster, label, obj_name, method, content_type, expires_in=expires_in
    )


def upload_challenge_file(url: str, key_auth: str) -> None:
    """
    Upload the challenge file to object storage.

    Args:
        url: Pre-signed URL for upload.
        key_auth: Challenge key authorization string.

    Raises:
        requests.HTTPError: If upload fails.
    """
    if not url:
        raise ValueError("No URL provided for challenge upload")

    logger.debug(f"Uploading challenge to: {url}")

    headers = {"Content-Type": "text/plain"}
    response = requests.put(url, data=key_auth, headers=headers)
    response.raise_for_status()


def delete_challenge_file(url: str) -> None:
    """
    Delete the challenge file from object storage.

    Args:
        url: Pre-signed URL for deletion.

    Raises:
        requests.HTTPError: If deletion fails.
    """
    if not url:
        logger.warning("No URL provided for challenge deletion")
        return

    logger.debug(f"Deleting challenge from: {url}")
    response = requests.delete(url)  # Linode uses PUT with DELETE method in signed URL
    response.raise_for_status()


def make_challenge_public(
    object_storage: linode.LinodeObjectStorageClient,
    cluster: str,
    label: str,
    obj_name: str,
) -> None:
    """
    Make the challenge file publicly readable.

    Args:
        object_storage: Object storage client.
        cluster: Linode cluster.
        label: Bucket label.
        obj_name: Object name.

    Raises:
        requests.HTTPError: If ACL update fails.
    """
    logger.debug(f"Making challenge public: {label}/{obj_name}")
    object_storage.update_object_acl(cluster, label, obj_name, "public-read")


def verify_challenge_accessible(domain: str, obj_name: str) -> None:
    """
    Verify that the challenge file is accessible via HTTPS.

    Args:
        domain: Domain where challenge should be accessible.
        obj_name: Object name (path to challenge file).

    Raises:
        requests.HTTPError: If challenge is not accessible.
    """
    url = urlunsplit(("http", domain, obj_name, "", ""))
    logger.debug(f"Verifying challenge accessible at: {url}")

    response = requests.head(url)
    response.raise_for_status()


def respond_to_challenge(challenge: models.Challenge) -> None:
    """
    Tell the ACME server to validate the challenge.

    Args:
        challenge: ACME challenge object.

    Raises:
        RuntimeError: If challenge validation fails.
    """
    logger.info(f"Responding to challenge: {challenge}")
    challenge.respond()
    challenge.poll_until_not({"pending", "processing"})

    if challenge.status != "valid":
        raise RuntimeError(f"Challenge validation failed: {challenge.status}")


def get_challenge_object_name(token: str) -> str:
    """
    Get the object storage path for a challenge token.

    Args:
        token: Challenge token from ACME server.

    Returns:
        str: Object storage path.
    """
    return f".well-known/acme-challenge/{quote(token)}"


def find_supported_challenge(
    authorization: models.Authorization,
) -> models.Challenge | None:
    """
    Find a supported challenge type from an authorization.

    Args:
        authorization: ACME authorization object.

    Returns:
        models.Challenge | None: First supported challenge, or None if none found.
    """
    for challenge in authorization.challenges:
        if challenge.type in SUPPORTED_CHALLENGES:
            logger.info(f"Found supported challenge: {challenge.type}")
            return challenge

    available_types = [c.type for c in authorization.challenges]
    logger.error(
        f"No supported challenge found. Available: {available_types}, "
        f"Supported: {SUPPORTED_CHALLENGES}"
    )
    return None


def process_challenge(
    object_storage: linode.LinodeObjectStorageClient,
    bucket: dict[str, Any],
    challenge: models.Challenge,
    account: models.Account,
) -> None:
    """
    Complete end-to-end challenge processing.

    Args:
        object_storage: Object storage client.
        bucket: Bucket information.
        challenge: ACME challenge to process.
        account: ACME account.

    Raises:
        requests.HTTPError: If any step fails.
    """
    obj_name = get_challenge_object_name(challenge["token"])
    key_auth = f"{challenge['token']}.{account.key_thumbprint}"

    try:
        # 1. Upload challenge file
        put_url = create_challenge_url(
            object_storage, bucket["cluster"], bucket["label"], obj_name, "PUT"
        )
        logger.debug(f"Challenge upload URL: {put_url}")
        upload_challenge_file(put_url, key_auth)

        # 2. Make it publicly accessible
        make_challenge_public(
            object_storage, bucket["cluster"], bucket["label"], obj_name
        )

        # 3. Verify it's accessible
        verify_challenge_accessible(bucket["hostname"], obj_name)

        # 4. Tell ACME server to validate
        respond_to_challenge(challenge)

    finally:
        # 5. Clean up
        try:
            logger.debug(f"Cleaning up challenge: {obj_name}")
            delete_url = create_challenge_url(
                object_storage, bucket["cluster"], bucket["label"], obj_name, "DELETE"
            )
            delete_challenge_file(delete_url)
        except Exception as e:
            logger.warning(f"Failed to clean up challenge: {e}")
