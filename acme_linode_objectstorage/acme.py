#!/usr/bin/env python3

import base64
import hashlib
import json
import math
import time
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())


class Resource:
    """Base class representing a generic ACME resource."""

    POLL_INTERVAL = 1

    def __init__(
        self, client: "AcmeClient", url: str, data: dict[str, Any] | None = None
    ):
        self.client = client
        self.url = url
        self._data = data
        self._retry_after = time.monotonic()

    @property
    def status(self) -> dict[str, str]:
        """Get the status of the resource."""
        return self._data.get("status", {})

    def update(self):
        """Update the resource information."""
        r = self.client.signed_request(self.url)

        self._retry_after = time.monotonic() + int(
            r.headers.get("Retry-After", self.POLL_INTERVAL)
        )
        self._data = r.json()

    def poll_until_not(self, statuses: set[str]):
        """
        Poll the resource until its status is not in the specified set.

        Args:
        - statuses (set[str]): Set of statuses to poll until.
        """
        while self.status in statuses:
            delay = self._retry_after - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.update()

    def __getitem__(self, item):
        """
        Get an item from the resource data.

        Args:
        - item: Item to get.

        Returns:
        - Any: Value associated with the item.
        """
        if not self._data:
            self.update()

        return self._data[item]

    def __repr__(self):
        """Representation of the Resource."""
        data = repr(self._data) if self._data else "..."
        return f"<{self.__class__.__name__} {self.url} {data}>"


class Account(Resource):
    """Class representing an ACME account."""

    @property
    def key(self) -> dict:
        """Get the account key."""
        return self["key"]

    @property
    def key_thumbprint(self) -> str:
        """Get the thumbprint of the account key."""
        return json_thumbprint(self.key)


class AcmeClient:
    """Client for interacting with ACME (Automated Certificate Management Environment) server."""

    DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
    TEST_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

    def __init__(
        self, account_key: rsa.RSAPrivateKeyWithSerialization, dry_run: bool = False
    ):
        """
        Initialize the AcmeClient.

        Args:
        - account_key (rsa.RSAPrivateKeyWithSerialization): The RSA private key for the account.
        """
        self.http = requests.Session()
        self.account_key = account_key
        self.dry_run = dry_run

        self._directory = None
        self._nonce = None
        self._key_id = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.http.close()

    def new_account(
        self,
        terms_of_service_agreed: bool | None = None,
        only_existing: bool | None = None,
    ) -> Account | None:
        """
        Create a new ACME account.

        Args:
        - terms_of_service_agreed (bool | None): Whether the user agrees to the terms of service.
        - only_existing (bool | None): Whether to return only an existing account.

        Returns:
        - acme_utils.Account | int: ACME account or an error code.
        """
        payload = {}

        if terms_of_service_agreed:
            payload["termsOfServiceAgreed"] = terms_of_service_agreed

        if only_existing:
            payload["onlyReturnExisting"] = only_existing

        public_jwk = rsa_jwk_public(self.account_key)
        r = self._signed_request(
            str(self.url_for("newAccount")),
            payload,
            {"alg": "RS256", "jwk": public_jwk},
        )

        self._key_id = r.headers["Location"]

        if not self._key_id:
            logging.warning("key id not found in headers when signing request")
            return None

        logging.debug("New Account created")

        return Account(self, self._key_id, r.json())

    def new_order(self, domains: list[str]) -> "Order":
        """
        Create a new order for the specified domains.

        Args:
        - domains (list[str]): List of domain names.

        Returns:
        - acme_utils.Order | None: ACME order or None if failed.
        """
        logging.debug("Creating new order for domains: %s", domains)

        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}

        r = self.signed_request(str(self.url_for("newOrder")), payload)

        return Order(self, r.headers["Location"], r.json())

    def url_for(self, resource: str) -> str | None:
        """
        Get the URL for a specific ACME resource.

        Args:
        - resource (str): ACME resource identifier.

        Returns:
        - str | None : Resource URL or None if not found.
        """
        if not self._directory:
            if self.dry_run:
                r = self.http.get(self.TEST_DIRECTORY_URL)
            else:
                r = self.http.get(self.DIRECTORY_URL)
            r.raise_for_status()

            self._directory = r.json()

        if not self._directory:
            return None

        return self._directory[resource]

    def signed_request(
        self, url: str, payload: dict | None = None
    ) -> requests.Response:
        """
        Send a signed request to the ACME server.

        Args:
        - url (str): URL for the request.
        - payload (dict | None): Payload data for the request.

        Returns:
        - requests.Response: Response object.
        """
        if not self._key_id:
            self.new_account(only_existing=True)

        return self._signed_request(
            url,
            payload,
            {"alg": "RS256", "kid": self._key_id},
        )

    def _signed_request(
        self, url: str, payload: dict | None, key: dict
    ) -> requests.Response:
        """
        Send a signed request to the ACME server with additional key information.

        Args:
        - url (str): URL for the request.
        - payload (dict | None): Payload data for the request.
        - key (dict): Key information for the request.

        Returns:
        - requests.Response: Response object.
        """
        if not self._nonce:
            self._new_nonce()

        protected = b64url(json_encode({"url": url, "nonce": self._nonce, **key}))
        dumped_payload = b64url(json_encode(payload)) if payload else ""

        signature = b64url(
            self.account_key.sign(
                f"{protected}.{dumped_payload}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        )
        data = {
            "protected": protected,
            "payload": dumped_payload,
            "signature": signature,
        }

        headers = {"Content-Type": "application/jose+json"}

        print(data)
        print(headers)
        print(url)

        r = self.http.post(url, headers=headers, json=data)
        r.raise_for_status()

        self._nonce = r.headers.get("Replay-Nonce")

        return r

    def _new_nonce(self):
        """Get a new nonce from the ACME server."""
        r = self.http.head(self.url_for("newNonce"))
        r.raise_for_status()

        self._nonce = r.headers["Replay-Nonce"]


class Challenge(Resource):
    """Class representing an ACME challenge."""

    @property
    def type(self) -> str:
        """Get the type of the challenge."""
        return self._data.get("type", "")

    def respond(self):
        """Respond to the challenge."""
        r = self.client.signed_request(self.url, {})
        self._data = r.json()


class Authorization(Resource):
    """Class representing an ACME authorization."""

    @property
    def identifier(self) -> dict:
        """Get the identifier for the authorization."""
        return self["identifier"]

    @property
    def challenges(self) -> list[Challenge]:
        """Get the list of challenges associated with the authorization."""
        self.update()  # Ensure that the authorization data is up-to-date
        return [
            Challenge(self.client, challenge["url"], challenge)
            for challenge in self._data.get("challenges", [])
        ]

    def respond_to_challenges(self):
        """Respond to all challenges associated with the authorization."""
        for challenge in self.challenges:
            challenge.respond()


class Order(Resource):
    """Class representing an ACME order."""

    @property
    def authorizations(self) -> list[Authorization]:
        """Get the list of authorizations associated with the order."""
        return [
            Authorization(self.client, url, data=self._data.get(url))
            for url in self._data.get("authorizations", [])
        ]

    def finalize(self, csr: x509.CertificateSigningRequest):
        """
        Finalize the order with the provided CSR (Certificate Signing Request).

        Args:
        - csr (x509.CertificateSigningRequest): The CSR for finalizing the order.

        Raises:
        - RuntimeError: If the order is not in the "ready" state.
        """
        if self.status != "ready":
            raise RuntimeError(f"Invalid state: {self.status}")

        csr = b64url(csr.public_bytes(serialization.Encoding.DER))

        r = self.client.signed_request(self._data.get("finalize"), {"csr": csr})
        self._data = r.json()

    def certificate(self) -> str:
        """
        Get the certificate associated with the order.

        Returns:
        - str: Certificate content.

        Raises:
        - RuntimeError: If the order is not in the "valid" state.
        """
        if self.status != "valid":
            raise RuntimeError(f"Invalid state: {self.status}")

        r = self.client.signed_request(self._data.get("certificate"))
        return r.text


def rsa_jwk_public(key: rsa.RSAPrivateKeyWithSerialization):
    """
    Convert an RSA private key to a JSON Web Key (JWK) public key.

    Args:
    - key (rsa.RSAPrivateKeyWithSerialization): RSA private key.

    Raises:
    - TypeError: If the key is not a serializable RSA key.

    Returns:
    - dict: JWK public key.
    """
    if not isinstance(key, rsa.RSAPrivateKeyWithSerialization):
        raise TypeError("Not a serializable RSA key")

    private = key.private_numbers()

    return {
        "kty": "RSA",
        "n": b64url_uint(private.public_numbers.n),
        "e": b64url_uint(private.public_numbers.e),
    }


def b64url_uint(n: int) -> str:
    """
    Convert an unsigned integer to a Base64url-encoded string.

    Args:
    - n (int): Unsigned integer.

    Raises:
    - TypeError: If the input is not an unsigned integer.

    Returns:
    - str: Base64url-encoded string.
    """
    if n < 0:
        raise TypeError("Must be unsigned integer")

    length = int(math.log2(n) / 8) + 1 if n != 0 else 0
    return b64url(n.to_bytes(length, "big"))


def b64url(data: bytes) -> str:
    """
    Convert binary data to a Base64url-encoded string.

    Args:
    - data (bytes): Binary data.

    Returns:
    - str: Base64url-encoded string.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_thumbprint(data: dict) -> str:
    """
    Calculate the JSON thumbprint (hash) of a dictionary.

    Args:
    - data (dict): Input data.

    Returns:
    - str: Base64url-encoded JSON thumbprint.
    """
    return b64url(hashlib.sha256(json_encode(data)).digest())


def json_encode(data: dict) -> bytes:
    """
    Encode a dictionary as JSON and convert it to bytes.

    Args:
    - data (dict): Input data.

    Returns:
    - bytes: JSON-encoded data.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
