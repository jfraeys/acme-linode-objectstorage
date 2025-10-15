import logging
import time
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from acme_linode_objectstorage import utils

# Only import for type checking, not at runtime
if TYPE_CHECKING:
    from acme_linode_objectstorage.acme import AcmeClient

logging.getLogger(__name__)


class Resource:
    """Base class representing a generic ACME resource."""

    POLL_INTERVAL = 1
    MAX_RETRIES = 5

    def __init__(self, client: "AcmeClient", url: str, data: dict[str, Any] | None = None):
        self.client = client
        self.url = url
        self._data: dict[str, Any] | None = data
        self._retry_after = time.monotonic()

    @property
    def status(self) -> str:
        """Get the status of the resource."""
        if not self._data:
            return ""
        return self._data.get("status", "")

    def add_headers(self, headers: dict[str, str]) -> None:
        """
        Add headers to the resource client.

        Args:
        - headers (dict[str, str]): Headers to add.
        """
        self.client.add_headers(headers)

    def get_json_response(self, r: Any) -> dict[str, Any]:
        """
        Parse the JSON response from the request.
        Args:
        - r: Response object.
        Returns:
        - dict[str, Any]: Parsed JSON data.
        Raises:
        - RuntimeError: If the response is not valid JSON.
        """
        try:
            if r.status_code == 204:
                return {}
            return r.json()
        except ValueError:
            raise RuntimeError(f"Invalid JSON response: {r.text}") from None

    def update(self) -> None:
        """Update the resource information with retries."""
        r = None  # Initialize r so it's accessible in the exception handler

        for attempt in range(self.MAX_RETRIES):
            try:
                r = self.client.signed_request(self.url, payload=None)

                if r.status_code not in (200, 202):
                    raise RuntimeError(f"Failed to update resource: {r.status_code}")

                self._data = self.get_json_response(r)

                self._retry_after = time.monotonic() + int(
                    r.headers.get("Retry-After", self.POLL_INTERVAL)
                )

                if self._data:
                    return

            except Exception as e:
                logging.error(f"Error while updating resource: {e}")
                wait_time = 2**attempt  # Default wait time with exponential backoff

                # Only use Retry-After if r was successfully assigned
                if r is not None:
                    wait_time = int(r.headers.get("Retry-After", wait_time))

                time.sleep(wait_time)

        raise RuntimeError("Failed to update resource after multiple attempts.")

    def poll_until_not(self, statuses: set[str]) -> None:
        """
        Poll the resource until its status is not in the specified set.

        Args:
        - statuses (set[str]): Set of statuses to poll.
        """
        while self.status in statuses:
            logging.debug(f"Polling {self}, current status: {self.status}")
            delay = self._retry_after - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.update()

    def __getitem__(self, item: str) -> Any:
        """
        Get an item from the resource data.

        Args:
        - item: Item to get.

        Returns:
        - Any: Value associated with the item.
        """
        if not self._data:
            self.update()

        if self._data is None:
            raise ValueError("Resource data is None")

        return self._data.get(item)

    def __repr__(self) -> str:
        """Representation of the Resource."""
        data = repr(self._data) if self._data else "..."
        return f"<{self.__class__.__name__} {self.url} {data}>"


class Account(Resource):
    """Represents an ACME account resource."""

    def __init__(self, client: "AcmeClient", url: str, data: dict[str, Any] | None = None):
        super().__init__(client, url, data)

    @property
    def get_contact(self) -> list[str] | None:
        """Return the contact URIs registered with the account."""
        if not self._data:
            return None
        return self._data.get("contact")

    @property
    def key(self) -> dict[str, Any]:
        """Return the account JWK."""
        value = self["key"]
        if not value:
            raise KeyError("Account key not found")
        return value

    @property
    def key_thumbprint(self) -> str:
        """Return the JWK thumbprint (for challenge signatures)."""
        return utils.json_thumbprint(self.key)


class Challenge(Resource):
    """Class representing an ACME challenge."""

    def __init__(self, client: "AcmeClient", url: str, data: dict[str, Any] | None = None):
        super().__init__(client, url, data)

    @property
    def type(self) -> str:
        """Get the type of the challenge."""
        if not self._data:
            self.update()
        if self._data:
            return self._data.get("type", "")
        return ""

    def respond(self) -> None:
        """Respond to the challenge."""
        r = self.client.signed_request(self.url, {})
        if r.status_code != 200:
            raise RuntimeError(f"Failed to respond to challenge: {r.status_code}")
        self._data = self.get_json_response(r)


class Authorization(Resource):
    """Class representing an ACME authorization."""

    def __init__(self, client: "AcmeClient", url: str, data: dict[str, Any] | None = None):
        super().__init__(client, url, data)

    @property
    def identifier(self) -> dict[str, Any]:
        """Get the identifier for the authorization."""
        return self["identifier"]

    @property
    def challenges(self) -> list[Challenge]:
        """Get the list of challenges associated with the authorization."""
        self.update()  # Ensure that the authorization data is up-to-date
        if not self._data:
            raise ValueError("Authorization data is None")

        return [
            Challenge(self.client, challenge["url"], challenge)
            for challenge in self._data.get("challenges", [])
        ]

    def respond_to_challenges(self) -> None:
        """Respond to all challenges associated with the authorization."""
        for challenge in self.challenges:
            challenge.respond()


class Order(Resource):
    """Class representing an ACME order."""

    def __init__(self, client: "AcmeClient", url: str, data: dict[str, Any] | None = None):
        super().__init__(client, url, data)

    @property
    def authorizations(self) -> list[Authorization]:
        """Get the list of authorizations associated with the order."""
        if not self._data:
            raise ValueError("Order data is None")

        return [Authorization(self.client, url) for url in self._data.get("authorizations", [])]

    def finalize(self, csr: x509.CertificateSigningRequest) -> None:
        """
        Finalize the order with the provided CSR (Certificate Signing Request).

        Args:
        - csr (x509.CertificateSigningRequest): The CSR for finalizing the order.

        Raises:
        - RuntimeError: If the order is not in the "ready" state.
        """
        logging.debug(f"status: {self.status}")
        if self.status != "ready":
            raise RuntimeError(f"Invalid state: {self.status}")

        csr_b64 = utils.b64url(csr.public_bytes(serialization.Encoding.DER))

        if not self._data:
            raise ValueError("Order data is None")

        r = self.client.signed_request(self._data.get("finalize", ""), {"csr": csr_b64})
        self._data = self.get_json_response(r)

    def certificate(self) -> str:
        """
        Get the certificate associated with the order.

        Returns:
        - str: Certificate content (PEM format).

        Raises:
        - RuntimeError: If the order is not in the "valid" state.
        """
        if self.status != "valid":
            raise RuntimeError(f"Invalid state: {self.status}")

        if not self._data:
            raise ValueError("Order data is None")

        r = self.client.signed_request(self._data.get("certificate", ""))

        # ACME certificates are returned as PEM text
        return r.text
