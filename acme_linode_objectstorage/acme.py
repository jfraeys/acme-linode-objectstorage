import logging
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from acme_linode_objectstorage import models, utils

logging.getLogger(__name__)


class AcmeClient:
    """Client for interacting with ACME (Automated Certificate Management Environment) server."""

    DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
    TEST_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

    def __init__(self, account_key: rsa.RSAPrivateKey, dry_run: bool = False):
        """
        Initialize the AcmeClient.

        Args:
        - account_key (rsa.RSAPrivateKey): The RSA private key for the account.
        """
        self.http = requests.Session()
        self.account_key = account_key
        self.dry_run = dry_run

        self._directory = None
        self._nonce = None
        self._key_id: str = ""

    def __enter__(self):
        """
        Context management entry point.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context management exit point. Closes the HTTP session.

        Args:
        - exc_type (type): Exception type.
        - exc_val (Exception): Exception instance.
        - exc_tb (traceback): Traceback object.
        """
        self.http.close()

    def close(self):
        """Close the AcmeClient."""
        self.__exit__(None, None, None)

    def add_headers(self, headers: dict[str, str]) -> None:
        """
        Add headers to the HTTP session.

        Args:
        - headers (dict[str, str]): Headers to add.
        """
        self.http.headers.update(headers)

    def new_account(
        self,
        terms_of_service_agreed: bool | None = None,
        only_existing: bool | None = None,
    ) -> models.Account | None:
        """
        Create a new ACME account.

        Args:
        - terms_of_service_agreed (bool | None): Whether the user agrees to the terms of service.
        - only_existing (bool | None): Whether to return only an existing account.

        Returns:
        - acme_utils.Account | int: ACME account or an error code.
        """
        payload: dict[str, Any] = {}

        if terms_of_service_agreed:
            payload["termsOfServiceAgreed"] = terms_of_service_agreed

        if only_existing:
            payload["onlyReturnExisting"] = only_existing

        public_jwk = utils.rsa_jwk_public(self.account_key)
        r = self._signed_request(
            url=str(self.url_for("newAccount")),
            key={"alg": "RS256", "jwk": public_jwk},
            payload=payload,
        )

        if not r or r.status_code != 200:
            return None

        self._key_id = r.headers["Location"]
        return models.Account(self, self._key_id, r.json())

    def new_order(self, domain: str, additional_domains: list[str] | None = None) -> models.Order | None:
        """
        Create a new order for the specified domains.

        Args:
        - domain (str): Primary domain name.
        - additional_domains (list[str] | None): Additional domain names to include in the order.

        Returns:
        - models.Order | None: ACME order or None if failed.
        """
        # Get the URL for creating the new order
        url = self.url_for("newOrder")
        if isinstance(url, bytes):
            url = url.decode("utf-8")

        if not url:
            logging.error("Failed to get URL for new order")
            return None

        # Construct payload for the new order request
        # Collect all domains
        all_domains = [domain]
        if additional_domains:
            for additional_domain in additional_domains:
                if additional_domain not in all_domains:
                    all_domains.append(additional_domain)
        
        payload = {"identifiers": [{"type": "dns", "value": d} for d in all_domains]}

        logging.debug(f"Creating new order with URL {url} and payload: {payload}")

        # Send the request to create a new order
        try:
            response = self.signed_request(url, payload)
        except Exception as e:
            logging.error(f"Error making request to create new order: {e}")
            return None

        # Check if the response status code is successful
        if response.status_code != 201:
            logging.error(
                f"Failed to create new order: {response.status_code} - {response.text}"
            )
            return None

        # Return the Order object on success
        try:
            order_data = response.json()
            return models.Order(self, response.headers["Location"], order_data)

        except Exception as e:
            logging.error(f"Failed to parse response JSON: {e}")
            return None

    def url_for(self, resource: str) -> str | bytes | None:
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
            logging.debug(f"Fetched directory: {self._directory}")

        if not self._directory:
            return None

        return self._directory[resource]

    def signed_request(
        self, url: str | bytes, payload: dict[str, Any] | None = None
    ) -> requests.Response:
        """
        Send a signed request to the ACME server.

        Args:
        - url (str): URL for the request.
        - payload (dict | None): Payload data for the request. None for POST-as-GET.

        Returns:
        - requests.Response: Response object.
        """
        # Check if the key ID is set, if not, attempt to create a new account.
        if not self._key_id:
            logging.debug("Key ID not found. Attempting to create a new account.")
            self.new_account(only_existing=True)

        # Ensure the key ID is now set
        if not self._key_id:
            logging.error(
                "Key ID is still not set after attempting to create a new account."
            )
            raise ValueError(
                "Key ID is not available, unable to make a signed request."
            )

        logging.debug(f"Using key ID: {self._key_id}")

        # Send the signed request using the _signed_request method
        try:
            logging.debug(f"Key ID at time of request: {self._key_id}")
            response = self._signed_request(
                url=url,
                key={"alg": "RS256", "kid": self._key_id},
                payload=payload,
            )
            logging.debug(f"Received response: {response.status_code}")
            return response
        except Exception as e:
            logging.error(f"Error during signed request: {e}", exc_info=True)
            raise

    def format_data(
        self, url: str | bytes, key: dict[str, Any], payload: dict[str, Any] | None
    ) -> dict[str, Any]:
        """
        Format the data for the signed request to the ACME server.

        Args:
        - url (str): URL for the request.
        - payload (dict | None): Payload data for the request. None for POST-as-GET.
        - key (dict): Key information for the request.

        Returns:
        - dict: Formatted data.
        """
        # Create protected header with necessary information
        protected_header = {"url": url, "nonce": self._nonce, **key}
        protected = utils.b64url(utils.json_encode(protected_header))

        # Log the protected header for debugging
        logging.debug(f"Protected header: {protected_header}")

        # For POST-as-GET (payload is None), use empty string
        if payload is None:
            dumped_payload = ""
            logging.debug("Using POST-as-GET (empty payload)")
        else:
            encoded_payload = utils.json_encode(payload)
            dumped_payload = utils.b64url(encoded_payload)
            # Log the payload for debugging
            logging.debug(f"Encoded payload: {utils.print_encoded(encoded_payload)}")
            logging.debug(f"Dumped payload (b64url): {dumped_payload}")

        # Create signing input string
        signing_input = f"{protected}.{dumped_payload}".encode("utf-8")

        # Generate signature using account key
        try:
            signature = utils.b64url(
                self.account_key.sign(
                    signing_input, padding.PKCS1v15(), hashes.SHA256()
                )
            )
            # Log the generated signature
            logging.debug(f"Generated signature: {signature}")
        except Exception as e:
            logging.error(f"Error during signature creation: {e}", exc_info=True)
            raise

        return {
            "protected": protected,
            "payload": dumped_payload,
            "signature": signature,
        }

    def _signed_request(
        self, url: str | bytes, key: dict[str, Any], payload: dict[str, Any] | None
    ) -> requests.Response:
        """Send a signed request to the ACME server with nonce handling."""
        if isinstance(url, bytes):
            url = url.decode("utf-8")

        # Ensure we have a nonce first
        if not self._nonce:
            self._new_nonce()

        for attempt in range(2):  # try once, then retry if badNonce
            data = self.format_data(url, key, payload)
            headers = {"Content-Type": "application/jose+json"}

            logging.debug(f"Sending signed request to {url} (attempt {attempt + 1})")

            try:
                response = self.http.post(url, headers=headers, json=data)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error sending signed request: {e}", exc_info=True)
                raise

            # Update nonce if present
            new_nonce = response.headers.get("Replay-Nonce")
            if new_nonce:
                self._nonce = new_nonce

            # Retry if the server says our nonce was invalid
            if response.status_code == 400:
                try:
                    err = response.json()
                    if err.get("type") == "urn:ietf:params:acme:error:badNonce":
                        logging.warning(
                            "badNonce received — retrying once with new nonce"
                        )
                        self._new_nonce()
                        continue
                except Exception:
                    pass

            # Normal exit
            return response

        raise RuntimeError("ACME request failed after badNonce retry")

    def _new_nonce(self):
        """Get a new nonce from the ACME server."""
        if not self.http:
            raise ValueError("HTTP session is not initialized")
        url = self.url_for("newNonce")
        if not url:
            raise ValueError("No URL for newNonce")
        r = self.http.head(url)
        r.raise_for_status()

        self._nonce = r.headers["Replay-Nonce"]
