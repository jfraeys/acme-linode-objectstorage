"""
Linode API client.

See https://www.linode.com/docs/api/.
"""

import logging
from typing import Any, Union
from urllib.parse import quote, urljoin

import requests
import requests.auth

logging.getLogger(__name__)

LINODE_API = "https://api.linode.com/"


class LinodeObjectStorageClient:
    """
    Object Storage Client for Linode.

    This class provides methods to interact with Linode's Object Storage API.

    Attributes:
        http (requests.Session): A session object for making HTTP requests.
        dry_run (bool): If True, allow GET/HEAD but mock POST/PUT/DELETE requests.
    """

    def __init__(self, token: str, dry_run: bool = False) -> None:
        self.http = requests.Session()
        self.http.auth = BearerAuth(token)
        self.dry_run = dry_run

    def __enter__(self):
        try:
            res = self.http.get(LINODE_API)
            res.raise_for_status()
            logging.info(f"Ping Response from {LINODE_API}: {res.json()}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error: {e}")
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.http.close()

    def close(self) -> None:
        """
        Closes the HTTP session.
        """
        self.__exit__(None, None, None)

    def add_headers(self, headers: dict[str, str]) -> None:
        """
        Adds headers to the HTTP session.

        Args:
            headers (dict[str, str]): A dictionary of headers to add to the session.
        """
        self.http.headers.update(headers)

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Internal method to make HTTP requests with dry-run support.

        In dry-run mode:
        - GET and HEAD requests are executed normally
        - POST, PUT, DELETE requests are logged but not executed

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, HEAD)
            url (str): URL for the request
            **kwargs: Additional arguments to pass to requests

        Returns:
            requests.Response: Response object (real or mocked)
        """
        method_upper = method.upper()

        if self.dry_run and method_upper not in ["GET", "HEAD"]:
            logging.warning(f"[DRY-RUN] Skipping {method_upper} request to {url}")
            if "json" in kwargs:
                logging.info(f"[DRY-RUN] Would send payload: {kwargs['json']}")
            if "data" in kwargs:
                logging.info(
                    f"[DRY-RUN] Would send data: {kwargs['data'][:100]}..."
                    if len(str(kwargs["data"])) > 100
                    else f"[DRY-RUN] Would send data: {kwargs['data']}"
                )

            # Return a mock successful response
            mock_response = requests.Response()
            mock_response.status_code = 200
            mock_response._content = b'{"dry_run": true, "success": true}'
            mock_response.headers["Content-Type"] = "application/json"
            return mock_response

        # Execute real request for GET/HEAD or when not in dry-run
        return getattr(self.http, method.lower())(url, **kwargs)

    def list_buckets(
        self,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, str]]:
        """
        Retrieves a list of buckets based on specified parameters.
        """
        if params is None:
            params = {}

        all_buckets: list[dict[str, Any]] = []
        page = 1
        total_pages = 1

        url = urljoin(LINODE_API, "v4/object-storage/buckets")

        try:
            while page <= total_pages:
                response = self._make_request(
                    "GET", url, params={**params, "page": page}
                )
                response.raise_for_status()

                data = response.json()
                current_buckets = data.get("data", [])
                all_buckets.extend(current_buckets)

                total_pages = data.get("pages", page)

                if not current_buckets:
                    break

                page += 1
            return all_buckets

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error while fetching buckets: {e}", exc_info=True)
        except Exception as e:
            logging.error(
                f"Unexpected error while fetching buckets: {e}", exc_info=True
            )

        return []

    def create_object_url(
        self,
        cluster: str,
        label: str,
        name: str,
        method: str = "GET",
        content_type: str = "",
        expires_in: int = -1,
    ) -> str:
        """
        Generates a URL for interacting with objects in the specified bucket.
        """
        if method not in ["GET", "PUT", "DELETE"]:
            raise ValueError("Method must be one of GET, PUT, or DELETE")

        payload: dict[str, Union[str, int]] = {"method": method, "name": name}

        if expires_in >= 0:
            payload["expires_in"] = expires_in

        if content_type:
            payload["content_type"] = content_type

        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/object-url",
        )

        logging.debug(
            f"Creating object URL for {method} request to {url} with payload {payload}"
        )

        try:
            r = self._make_request("POST", url, json=payload)
            r.raise_for_status()
            response = r.json()

            if self.dry_run:
                # Return a mock URL in dry-run mode
                return (
                    f"https://{cluster}.linodeobjects.com/{label}/{name}?dry-run=true"
                )

            return response["url"]
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP request to generate object URL failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                    logging.error(f"Error detail from Linode API: {error_detail}")
                except ValueError:
                    logging.error(f"Error response body: {e.response.text}")

        return ""

    def update_object_acl(
        self, cluster: str, label: str, name: str, acl: str
    ) -> dict[str, Any]:
        """
        Updates the Access Control List (ACL) for the specified object.
        """
        payload = {"name": name, "acl": acl}

        logging.debug(f"Updating ACL for object {name} using payload {payload}")

        url = urljoin(
            LINODE_API,
            f"/v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/object-acl",
        )

        try:
            r = self._make_request("PUT", url, json=payload)
            r.raise_for_status()
            response = r.json()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(
                f"HTTP request to update object URL failed: {e}", exc_info=True
            )

        return {}

    def check_ssl_exists(self, cluster: str, label: str) -> bool:
        """
        Checks if SSL is configured for the specified label.
        """
        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/ssl",
        )

        try:
            r = self._make_request("GET", url)
            r.raise_for_status()
            response = r.json()
            return "ssl" in response
        except requests.exceptions.RequestException as e:
            logging.error(
                f"HTTP request to check ssl exists failed: {e}", exc_info=True
            )

        return False

    def get_ssl(self, cluster: str, label: str) -> dict[str, Any]:
        """
        Retrieves SSL configuration for the specified bucket.
        Args:
            cluster (str): The cluster name.
            label (str): The bucket label.
        Returns:
            dict[str, Any]: SSL configuration details.
        Raises:
            requests.exceptions.RequestException: If the HTTP request fails.
        """
        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/ssl",
        )
        try:
            r = self._make_request("GET", url)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP request to get ssl failed: {e}", exc_info=True)
        except Exception as e:
            logging.error(f"Unexpected error: {e}", exc_info=True)

        return {}

    def create_ssl(
        self, cluster: str, label: str, certificate: str, private_key: str
    ) -> bool:
        """
        Creates SSL configuration for the specified bucket.

        Raises:
            requests.exceptions.HTTPError: If the HTTP request fails.
        """
        payload = {
            "certificate": certificate,
            "private_key": private_key,
            "source": "custom",
        }

        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/ssl",
        )

        if self.dry_run:
            logging.info("[DRY-RUN] Certificate preview (first 100 chars):")
            logging.info(f"[DRY-RUN] {certificate[:100]}...")

        r = self._make_request("POST", url, json=payload)

        # Log detailed error before raising
        if r.status_code >= 400:
            try:
                error_detail = r.json()
                logging.error(f"Error detail from Linode API: {error_detail}")
            except ValueError:
                logging.error(f"Error response body: {r.text}")

        r.raise_for_status()
        response = r.json()

        return "ssl" in response or self.dry_run

    def upload_ssl(
        self, cluster: str, label: str, certificate: str, private_key: str
    ) -> bool:
        """
        Uploads SSL certificate and private key for the specified label.
        """
        data = {"certificate": certificate, "private_key": private_key}

        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/ssl",
        )
        r = self._make_request("POST", url, json=data)
        r.raise_for_status()

        return "ssl" in r.json() or self.dry_run

    def delete_ssl(self, cluster: str, label: str) -> bool:
        """
        Deletes SSL configuration for the specified bucket.
        """
        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(label)}/ssl",
        )

        try:
            r = self._make_request("DELETE", url)
            r.raise_for_status()
            response = r.json()
            return response == {} or self.dry_run
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP request to delete ssl failed: {e}", exc_info=True)

        return False


class BearerAuth(requests.auth.AuthBase):
    """
    Bearer Authentication for Linode API.

    This class provides Bearer token authentication for Linode API requests.

    Attributes:
        token (str): The Bearer token used for authentication.
    """

    def __init__(self, token: str) -> None:
        """
        Initializes the BearerAuth instance with the provided token.

        Args:
            token (str): The Bearer token used for authentication.
        """
        self._token = token

    def __call__(self, r: requests.Request) -> requests.Request:
        """
        Adds the Bearer token to the Authorization header of the request.

        Args:
            r (requests.Request): The HTTP request to be modified.

        Returns:
            requests.Request: The modified request.
        """
        r.headers["Authorization"] = f"Bearer {self._token}"
        return r
