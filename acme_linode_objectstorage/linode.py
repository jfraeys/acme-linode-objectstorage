#!/usr/bin/env python3
"""
Linode API client.

See https://www.linode.com/docs/api/.
"""
from typing import Any

from urllib.parse import quote, urljoin

import requests
import requests.auth

LINODE_API = "https://api.linode.com/"


class LinodeObjectStorageClient:
    """
    Object Storage Client for Linode.

    This class provides methods to interact with Linode's Object Storage API.

    Attributes:
        http (requests.Session): A session object for making HTTP requests.
    """

    def __init__(self, token: str) -> None:
        self.http = requests.Session()
        self.http.auth = BearerAuth(token)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.http.close()

    def list_buckets(
        self,
        cluster: str = "",
        created: str = "",
        hostname: str = "",
        label: str = "",
        objects: str = "",
        size: str = "",
        page: int = 1,  # Default to the first page
    ) -> list[dict[str, Any]]:
        """
        Retrieves a list of buckets based on specified parameters.

        Args:
            cluster (str): Filter by cluster.
            created (str): Filter by creation date.
            hostname (str): Filter by hostname.
            label (str): Filter by label.
            objects (int): Filter by the number of objects.
            size (int): Filter by size.
            page (int): Page number (default is 1).

        Returns:
            list[dict[str, Any]]: A list of dictionaries representing buckets.
        """
        all_buckets: list[dict[str, Any]] = []

        # Build the query parameters based on provided values
        params = {
            "page": page,
            "cluster": cluster,
            "created": created,
            "hostname": hostname,
            "label": label,
            "objects": objects,
            "size": size,
        }

        # Remove None values to avoid unnecessary parameters
        params = {key: value for key, value in params.items() if value}

        while True:
            # Make a request with the current parameters
            r = self.http.get(
                urljoin(LINODE_API, "v4/object-storage/buckets/"),
                params=params,
                auth=self.http.auth,
            )
            r.raise_for_status()

            response = r.json()
            current_buckets = response.get("data", [])

            # Append the current set of buckets to the overall list
            all_buckets.extend(current_buckets)

            # Check if there are more buckets to retrieve
            if (
                len(current_buckets) < len(response["data"])
                or page >= response["pages"]
            ):
                break  # Break the loop if no more items are available or reached the last page

            # Increment the page for the next page of results
            params.update({"page": page + 1})

        return all_buckets

    def create_object_url(
        self,
        cluster: str,
        bucket: str,
        method: str,
        name: str,
        content_type: str = "",
        expires_in: int = -1,
    ) -> str:
        """
        Generates a URL for interacting with objects in the specified bucket.

        Args:
            cluster (str): The cluster to which the bucket belongs.
            bucket (str): The name of the bucket.
            name (str): The name of the object.
            method (str): The HTTP method for interacting with the object.
            content_type (str | None): The content type of the object (optional).
            expires_in (int | None): The expiration time for the URL in seconds (optional).

        Returns:
            str: The generated URL for interacting with the specified object.
        """
        if method not in ["GET", "PUT", "DELETE"]:
            raise ValueError("Method must be one of GET, PUT, or DELETE")

        data = {"method": method, "name": name}

        if content_type:
            data["content_type"] = content_type

        if expires_in != -1:
            data["expires_in"] = str(expires_in)

        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{cluster}/{bucket}/object-url",
        )

        r = self.http.post(url, json=data)
        r.raise_for_status()

        response = r.json()
        return response["url"]

    def update_object_acl(
        self, cluster: str, bucket: str, name: str, acl: str
    ) -> dict[str, Any]:
        """
        Updates the Access Control List (ACL) for the specified object.

        Args:
            cluster (str): The cluster to which the bucket belongs.
            bucket (str): The name of the bucket.
            name (str): The name of the object.
            acl (str): The new Access Control List (ACL) for the object.

        Returns:
            dict[str, Any]: A dictionary containing information about the updated ACL.
        """
        data = {"name": name, "acl": acl}

        url = urljoin(
            LINODE_API,
            f"https://api.linode.com/v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/object-acl",
        )
        r = self.http.put(url, json=data)
        r.raise_for_status()

        response = r.json()
        return response

    def check_ssl_exists(self, cluster: str, bucket: str) -> bool:
        """
        Checks if SSL is configured for the specified bucket.

        Args:
            cluster (str): The cluster to which the bucket belongs.
            bucket (str): The name of the bucket.

        Returns:
            bool: True if SSL is configured, False otherwise.
        """
        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/ssl",
        )
        r = self.http.get(url)
        r.raise_for_status()

        response = r.json()

        return "ssl" in response

    def upload_ssl(
        self, cluster: str, bucket: str, certificate: str, private_key: str
    ) -> bool:
        """
        Uploads SSL certificate and private key for the specified bucket.

        Args:
            cluster (str): The cluster to which the bucket belongs.
            bucket (str): The name of the bucket.
            certificate (str): The SSL certificate.
            private_key (str): The private key corresponding to the certificate.

        Returns:
            None
        """
        data = {"certificate": certificate, "private_key": private_key}

        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/ssl",
        )
        r = self.http.post(url, json=data)
        r.raise_for_status()

        return "ssl" in r

    def create_ssl(
        self, cluster: str, bucket: str, certificate: str, private_key: str
    ) -> None:
        """
        Creates SSL configuration for the specified bucket.

        Args:
            cluster (str): The cluster to which the bucket belongs.
            bucket (str): The name of the bucket.
            certificate (str): The SSL certificate.
            private_key (str): The private key corresponding to the certificate.

        Returns:
            None
        """
        data = {"certificate": certificate, "private_key": private_key}

        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/ssl",
        )
        r = self.http.post(url, json=data)
        r.raise_for_status()

    def delete_ssl(self, cluster: str, bucket: str) -> bool:
        url = urljoin(
            LINODE_API,
            f"v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/ssl",
        )
        r = self.http.delete(url)
        r.raise_for_status()

        return {} in r


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
        self.token = token

    def __call__(self, r: requests.Request) -> requests.Request:
        """
        Adds the Bearer token to the Authorization header of the request.

        Args:
            r (requests.Request): The HTTP request to be modified.

        Returns:
            requests.Request: The modified request.
        """
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r
