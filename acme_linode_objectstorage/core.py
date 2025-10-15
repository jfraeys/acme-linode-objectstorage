"""
Core library interface for ACME Linode Object Storage.

This module provides a high-level, library-friendly API for automated SSL
certificate management on Linode Object Storage buckets.

Example usage:
    ```python
    from acme_linode_objectstorage import AcmeLinodeManager
    from pathlib import Path

    # Initialize manager
    manager = AcmeLinodeManager(
        linode_token="your-token",
        account_key_path=Path("account.pem"),
        dry_run=False
    )

    # Option 1: Auto-discover bucket from DNS
    result = manager.provision_certificate("cdn.example.com")

    # Option 2: Specify bucket explicitly
    result = manager.provision_certificate(
        domain="cdn.example.com",
        bucket_label="my-bucket"
    )

    # Option 3: Multiple domains
    results = manager.provision_certificates([
        {"domain": "cdn.example.com"},
        {"domain": "assets.example.com", "bucket_label": "assets-bucket"}
    ])
    ```
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_linode_objectstorage import acme, exceptions, linode
from acme_linode_objectstorage.certificate import generate_csr, generate_private_key
from acme_linode_objectstorage.ssl import (
    register_acme_account,
    register_and_update_cert,
)

logger = logging.getLogger(__name__)

DEFAULT_KEY_SIZE = 2048


@dataclass
class CertificateResult:
    """Result of a certificate provisioning operation."""

    domain: str
    success: bool
    error_message: str = ""
    bucket_label: str = ""
    cluster: str = ""

    def __bool__(self) -> bool:
        """Allow boolean evaluation of result."""
        return self.success

    def __repr__(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return f"<CertificateResult {self.domain}: {status}>"


class AcmeLinodeManager:
    """
    High-level manager for ACME certificate operations on Linode Object Storage.

    This class provides a clean API for provisioning and managing SSL certificates
    for custom domains on Linode Object Storage buckets.

    Attributes:
        linode_token: Linode API token for authentication.
        account_key: RSA private key for ACME account.
        dry_run: If True, use staging environment and don't make destructive changes.
        agree_tos: Whether to automatically agree to ACME terms of service.
        key_size: RSA key size for certificate private keys (default: 2048).
    """

    def __init__(
        self,
        linode_token: str,
        account_key: rsa.RSAPrivateKey | None = None,
        account_key_path: Path | None = None,
        dry_run: bool = False,
        agree_tos: bool = True,
        key_size: int = DEFAULT_KEY_SIZE,
        user_agent: str = "acme-linode-objectstorage-lib",
    ):
        """
        Initialize the ACME Linode manager.

        Args:
            linode_token: Linode API token.
            account_key: RSA private key for ACME account (optional).
            account_key_path: Path to PEM file containing account key (optional).
            dry_run: Use staging environment for testing.
            agree_tos: Automatically agree to ACME terms of service.
            key_size: RSA key size for certificates.
            user_agent: User agent string for API requests.

        Raises:
            ValueError: If neither account_key nor account_key_path is provided,
                       or if the key cannot be loaded.
        """
        if not linode_token:
            raise ValueError("linode_token is required")

        # Load account key
        if account_key is None and account_key_path is None:
            raise ValueError("Either account_key or account_key_path must be provided")

        if account_key is None and account_key_path:
            account_key = self._load_account_key(account_key_path)

        if account_key is None:
            raise ValueError("Failed to load account key")

        self.linode_token = linode_token
        self.account_key = account_key
        self.dry_run = dry_run
        self.agree_tos = agree_tos
        self.key_size = key_size
        self.user_agent = user_agent

        # Initialize clients (lazy initialization)
        self._object_storage: linode.LinodeObjectStorageClient | None = None
        self._acme_client: acme.AcmeClient | None = None
        self._acme_account: Any | None = None

    @property
    def object_storage(self) -> linode.LinodeObjectStorageClient:
        """Get or create Linode Object Storage client."""
        if self._object_storage is None:
            self._object_storage = linode.LinodeObjectStorageClient(
                self.linode_token, dry_run=self.dry_run
            )
            self._object_storage.add_headers({"User-Agent": self.user_agent})
        return self._object_storage

    @property
    def acme_client(self) -> acme.AcmeClient:
        """Get or create ACME client."""
        if self._acme_client is None:
            self._acme_client = acme.AcmeClient(
                account_key=self.account_key, dry_run=self.dry_run
            )
            self._acme_client.add_headers({"User-Agent": self.user_agent})
        return self._acme_client

    @property
    def acme_account(self) -> Any:
        """Get or create ACME account."""
        if self._acme_account is None:
            self._acme_account = register_acme_account(self.acme_client, self.agree_tos)
            if not self._acme_account:
                raise RuntimeError("Failed to register ACME account")
        return self._acme_account

    def _load_account_key(self, path: Path) -> rsa.RSAPrivateKey:
        """
        Load RSA private key from PEM file.

        Args:
            path: Path to PEM file.

        Returns:
            RSA private key.

        Raises:
            ValueError: If key cannot be loaded or is invalid.
        """
        try:
            key_data = path.read_bytes()
            key = serialization.load_pem_private_key(key_data, password=None)

            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError(f"Invalid key type: {type(key)}")

            return key

        except FileNotFoundError:
            raise ValueError(f"Account key file not found: {path}")
        except Exception as e:
            raise ValueError(f"Failed to load account key: {e}")

    def _discover_bucket_from_dns(self, domain: str) -> tuple[str | None, str | None]:
        """
        Discover bucket and cluster from DNS CNAME records.

        Args:
            domain: Custom domain name.

        Returns:
            Tuple of (bucket_label, cluster) or (None, None) if not found.
        """
        import re

        import dns.resolver

        try:
            logger.debug(f"Looking up DNS records for: {domain}")
            answers = dns.resolver.resolve(domain, "CNAME")

            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
                logger.debug(f"Found CNAME: {domain} → {cname}")

                # Parse Linode Object Storage hostname
                match = re.match(r"^([^.]+)\.([^.]+)\.linodeobjects\.com$", cname)

                if match:
                    bucket_label = match.group(1)
                    cluster = match.group(2)
                    logger.info(
                        f"Discovered bucket '{bucket_label}' in cluster '{cluster}'"
                    )
                    return (bucket_label, cluster)

            logger.warning(f"No Linode Object Storage CNAME found for: {domain}")
            return (None, None)

        except Exception as e:
            logger.error(f"DNS lookup failed for {domain}: {e}")
            return (None, None)

    def _find_bucket(self, label: str) -> dict[str, Any] | None:
        """
        Find a bucket by label.

        Args:
            label: Bucket label.

        Returns:
            Bucket information or None if not found.
        """
        buckets = self.object_storage.list_buckets()
        return next((b for b in buckets if b.get("label") == label), None)

    def _resolve_bucket(
        self, domain: str, bucket_label: str | None = None
    ) -> dict[str, Any]:
        """
        Resolve bucket information for a domain.

        Args:
            domain: Custom domain name.
            bucket_label: Optional bucket label (will auto-discover if not provided).

        Returns:
            Bucket information with custom domain.

        Raises:
            exceptions.BucketNotFoundError: If bucket cannot be found.
            ValueError: If DNS resolution fails.
        """
        # Determine bucket label
        if bucket_label is None:
            label, _ = self._discover_bucket_from_dns(domain)
            if not label:
                raise ValueError(
                    f"Could not discover bucket for domain '{domain}'. "
                    f"Make sure the domain has a CNAME pointing to a Linode bucket, "
                    f"or provide the bucket_label explicitly."
                )
        else:
            label = bucket_label

        # Find the bucket
        bucket = self._find_bucket(label)
        if not bucket:
            raise exceptions.BucketNotFoundError(label)

        # Create enhanced bucket info with custom domain
        return {
            **bucket,
            "custom_domain": domain,
            "bucket_hostname": bucket.get("hostname"),
            "hostname": domain,  # Override with custom domain
        }

    def provision_certificate(
        self,
        domain: str,
        bucket_label: str | None = None,
        additional_domains: list[str] | None = None,
    ) -> CertificateResult:
        """
        Provision an SSL certificate for a custom domain.

        This method:
        1. Resolves the bucket (auto-discover or explicit)
        2. Generates a private key and CSR
        3. Creates an ACME order
        4. Completes DNS challenges
        5. Obtains the certificate
        6. Uploads it to Linode Object Storage

        Args:
            domain: Custom domain name (e.g., "cdn.example.com").
            bucket_label: Optional bucket label. If not provided, will auto-discover
                         via DNS CNAME lookup.
            additional_domains: Additional domains to include in SAN (optional).

        Returns:
            CertificateResult with success status and details.

        Example:
            ```python
            result = manager.provision_certificate("cdn.example.com")
            if result.success:
                print(f"Certificate installed for {result.domain}")
            else:
                print(f"Failed: {result.error_message}")
            ```
        """
        try:
            logger.info(f"Starting certificate provisioning for: {domain}")

            # Resolve bucket
            bucket = self._resolve_bucket(domain, bucket_label)
            logger.debug(
                f"Resolved bucket: {bucket['label']} in cluster {bucket['cluster']}"
            )

            # Generate private key and CSR
            logger.debug(f"Generating {self.key_size}-bit private key")
            private_key = generate_private_key(self.key_size)

            # Prepare domains for CSR
            csr_domains = additional_domains or []
            bucket_hostname = bucket.get("bucket_hostname")
            if bucket_hostname and bucket_hostname != domain:
                if bucket_hostname not in csr_domains:
                    csr_domains.append(bucket_hostname)

            logger.debug(f"Creating CSR for domain: {domain}")
            if csr_domains:
                logger.debug(f"Including additional domains in SAN: {csr_domains}")

            csr = generate_csr(
                domain, private_key, csr_domains if csr_domains else None
            )

            # Register and update certificate
            logger.info("Obtaining certificate from ACME server")
            result_code = register_and_update_cert(
                acme_client=self.acme_client,
                object_storage=self.object_storage,
                bucket=bucket,
                csr=csr,
                private_key=private_key,
                account=self.acme_account,
            )

            if result_code == 0:
                logger.info(f"Successfully provisioned certificate for: {domain}")
                return CertificateResult(
                    domain=domain,
                    success=True,
                    bucket_label=bucket["label"],
                    cluster=bucket["cluster"],
                )
            else:
                logger.error(f"Failed to provision certificate for: {domain}")
                return CertificateResult(
                    domain=domain,
                    success=False,
                    error_message="Certificate registration failed",
                    bucket_label=bucket["label"],
                    cluster=bucket["cluster"],
                )

        except exceptions.BucketNotFoundError as e:
            logger.error(str(e))
            return CertificateResult(domain=domain, success=False, error_message=str(e))
        except ValueError as e:
            logger.error(str(e))
            return CertificateResult(domain=domain, success=False, error_message=str(e))
        except Exception as e:
            logger.exception(f"Unexpected error provisioning certificate: {e}")
            return CertificateResult(
                domain=domain, success=False, error_message=f"Unexpected error: {e}"
            )

    def provision_certificates(
        self, domains: list[dict[str, Any]], parallel: bool = True
    ) -> list[CertificateResult]:
        """
        Provision certificates for multiple domains.

        Args:
            domains: List of domain configurations. Each item should be a dict with:
                    - "domain": str (required) - The custom domain name
                    - "bucket_label": str (optional) - Explicit bucket label
                    - "additional_domains": list[str] (optional) - Additional SANs
            parallel: If True, process domains concurrently (default: True).

        Returns:
            List of CertificateResult objects.

        Example:
            ```python
            results = manager.provision_certificates([
                {"domain": "cdn.example.com"},
                {"domain": "assets.example.com", "bucket_label": "assets"},
                {"domain": "media.example.com", "additional_domains": ["www.media.example.com"]}
            ])

            for result in results:
                if result.success:
                    print(f"✓ {result.domain}")
                else:
                    print(f"✗ {result.domain}: {result.error_message}")
            ```
        """
        if not domains:
            return []

        if parallel and len(domains) > 1:
            return self._provision_certificates_parallel(domains)
        else:
            return self._provision_certificates_sequential(domains)

    def _provision_certificates_sequential(
        self, domains: list[dict[str, Any]]
    ) -> list[CertificateResult]:
        """Process domains sequentially."""
        logger.info(f"Processing {len(domains)} domain(s) sequentially")
        results = []

        for config in domains:
            domain = config.get("domain")
            if not domain:
                logger.warning("Skipping domain config without 'domain' field")
                results.append(
                    CertificateResult(
                        domain="unknown",
                        success=False,
                        error_message="Missing 'domain' field",
                    )
                )
                continue

            result = self.provision_certificate(
                domain=domain,
                bucket_label=config.get("bucket_label"),
                additional_domains=config.get("additional_domains"),
            )
            results.append(result)

        return results

    def _provision_certificates_parallel(
        self, domains: list[dict[str, Any]]
    ) -> list[CertificateResult]:
        """Process domains in parallel."""
        import asyncio

        logger.info(f"Processing {len(domains)} domain(s) in parallel")

        async def process_async(config: dict[str, Any]) -> CertificateResult:
            """Async wrapper for provision_certificate."""
            domain = config.get("domain")
            if not domain:
                return CertificateResult(
                    domain="unknown",
                    success=False,
                    error_message="Missing 'domain' field",
                )

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                self.provision_certificate,
                domain,
                config.get("bucket_label"),
                config.get("additional_domains"),
            )

        async def gather_results() -> list[CertificateResult]:
            tasks = [process_async(config) for config in domains]
            return await asyncio.gather(*tasks, return_exceptions=False)

        # Run the async gathering
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an event loop, create a new task
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, gather_results())
                    return future.result()
            else:
                # No event loop running, safe to use asyncio.run
                return asyncio.run(gather_results())
        except Exception as e:
            logger.exception(f"Error in parallel processing: {e}")
            # Fall back to sequential processing
            logger.warning("Falling back to sequential processing")
            return self._provision_certificates_sequential(domains)

    def list_buckets(self) -> list[dict[str, Any]]:
        """
        List all Object Storage buckets.

        Returns:
            List of bucket information dictionaries.

        Example:
            ```python
            buckets = manager.list_buckets()
            for bucket in buckets:
                print(f"{bucket['label']} in {bucket['cluster']}")
            ```
        """
        return self.object_storage.list_buckets()

    def close(self) -> None:
        """
        Close all client connections.

        Should be called when done using the manager, especially in long-running
        applications. Can also be used via context manager.

        Example:
            ```python
            manager = AcmeLinodeManager(...)
            try:
                manager.provision_certificate("cdn.example.com")
            finally:
                manager.close()
            ```
        """
        if self._object_storage:
            self._object_storage.close()
        if self._acme_client:
            self._acme_client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def __repr__(self) -> str:
        mode = "DRY-RUN" if self.dry_run else "PRODUCTION"
        return f"<AcmeLinodeManager mode={mode}>"
