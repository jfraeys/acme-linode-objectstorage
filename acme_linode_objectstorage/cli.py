#!/usr/bin/env python3

import argparse
import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any

import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_linode_objectstorage import acme, exceptions, linode, utils
from acme_linode_objectstorage.certificate import generate_csr, generate_private_key
from acme_linode_objectstorage.ssl import (
    register_acme_account,
    register_and_update_cert,
)

logging.getLogger(__name__)

USER_AGENT = "acme-linode-objectstorage"
KEY_SIZE = 2048


def get_linode_token(linode_token_env_var: str = "LINODE_API_TOKEN") -> str:
    """
    Get Linode API token from environment.

    Returns:
        str: The Linode API token

    Raises:
        ValueError: If token is not found or empty
    """
    # Try docker secrets first
    token: str | None = utils.get_env_secrets(linode_token_env_var)

    # Fallback to regular environment variable
    if not token:
        token = os.getenv(linode_token_env_var)

    if not token:
        raise ValueError(
            "LINODE_API_TOKEN not found. Please set it as an environment variable:\n"
            "  export LINODE_API_TOKEN='your-token-here'\n"
            "Or pass it via Docker secrets."
        )

    # Validate token format (basic check)
    token = token.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", token):
        raise ValueError(
            f"{linode_token_env_var} appears to be invalid (wrong format or length)"
        )

    logging.debug(f"Using Linode token: {token[:8]}..." if token else "No token found")
    return token


def parse_args() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Automated SSL certificate management for Linode Object Storage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single custom domain (auto-discovers bucket via DNS)
  %(prog)s -k account.pem -d cdn.example.com --tos

  # Multiple custom domains
  %(prog)s -k account.pem -d cdn.example.com -d assets.example.com --tos

  # Specify bucket explicitly (skips DNS lookup)
  %(prog)s -k account.pem -d cdn.example.com -b my-bucket --tos

  # Using staging environment for testing
  %(prog)s -k account.pem -d test.example.com --dry-run --tos

Note: Domains must have CNAME records pointing to Linode Object Storage buckets
  (e.g., cdn.example.com → bucket1.us-east-1.linodeobjects.com)
""",
    )
    parser.add_argument(
        "-k",
        "--account-key",
        dest="account_key",
        required=True,
        help="Path to the ACME account private key file",
    )
    parser.add_argument(
        "-d",
        "--domain",
        action="append",
        type=str,
        required=True,
        help="Custom domain name (e.g., cdn.example.com). Can be specified multiple times.",
    )
    parser.add_argument(
        "-b",
        "--bucket",
        action="append",
        type=str,
        help="Bucket label (optional). If not provided, will be auto-discovered via DNS. "
        "If provided, must match the order of --domain flags.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use the ACME staging environment for testing",
    )
    parser.add_argument(
        "-tos",
        "--agree-to-terms-of-service",
        dest="tos",
        action="store_true",
        help="Agree to the ACME terms of service",
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Process domains sequentially instead of in parallel",
    )

    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    """
    Configures the logging settings based on the verbosity level.

    Args:
        verbose: If True, enable DEBUG logging; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")


def load_account_key(account_key_file: Path) -> rsa.RSAPrivateKey | None:
    """
    Loads an RSA private key from a PEM file.

    Args:
        account_key_file: Path to the private key file.

    Returns:
        rsa.RSAPrivateKey | None: The loaded private key, or None if loading fails.
    """
    try:
        key_data = account_key_file.read_bytes()
        account_key = serialization.load_pem_private_key(key_data, password=None)

        if not isinstance(account_key, rsa.RSAPrivateKey):
            raise TypeError(f"Invalid account key type: {type(account_key)}")

        return account_key

    except FileNotFoundError:
        logging.error(f"Key file not found: {account_key_file}")
    except ValueError as e:
        logging.error(f"Invalid key format in {account_key_file}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error loading key from {account_key_file}: {e}")

    return None


def discover_bucket_from_dns(domain: str) -> tuple[str | None, str | None]:
    """
    Discover the Linode bucket name and cluster from DNS CNAME records.

    Args:
        domain: Custom domain name (e.g., cdn.example.com)

    Returns:
        tuple[str | None, str | None]: (bucket_label, cluster) or (None, None) if not found

    Example:
        cdn.example.com → CNAME → bucket1.us-east-1.linodeobjects.com
        Returns: ('bucket1', 'us-east-1')
    """
    try:
        logging.debug(f"Looking up DNS records for: {domain}")

        # Query CNAME records
        answers = dns.resolver.resolve(domain, "CNAME")

        for rdata in answers:
            cname = str(rdata.target).rstrip(".")
            logging.debug(f"Found CNAME: {domain} → {cname}")

            # Parse Linode Object Storage hostname
            # Expected format: bucket-name.region.linodeobjects.com
            match = re.match(r"^([^.]+)\.([^.]+)\.linodeobjects\.com$", cname)

            if match:
                bucket_label = match.group(1)
                cluster = match.group(2)
                logging.info(
                    f"Discovered bucket '{bucket_label}' in cluster '{cluster}' for domain '{domain}'"
                )
                return (bucket_label, cluster)
            else:
                logging.warning(
                    f"CNAME '{cname}' doesn't match Linode Object Storage format"
                )

        logging.warning(f"No Linode Object Storage CNAME found for: {domain}")
        return (None, None)

    except dns.resolver.NXDOMAIN:
        logging.error(f"Domain does not exist: {domain}")
        return (None, None)
    except dns.resolver.NoAnswer:
        logging.error(f"No CNAME record found for: {domain}")
        return (None, None)
    except Exception as e:
        logging.error(f"DNS lookup failed for {domain}: {e}")
        return (None, None)


def find_bucket_by_label(
    object_storage: linode.LinodeObjectStorageClient, label: str
) -> dict[str, Any] | None:
    """
    Find a bucket by its label.

    Args:
        object_storage: Linode object storage client.
        label: Bucket label to find.

    Returns:
        dict[str, Any] | None: Bucket information or None if not found.
    """
    bucket_list = object_storage.list_buckets()
    return next((b for b in bucket_list if b.get("label") == label), None)


def create_domain_bucket_mapping(
    object_storage: linode.LinodeObjectStorageClient,
    domains: list[str],
    bucket_labels: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Create a mapping of custom domains to their buckets.

    Args:
        object_storage: Linode object storage client.
        domains: List of custom domain names.
        bucket_labels: Optional list of bucket labels. If None, will auto-discover via DNS.

    Returns:
        list[dict[str, Any]]: List of domain-bucket mappings.

    Raises:
        ValueError: If explicit buckets provided but count doesn't match domains.
        exceptions.BucketNotFoundError: If a bucket is not found.
    """
    # If buckets provided explicitly, validate count matches
    if bucket_labels is not None and len(domains) != len(bucket_labels):
        raise ValueError(
            f"Number of domains ({len(domains)}) must match number of buckets ({len(bucket_labels)})"
        )

    mappings = []

    for i, domain in enumerate(domains):
        # Determine bucket labeli
        if bucket_labels and i < len(bucket_labels):
            # Use explicit bucket label
            label = bucket_labels[i]
            logging.debug(f"Using explicit bucket '{label}' for domain '{domain}'")
        else:
            # Auto-discover from DNS
            label, _ = discover_bucket_from_dns(domain)
            if not label:
                raise ValueError(
                    f"Could not discover bucket for domain '{domain}'. "
                    f"Make sure the domain has a CNAME pointing to a Linode Object Storage bucket, "
                    f"or provide the bucket explicitly with -b/--bucket."
                )

        # Find the bucket
        bucket = find_bucket_by_label(object_storage, label)
        if not bucket:
            raise exceptions.BucketNotFoundError(label)

        # Create mapping with custom domain
        mapping = {
            **bucket,  # Include all original bucket info
            "custom_domain": domain,  # Add custom domain
            "bucket_hostname": bucket.get("hostname"),  # Preserve original bucket hostname
            "hostname": domain,  # Override hostname with custom domain
        }

        logging.debug(
            f"Mapped domain '{domain}' to bucket '{label}' "
            f"(cluster: {bucket.get('cluster')}, endpoint: {bucket.get('endpoint_type')})"
        )

        mappings.append(mapping)

    return mappings


async def process_domain_async(
    domain_bucket: dict[str, Any],
    acme_client: acme.AcmeClient,
    object_storage: linode.LinodeObjectStorageClient,
    account: Any,
) -> tuple[str, int]:
    """
    Process a single domain to obtain and install SSL certificate (async).

    Args:
        domain_bucket: Domain-bucket mapping with custom_domain field.
        acme_client: ACME client.
        object_storage: Object storage client.
        account: ACME account.

    Returns:
        tuple[str, int]: (domain, result_code) where result_code is 0 for success, 1 for failure.
    """
    domain = domain_bucket.get("custom_domain")
    label = domain_bucket.get("label", "unknown")

    if not domain:
        logging.warning(f"Skipping bucket without custom domain: {label}")
        return (label, 1)

    logging.info(f"[{domain}] Processing certificate for custom domain")
    logging.debug(
        f"[{domain}] Bucket: {label}, cluster: {domain_bucket.get('cluster')}, "
        f"endpoint: {domain_bucket.get('endpoint_type')}"
    )

    try:
        # Run CPU-bound operations in thread pool
        loop = asyncio.get_event_loop()
        private_key = await loop.run_in_executor(None, generate_private_key, KEY_SIZE)

        # Include bucket hostname in SAN if it exists and differs from custom domain
        additional_domains = []
        bucket_hostname = domain_bucket.get("bucket_hostname")
        if bucket_hostname and bucket_hostname != domain:
            additional_domains.append(bucket_hostname)

        csr = await loop.run_in_executor(None, generate_csr, domain, private_key, additional_domains)

        logging.debug(f"[{domain}] Generated CSR")

        # Register and update certificate
        result = await loop.run_in_executor(
            None,
            register_and_update_cert,
            acme_client,
            object_storage,
            domain_bucket,
            csr,
            private_key,
            account,
        )

        if result != 0:
            logging.error(f"[{domain}] Certificate registration failed")
        else:
            logging.info(f"[{domain}] Successfully updated certificate")

        return (domain, result)

    except Exception as e:
        logging.exception(f"[{domain}] Unexpected error: {e}")
        return (domain, 1)


def process_domain_sync(
    domain_bucket: dict[str, Any],
    acme_client: acme.AcmeClient,
    object_storage: linode.LinodeObjectStorageClient,
    account: Any,
) -> tuple[str, int]:
    """
    Process a single domain to obtain and install SSL certificate (synchronous).

    Args:
        domain_bucket: Domain-bucket mapping with custom_domain field.
        acme_client: ACME client.
        object_storage: Object storage client.
        account: ACME account.

    Returns:
        tuple[str, int]: (domain, result_code) where result_code is 0 for success, 1 for failure.
    """
    domain = domain_bucket.get("custom_domain")
    label = domain_bucket.get("label", "unknown")

    if not domain:
        logging.warning(f"Skipping bucket without custom domain: {label}")
        return (label, 1)

    logging.info(f"Processing certificate for: {domain} (bucket: {label})")
    logging.debug(
        f"Domain: {domain}, bucket: {label}, cluster: {domain_bucket.get('cluster')}"
    )

    # Generate key and CSR for this certificate
    private_key = generate_private_key(KEY_SIZE)

    # Include bucket hostname in SAN if it exists and differs from custom domain
    additional_domains = []
    bucket_hostname = domain_bucket.get("bucket_hostname")
    if bucket_hostname and bucket_hostname != domain:
        additional_domains.append(bucket_hostname)

    csr = generate_csr(domain, private_key, additional_domains)

    logging.debug(f"Generated CSR for domain: {domain}")

    # Register and update certificate
    result = register_and_update_cert(
        acme_client=acme_client,
        object_storage=object_storage,
        bucket=domain_bucket,
        csr=csr,
        private_key=private_key,
        account=account,
    )

    if result != 0:
        logging.error(f"Certificate registration failed for: {domain}")
    else:
        logging.info(f"Successfully updated certificate for: {domain}")

    return (domain, result)


async def process_domains_parallel(
    domain_buckets: list[dict[str, Any]],
    acme_client: acme.AcmeClient,
    object_storage: linode.LinodeObjectStorageClient,
    account: Any,
) -> list[tuple[str, int]]:
    """
    Process multiple domains in parallel.

    Args:
        domain_buckets: List of domain-bucket mappings.
        acme_client: ACME client.
        object_storage: Object storage client.
        account: ACME account.

    Returns:
        list[tuple[str, int]]: List of (domain, result_code) tuples.
    """
    logging.info(f"Processing {len(domain_buckets)} domain(s) in parallel")

    tasks = [
        process_domain_async(db, acme_client, object_storage, account)
        for db in domain_buckets
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle any exceptions that occurred
    processed_results: list[tuple[str, int]] = []
    for i, result in enumerate(results):
        if isinstance(result, BaseException):
            domain = domain_buckets[i].get("custom_domain", "unknown")
            logging.error(f"[{domain}] Task failed with exception: {result}")
            processed_results.append((domain, 1))
        else:
            processed_results.append(result)

    return processed_results


def process_domains_sequential(
    domain_buckets: list[dict[str, Any]],
    acme_client: acme.AcmeClient,
    object_storage: linode.LinodeObjectStorageClient,
    account: Any,
) -> list[tuple[str, int]]:
    """
    Process multiple domains sequentially.

    Args:
        domain_buckets: List of domain-bucket mappings.
        acme_client: ACME client.
        object_storage: Object storage client.
        account: ACME account.

    Returns:
        list[tuple[str, int]]: List of (domain, result_code) tuples.
    """
    logging.info(f"Processing {len(domain_buckets)} domain(s) sequentially")

    results = []
    for db in domain_buckets:
        result = process_domain_sync(db, acme_client, object_storage, account)
        results.append(result)

    return results


def main() -> int:
    """
    Main entry point for the CLI.

    Returns:
        int: Exit code (0 for success, 1 for failure).
    """
    args = parse_args()
    configure_logging(args.verbose)

    try:
        # Load Linode token
        linode_token = get_linode_token()

        # Load account key
        account_key = load_account_key(Path.cwd().joinpath(args.account_key))
        if not account_key:
            logging.error("Failed to load account key")
            return 1

        # Initialize Linode Object Storage client
        object_storage = linode.LinodeObjectStorageClient(linode_token)
        object_storage.add_headers({"User-Agent": USER_AGENT})

        # Create domain-bucket mappings (auto-discover if buckets not provided)
        logging.info(f"Resolving {len(args.domain)} custom domain(s)")
        domain_buckets = create_domain_bucket_mapping(
            object_storage, args.domain, args.bucket
        )

        if not domain_buckets:
            logging.error("No valid domain-bucket mappings created")
            return 1

        # Log the mappings
        logging.info("Domain-bucket mappings:")
        for db in domain_buckets:
            logging.info(f"  {db['custom_domain']} → {db['label']}")

        # Initialize ACME client
        acme_client = acme.AcmeClient(account_key=account_key, dry_run=args.dry_run)
        acme_client.add_headers({"User-Agent": USER_AGENT})

        if args.dry_run:
            logging.warning("=" * 60)
            logging.warning("DRY-RUN MODE ENABLED")
            logging.warning("  - Using ACME staging environment")
            logging.warning("  - Certificates will NOT be trusted by browsers")
            logging.warning("  - Use for testing only")
            logging.warning("=" * 60)

        # Register ACME account
        account = register_acme_account(acme_client, args.tos)
        if not account:
            logging.error("Failed to register ACME account")
            return 1

        # Process domains (parallel or sequential)
        if args.no_parallel or len(domain_buckets) == 1:
            # Sequential processing
            results = process_domains_sequential(
                domain_buckets, acme_client, object_storage, account
            )
        else:
            # Parallel processing
            results = asyncio.run(
                process_domains_parallel(
                    domain_buckets, acme_client, object_storage, account
                )
            )

        # Report results
        logging.info("=" * 60)
        logging.info("Certificate Update Summary:")
        failed_domains = []
        for domain, result_code in results:
            if result_code == 0:
                logging.info(f"  ✓ {domain}: SUCCESS")
            else:
                logging.error(f"  ✗ {domain}: FAILED")
                failed_domains.append(domain)

        # Return failure if any domain failed
        if failed_domains:
            logging.error("=" * 60)
            logging.error(
                f"Failed to update {len(failed_domains)} domain(s): {', '.join(failed_domains)}"
            )
            return 1

        logging.info("=" * 60)
        logging.info(f"All {len(results)} certificate(s) updated successfully")
        return 0

    except exceptions.BucketNotFoundError as e:
        logging.error(str(e))
        return 1
    except ValueError as e:
        logging.error(str(e))
        return 1
    except Exception as e:
        logging.exception("Unexpected error: %s", e)
        return 1


if __name__ == "__main__":
    exit(main())

