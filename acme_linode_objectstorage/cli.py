#!/usr/bin/env python3
"""
Command-line interface for ACME Linode Object Storage.
"""

import argparse
import logging
import os
import re
import sys
from pathlib import Path

from acme_linode_objectstorage import utils
from acme_linode_objectstorage.core import AcmeLinodeManager

logger = logging.getLogger(__name__)

USER_AGENT = "acme-linode-objectstorage-cli"


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
        raise ValueError(f"{linode_token_env_var} appears to be invalid (wrong format or length)")

    logger.debug(f"Using Linode token: {token[:8]}..." if token else "No token found")
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
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
    logging.basicConfig(
        level=level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )


def create_domain_configs(
    domains: list[str],
    bucket_labels: list[str] | None = None,
) -> list[dict[str, str]]:
    """
    Create domain configuration list for the manager.

    Args:
        domains: List of custom domain names.
        bucket_labels: Optional list of bucket labels.

    Returns:
        list[dict[str, str]]: List of domain configurations.

    Raises:
        ValueError: If bucket count doesn't match domain count.
    """
    if bucket_labels and len(domains) != len(bucket_labels):
        raise ValueError(
            f"Number of domains ({len(domains)}) must match number of buckets ({len(bucket_labels)})"
        )

    configs = []
    for i, domain in enumerate(domains):
        config = {"domain": domain}
        if bucket_labels and i < len(bucket_labels):
            config["bucket_label"] = bucket_labels[i]
        configs.append(config)

    return configs


def main() -> int:
    """
    Main entry point for the CLI.

    Returns:
        int: Exit code (0 for success, 1 for failure).
    """
    args = parse_args()
    configure_logging(args.verbose)

    try:
        # Get Linode token
        linode_token = get_linode_token()

        # Validate account key exists
        account_key_path = Path.cwd() / args.account_key
        if not account_key_path.exists():
            logger.error(f"Account key file not found: {account_key_path}")
            return 1

        # Show dry-run warning
        if args.dry_run:
            logger.warning("=" * 60)
            logger.warning("DRY-RUN MODE ENABLED")
            logger.warning("  - Using ACME staging environment")
            logger.warning("  - Certificates will NOT be trusted by browsers")
            logger.warning("  - Use for testing only")
            logger.warning("=" * 60)

        # Create domain configurations
        logger.info(f"Processing {len(args.domain)} custom domain(s)")
        domain_configs = create_domain_configs(args.domain, args.bucket)

        # Initialize the manager
        logger.info("Initializing ACME Linode Manager")
        with AcmeLinodeManager(
            linode_token=linode_token,
            account_key_path=account_key_path,
            dry_run=args.dry_run,
            agree_tos=args.tos,
            user_agent=USER_AGENT,
        ) as manager:
            # Provision certificates
            parallel = not args.no_parallel and len(domain_configs) > 1

            if parallel:
                logger.info(f"Processing {len(domain_configs)} domain(s) in parallel")
            else:
                logger.info(f"Processing {len(domain_configs)} domain(s) sequentially")

            results = manager.provision_certificates(domain_configs, parallel=parallel)

        # Report results
        logger.info("=" * 60)
        logger.info("Certificate Update Summary:")

        failed_domains = []
        for result in results:
            if result.success:
                logger.info(f"  ✓ {result.domain}: SUCCESS")
            else:
                logger.error(f"  ✗ {result.domain}: FAILED")
                if result.error_message:
                    logger.error(f"    Error: {result.error_message}")
                failed_domains.append(result.domain)

        # Final summary
        if failed_domains:
            logger.error("=" * 60)
            logger.error(
                f"Failed to update {len(failed_domains)} domain(s): {', '.join(failed_domains)}"
            )
            return 1

        logger.info("=" * 60)
        logger.info(f"All {len(results)} certificate(s) updated successfully")
        return 0

    except ValueError as e:
        logger.error(str(e))
        return 1
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user")
        return 130
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
