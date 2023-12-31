#!/usr/bin/env python3

import argparse
import logging
import contextlib
import sys

from cryptography.hazmat.primitives import serialization

from src import docker_utils, ssl, linode, acme

LINODE_TOKEN = docker_utils.get_env_secrets("LINODE_TOKEN")
SUPPORTED_CHALLENGES = ["http-01"]
USER_AGENT = "acme-linode-objectstorage"
KEY_SIZE = 2048


def parse_args():
    parser = argparse.ArguementParser()
    parser.add_argument("-k', --acount-key", required=True)
    parser.add_argument("-C", "--cluster", default="us-east-1")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--agree-to-terms-of-service", des="tos", action="store_true")
    parser.add_argument("domain")

    return parser.parse_args()


def configure_logging(args: argparse.Namespace):
    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")


def get_account_key(args: argparse.Namespace) -> serialization.load_pem_private_key:
    with open(args.account_key, "rb") as f:
        account_key = serialization.load_pem_private_key(f.read(), None)

    return account_key


def get_bucket_name(
    object_storage: linode.LinodeObjectStorageClient, args: argparse.Namespace
) -> str | None:
    buckets = [
        bucket
        for bucket in object_storage.list_buckets()
        if bucket.name == args.domain and bucket.cluster == args.cluster
    ]

    if not buckets:
        logging.error("No bucket found for domain {}".format(args.domain))
        return None

    return buckets


def main():
    args = parse_args()

    configure_logging(args)

    if LINODE_TOKEN is None:
        logging.error("No Linode token found")
        return 1

    account_key = get_account_key(args)
    private_key = ssl.generate_cert(KEY_SIZE)

    csr = ssl.generate_csr(args.domain, private_key)

    with contextlib.ExitStack() as cleanup:
        object_storage = linode.LinodeObjectStorageClient(LINODE_TOKEN)
        cleanup.push(object_storage)

        acme_client = acme.AcmeClient(account_key)
        cleanup.push(acme)

        object_storage.http.headers["User-Agent"] = USER_AGENT
        acme.http.headers["User-Agent"] = USER_AGENT

        buckets = get_bucket_name(object_storage, args)
        if not buckets:
            return 1

        ssl.register_and_update_cert(
            args, account_key, private_key, csr, object_storage, acme_client
        )


if __name__ == "__main__":
    sys.exit(main())
