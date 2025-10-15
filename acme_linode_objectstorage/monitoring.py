"""
Simple monitoring utilities.
"""

import logging
import time
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@contextmanager
def timer(operation_name: str):
    """
    Simple timer context manager.

    Usage:
        with timer("Process bucket"):
            # do work
    """
    start = time.monotonic()
    logger.debug(f"Starting: {operation_name}")

    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        logger.info(f"{operation_name} completed in {elapsed:.2f}s")
