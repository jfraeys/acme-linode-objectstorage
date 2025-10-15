"""
ACME Linode Object Storage - Automated SSL certificate management for Linode Object Storage.
"""

from . import (
    acme,
    certificate,
    challenge,
    exceptions,
    linode,
    models,
    ssl,
    utils,
    validation,
)

# Import main public API
from .core import AcmeLinodeManager, CertificateResult

__version__ = "0.1.0"

__all__ = [
    # High-level API (recommended for most users)
    "AcmeLinodeManager",
    "CertificateResult",
    # Low-level modules (for advanced usage)
    "acme",
    "certificate",
    "challenge",
    "exceptions",
    "linode",
    "models",
    "ssl",
    "utils",
    "validation",
]
