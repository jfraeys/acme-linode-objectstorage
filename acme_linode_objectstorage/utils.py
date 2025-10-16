import base64
import hashlib
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def rsa_jwk_public(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> dict:
    """
    Convert an RSA private key to a JSON Web Key (JWK) public key.

    Args:
        key (rsa.RSAPrivateKey): RSA private key.

    Raises:
        TypeError: If the key is not a valid RSA private key.

    Returns:
        dict: JWK public key.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()

    public_numbers = key.public_numbers()

    return {
        "kty": "RSA",
        "n": b64url_uint(public_numbers.n),
        "e": b64url_uint(public_numbers.e),
    }


def b64url_uint(n: int) -> str:
    """
    Convert an unsigned integer to a Base64url-encoded string.

    Args:
        n (int): Unsigned integer.

    Raises:
        TypeError: If the input is not an unsigned integer.

    Returns:
        str: Base64url-encoded string.
    """
    if not isinstance(n, int) or n < 0:
        raise TypeError("Input must be an unsigned integer")

    # Determine minimum number of bytes to represent n
    length = max(1, (n.bit_length() + 7) // 8)

    # Convert to bytes and base64url encode (no padding)
    encoded = base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=")

    return encoded.decode("ascii")


def b64url(data: bytes) -> str:
    """
    Convert binary data to a Base64url-encoded string.

    Args:
    - data (bytes): Binary data.

    Returns:
    - str: Base64url-encoded string.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_thumbprint(data: dict) -> str:
    """
    Calculate the JSON thumbprint (hash) of a dictionary.

    Args:
    - data (dict): Input data.

    Returns:
    - str: Base64url-encoded JSON thumbprint.
    """
    return b64url(hashlib.sha256(json_encode(data)).digest())


def json_encode(data: dict) -> bytes:
    """
    Encode a dictionary as JSON and convert it to bytes.

    Args:
    - data (dict): Input data.

    Returns:
    - bytes: JSON-encoded data.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def print_encoded(data: bytes) -> str:
    """
    Return a Base64url-encoded string with padding.

    Args:
    - data (bytes): Data to be encoded in Base64url format.

    Returns:
    - str: Base64url-encoded string with padding.
    """
    # Base64url encode the data (replace "+" with "-", "/" with "_")
    encoded = base64.urlsafe_b64encode(data)

    return encoded.decode("utf-8").rstrip("=") + "=" * (4 - len(encoded) % 4)


def private_key_to_pem(private_key):
    """
    Converts a private key object to PEM format.

    Args:
    - private_key: The private key object to convert.

    Returns:
    - str: PEM formatted string representation of the private key.
    """
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem_bytes.decode("ascii")


def get_env_secrets(name: str, path: Path = Path(Path.cwd() / "secrets/")) -> str | None:
    """
    Get an environment variable from either a file in the project secrets directory or an environment variable.

    Args:
        name (str): Environment variable name.
        path (Path): Path to the secrets directory (default: "secrets/").

    Returns:
        str: The environment variable.

    Raises:
        EnvironmentError: If the environment variable or secret file is not found.
    """
    secret = os.environ.get(name)

    if not secret and (path / name).exists():
        secret = (path / name).read_text().rstrip("\n")
        logging.debug(f"Loaded secret from file: {path}/{name}")
        return secret
    elif not secret and not (path / name).exists():
        raise OSError(f"Environment variable and/or secret file variable: {path}/{name} not found")
    return secret
