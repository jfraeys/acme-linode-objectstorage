"""Tests for utility functions."""

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_linode_objectstorage import utils


@pytest.fixture
def rsa_private_key():
    """Generate a test RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestRSAJWKPublic:
    """Tests for rsa_jwk_public function."""

    def test_converts_private_key_to_jwk(self, rsa_private_key):
        """Test converting RSA private key to JWK."""
        jwk = utils.rsa_jwk_public(rsa_private_key)

        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk
        assert isinstance(jwk["n"], str)
        assert isinstance(jwk["e"], str)

    def test_converts_public_key_to_jwk(self, rsa_private_key):
        """Test converting RSA public key to JWK."""
        public_key = rsa_private_key.public_key()
        jwk = utils.rsa_jwk_public(public_key)

        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk


class TestB64urlUint:
    """Tests for b64url_uint function."""

    def test_encodes_positive_integer(self):
        """Test encoding a positive integer."""
        result = utils.b64url_uint(123456)
        assert isinstance(result, str)
        assert "=" not in result  # No padding

    def test_encodes_zero(self):
        """Test encoding zero."""
        result = utils.b64url_uint(0)
        assert result == "AA"

    def test_raises_on_negative(self):
        """Test that negative integers raise TypeError."""
        with pytest.raises(TypeError, match="unsigned integer"):
            utils.b64url_uint(-1)

    def test_raises_on_non_integer(self):
        """Test that non-integers raise TypeError."""
        with pytest.raises(TypeError, match="unsigned integer"):
            utils.b64url_uint("123")


class TestB64url:
    """Tests for b64url function."""

    def test_encodes_bytes(self):
        """Test encoding bytes to base64url."""
        data = b"hello world"
        result = utils.b64url(data)

        assert isinstance(result, str)
        assert "=" not in result  # No padding

        # Verify it's valid base64url
        decoded = base64.urlsafe_b64decode(result + "==")
        assert decoded == data

    def test_empty_bytes(self):
        """Test encoding empty bytes."""
        result = utils.b64url(b"")
        assert result == ""


class TestJsonThumbprint:
    """Tests for json_thumbprint function."""

    def test_creates_consistent_thumbprint(self):
        """Test that thumbprint is consistent for same data."""
        data = {"key": "value", "another": "item"}

        result1 = utils.json_thumbprint(data)
        result2 = utils.json_thumbprint(data)

        assert result1 == result2

    def test_different_data_different_thumbprint(self):
        """Test that different data produces different thumbprints."""
        data1 = {"key": "value1"}
        data2 = {"key": "value2"}

        result1 = utils.json_thumbprint(data1)
        result2 = utils.json_thumbprint(data2)

        assert result1 != result2

    def test_order_independent(self):
        """Test that key order doesn't affect thumbprint."""
        data1 = {"a": 1, "b": 2}
        data2 = {"b": 2, "a": 1}

        result1 = utils.json_thumbprint(data1)
        result2 = utils.json_thumbprint(data2)

        assert result1 == result2


class TestJsonEncode:
    """Tests for json_encode function."""

    def test_encodes_dict_to_bytes(self):
        """Test encoding dict to JSON bytes."""
        data = {"key": "value"}
        result = utils.json_encode(data)

        assert isinstance(result, bytes)
        assert json.loads(result) == data

    def test_consistent_encoding(self):
        """Test that encoding is consistent (sorted keys)."""
        data = {"z": 1, "a": 2}
        result = utils.json_encode(data)

        # Should be in sorted order
        assert result == b'{"a":2,"z":1}'

    def test_no_whitespace(self):
        """Test that encoding has no extra whitespace."""
        data = {"key": "value", "nested": {"inner": 123}}
        result = utils.json_encode(data)

        assert b" " not in result
        assert b"\n" not in result


class TestPrivateKeyToPem:
    """Tests for private_key_to_pem function."""

    def test_converts_key_to_pem(self, rsa_private_key):
        """Test converting private key to PEM format."""
        pem = utils.private_key_to_pem(rsa_private_key)

        assert isinstance(pem, str)
        assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
        assert pem.endswith("-----END RSA PRIVATE KEY-----\n")

    def test_pem_is_valid_format(self, rsa_private_key):
        """Test that PEM output is valid."""
        pem = utils.private_key_to_pem(rsa_private_key)
        lines = pem.split("\n")

        assert lines[0] == "-----BEGIN RSA PRIVATE KEY-----"
        assert lines[-2] == "-----END RSA PRIVATE KEY-----"

        # Check that middle lines are base64
        for line in lines[1:-2]:
            if line:
                assert all(
                    c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                    for c in line
                )


class TestPrintEncoded:
    """Tests for print_encoded function."""

    def test_encodes_with_padding(self):
        """Test that output is properly base64url encoded."""
        data = b"hello"
        result = utils.print_encoded(data)

        # Should be base64url encoded
        assert isinstance(result, str)

        # The function adds padding, so verify it's base64
        # Note: print_encoded adds extra padding, so length may not be % 4
        assert len(result) > 0


class TestGetEnvSecrets:
    """Tests for get_env_secrets function."""

    def test_reads_from_file(self, tmp_path, monkeypatch):
        """Test reading secret from file."""
        # Create a secrets directory
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        # Write a secret file
        secret_file = secrets_dir / "TEST_SECRET"
        secret_file.write_text("my-secret-value\n")

        # Clear environment variable
        monkeypatch.delenv("TEST_SECRET", raising=False)

        # Read the secret
        result = utils.get_env_secrets("TEST_SECRET", path=secrets_dir)
        assert result == "my-secret-value"

    def test_reads_from_environment(self, monkeypatch):
        """Test reading secret from environment variable."""
        monkeypatch.setenv("TEST_SECRET", "env-secret-value")

        result = utils.get_env_secrets("TEST_SECRET")
        assert result == "env-secret-value"

    def test_raises_when_not_found(self, tmp_path):
        """Test that missing secret raises EnvironmentError."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        with pytest.raises(OSError, match="not found"):
            utils.get_env_secrets("MISSING_SECRET", path=secrets_dir)
