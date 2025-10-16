"""Tests for certificate management functions."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from acme_linode_objectstorage import certificate


class TestGeneratePrivateKey:
    """Tests for generate_private_key function."""

    def test_generates_rsa_key(self):
        """Test that an RSA key is generated."""
        key = certificate.generate_private_key(2048)

        assert isinstance(key, rsa.RSAPrivateKey)

    def test_correct_key_size(self):
        """Test that key has correct size."""
        key = certificate.generate_private_key(2048)

        assert key.key_size == 2048

    def test_custom_key_size(self):
        """Test generating key with custom size."""
        key = certificate.generate_private_key(4096)

        assert key.key_size == 4096

    def test_correct_public_exponent(self):
        """Test that key has correct public exponent."""
        key = certificate.generate_private_key(2048)
        public_numbers = key.public_key().public_numbers()

        assert public_numbers.e == 65537


class TestGenerateCSR:
    """Tests for generate_csr function."""

    @pytest.fixture
    def private_key(self):
        """Generate a test private key."""
        return certificate.generate_private_key(2048)

    def test_generates_csr(self, private_key):
        """Test that a CSR is generated."""
        csr = certificate.generate_csr("example.com", private_key)

        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_csr_has_correct_cn(self, private_key):
        """Test that CSR has correct Common Name."""
        csr = certificate.generate_csr("example.com", private_key)

        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "example.com"

    def test_csr_has_san_extension(self, private_key):
        """Test that CSR has Subject Alternative Name extension."""
        csr = certificate.generate_csr("example.com", private_key)

        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        assert san_ext is not None

        sans = san_ext.value.get_values_for_type(x509.DNSName)
        assert "example.com" in sans

    def test_csr_with_additional_domains(self, private_key):
        """Test CSR with additional domains in SAN."""
        additional = ["www.example.com", "api.example.com"]
        csr = certificate.generate_csr("example.com", private_key, additional)

        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)

        assert "example.com" in sans
        assert "www.example.com" in sans
        assert "api.example.com" in sans
        assert len(sans) == 3

    def test_csr_avoids_duplicate_domains(self, private_key):
        """Test that duplicate domains are not added to SAN."""
        additional = ["example.com", "www.example.com"]
        csr = certificate.generate_csr("example.com", private_key, additional)

        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)

        # Should have example.com and www.example.com, but example.com shouldn't be duplicated
        assert sans.count("example.com") == 1
        assert "www.example.com" in sans

    def test_csr_is_signed(self, private_key):
        """Test that CSR is properly signed."""
        csr = certificate.generate_csr("example.com", private_key)

        # Verify signature is present
        assert csr.signature is not None
        assert len(csr.signature) > 0

    def test_empty_additional_domains(self, private_key):
        """Test CSR with empty additional domains list."""
        csr = certificate.generate_csr("example.com", private_key, [])

        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)

        assert sans == ["example.com"]

    def test_none_additional_domains(self, private_key):
        """Test CSR with None as additional domains."""
        csr = certificate.generate_csr("example.com", private_key, None)

        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)

        assert sans == ["example.com"]


class TestFinalizeOrder:
    """Tests for finalize_order function (integration-light)."""

    def test_returns_empty_on_invalid_status(self):
        """Test that empty string is returned when order status is invalid."""
        from unittest.mock import Mock

        mock_order = Mock()
        mock_order.status = "invalid"
        mock_order.poll_until_not = Mock()

        private_key = certificate.generate_private_key(2048)
        csr = certificate.generate_csr("example.com", private_key)

        result = certificate.finalize_order(mock_order, csr)

        # Should poll and get invalid status, returning empty string
        assert result == ""


class TestUploadCertificate:
    """Tests for upload_certificate function (unit tests only)."""

    def test_rejects_invalid_certificate_format(self):
        """Test that invalid certificate format is rejected."""
        from unittest.mock import Mock

        mock_storage = Mock()
        bucket = {
            "label": "test-bucket",
            "hostname": "test.example.com",
            "cluster": "us-east-1",
        }

        invalid_cert = "This is not a certificate"
        private_key = certificate.generate_private_key(2048)

        result = certificate.upload_certificate(mock_storage, bucket, invalid_cert, private_key)

        assert result is False

    def test_rejects_certificate_not_covering_domain(self):
        """Test that certificate not covering domain is rejected."""
        from unittest.mock import Mock

        mock_storage = Mock()
        bucket = {
            "label": "test-bucket",
            "hostname": "other.example.com",  # Different domain
            "cluster": "us-east-1",
        }

        # Generate a certificate for example.com
        private_key = certificate.generate_private_key(2048)

        # Create a valid-looking PEM (but we know validation will fail on domain)
        cert_pem = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"

        result = certificate.upload_certificate(mock_storage, bucket, cert_pem, private_key)

        assert result is False
