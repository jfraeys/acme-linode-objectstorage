"""Tests for validation functions."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_linode_objectstorage import validation


@pytest.fixture
def sample_certificate():
    """Generate a sample self-signed certificate for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.com"),
                    x509.DNSName("www.example.com"),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert


class TestValidateBucketForSSL:
    """Tests for validate_bucket_for_ssl function."""

    def test_valid_bucket(self):
        """Test validation of a valid bucket."""
        bucket = {
            "label": "test-bucket",
            "hostname": "test.example.com",
            "cluster": "us-east-1",
            "endpoint_type": "E3",
        }

        is_valid, error = validation.validate_bucket_for_ssl(bucket)
        assert is_valid
        assert error == ""

    def test_missing_hostname(self):
        """Test bucket without hostname."""
        bucket = {
            "label": "test-bucket",
            "cluster": "us-east-1",
        }

        is_valid, error = validation.validate_bucket_for_ssl(bucket)
        assert not is_valid
        assert "hostname" in error

    def test_missing_cluster(self):
        """Test bucket without cluster."""
        bucket = {
            "label": "test-bucket",
            "hostname": "test.example.com",
        }

        is_valid, error = validation.validate_bucket_for_ssl(bucket)
        assert not is_valid
        assert "cluster" in error


class TestValidateCertificateFormat:
    """Tests for validate_certificate_format function."""

    def test_valid_pem_format(self):
        """Test valid PEM certificate format."""
        cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        is_valid, error = validation.validate_certificate_format(cert)

        assert is_valid
        assert error == ""

    def test_missing_begin_marker(self):
        """Test certificate without BEGIN marker."""
        cert = "MIICertificateData\n-----END CERTIFICATE-----"
        is_valid, error = validation.validate_certificate_format(cert)

        assert not is_valid
        assert "BEGIN CERTIFICATE" in error

    def test_missing_end_marker(self):
        """Test certificate without END marker."""
        cert = "-----BEGIN CERTIFICATE-----\nMIICertificateData"
        is_valid, error = validation.validate_certificate_format(cert)

        assert not is_valid
        assert "END CERTIFICATE" in error

    def test_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        cert = "\n  -----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----  \n"
        is_valid, error = validation.validate_certificate_format(cert)

        assert is_valid


class TestNormalizeCertificate:
    """Tests for normalize_certificate function."""

    def test_converts_line_endings(self):
        """Test conversion of different line endings."""
        cert = "-----BEGIN CERTIFICATE-----\r\nMIIC\r\n-----END CERTIFICATE-----\r\n"
        normalized = validation.normalize_certificate(cert)

        assert "\r\n" not in normalized
        assert "\r" not in normalized
        assert normalized.count("\n") == 3

    def test_adds_trailing_newline(self):
        """Test that trailing newline is added if missing."""
        cert = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"
        normalized = validation.normalize_certificate(cert)

        assert normalized.endswith("\n")

    def test_preserves_existing_newline(self):
        """Test that existing newline is preserved."""
        cert = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
        normalized = validation.normalize_certificate(cert)

        assert normalized == cert


class TestGetCertificateDomains:
    """Tests for get_certificate_domains function."""

    def test_extracts_cn_and_sans(self, sample_certificate):
        """Test extraction of CN and SANs."""
        cn, sans = validation.get_certificate_domains(sample_certificate)

        assert cn == "example.com"
        assert "example.com" in sans
        assert "www.example.com" in sans
        assert len(sans) == 2

    def test_certificate_without_san(self):
        """Test certificate without SAN extension."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "test.com"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        cn, sans = validation.get_certificate_domains(cert)

        assert cn == "test.com"
        assert sans == []


class TestVerifyCertificateCoverseDomain:
    """Tests for verify_certificate_covers_domain function."""

    def test_domain_in_san(self, sample_certificate):
        """Test domain present in SAN."""
        is_valid, error = validation.verify_certificate_covers_domain(
            sample_certificate, "www.example.com"
        )

        assert is_valid
        assert error == ""

    def test_domain_matches_cn(self, sample_certificate):
        """Test domain matches CN."""
        is_valid, _ = validation.verify_certificate_covers_domain(sample_certificate, "example.com")

        assert is_valid

    def test_domain_not_covered(self, sample_certificate):
        """Test domain not in certificate."""
        is_valid, error = validation.verify_certificate_covers_domain(
            sample_certificate, "other.com"
        )

        assert not is_valid
        assert "other.com" in error


class TestParseCertificateChain:
    """Tests for parse_certificate_chain function."""

    def test_parses_single_certificate(self, sample_certificate):
        """Test parsing a single certificate."""
        from cryptography.hazmat.primitives import serialization

        pem = sample_certificate.public_bytes(serialization.Encoding.PEM).decode()
        certs = validation.parse_certificate_chain(pem)

        assert len(certs) == 1
        assert isinstance(certs[0], x509.Certificate)

    def test_parses_chain(self, sample_certificate):
        """Test parsing a certificate chain."""
        from cryptography.hazmat.primitives import serialization

        pem = sample_certificate.public_bytes(serialization.Encoding.PEM).decode()
        # Duplicate to simulate a chain
        chain = pem + pem

        certs = validation.parse_certificate_chain(chain)

        assert len(certs) == 2

    def test_invalid_certificate_raises(self):
        """Test that invalid certificate raises ValueError."""
        invalid_pem = "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"

        with pytest.raises(ValueError, match="Failed to parse"):
            validation.parse_certificate_chain(invalid_pem)


class TestValidateCertificateChain:
    """Tests for validate_certificate_chain function."""

    def test_valid_chain(self, sample_certificate):
        """Test validation of a valid certificate chain."""
        from cryptography.hazmat.primitives import serialization

        pem = sample_certificate.public_bytes(serialization.Encoding.PEM).decode()
        is_valid, error, count = validation.validate_certificate_chain(pem, "example.com")

        assert is_valid
        assert error == ""
        assert count == 1

    def test_domain_not_covered(self, sample_certificate):
        """Test validation fails when domain not covered."""
        from cryptography.hazmat.primitives import serialization

        pem = sample_certificate.public_bytes(serialization.Encoding.PEM).decode()
        is_valid, error, count = validation.validate_certificate_chain(pem, "notcovered.com")

        assert not is_valid
        assert "notcovered.com" in error

    def test_empty_chain(self):
        """Test validation of empty chain."""
        is_valid, error, count = validation.validate_certificate_chain("", "example.com")

        assert not is_valid
        assert "No certificates" in error
        assert count == 0

    def test_chain_with_multiple_certs(self, sample_certificate):
        """Test validation of chain with multiple certificates."""
        from cryptography.hazmat.primitives import serialization

        pem = sample_certificate.public_bytes(serialization.Encoding.PEM).decode()
        chain = pem + pem  # Duplicate cert

        is_valid, error, count = validation.validate_certificate_chain(chain, "example.com")

        assert is_valid
        assert count == 2
