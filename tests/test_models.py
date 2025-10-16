"""Tests for ACME models."""

from unittest.mock import Mock

import pytest

from acme_linode_objectstorage import models


class TestResource:
    """Tests for Resource base class."""

    def test_initialization(self):
        """Test resource initialization."""
        mock_client = Mock()
        resource = models.Resource(mock_client, "https://example.com/resource", {"status": "valid"})

        assert resource.client == mock_client
        assert resource.url == "https://example.com/resource"
        assert resource.status == "valid"

    def test_status_property(self):
        """Test status property."""
        mock_client = Mock()
        resource = models.Resource(mock_client, "https://example.com", {"status": "pending"})

        assert resource.status == "pending"

    def test_status_empty_when_no_data(self):
        """Test status returns empty string when no data."""
        mock_client = Mock()
        resource = models.Resource(mock_client, "https://example.com", None)

        assert resource.status == ""

    def test_getitem(self):
        """Test accessing resource data via __getitem__."""
        mock_client = Mock()
        data = {"key": "value", "number": 42}
        resource = models.Resource(mock_client, "https://example.com", data)

        assert resource["key"] == "value"
        assert resource["number"] == 42

    def test_repr(self):
        """Test string representation."""
        mock_client = Mock()
        resource = models.Resource(mock_client, "https://example.com", {"test": "data"})

        repr_str = repr(resource)
        assert "Resource" in repr_str
        assert "https://example.com" in repr_str


class TestAccount:
    """Tests for Account model."""

    def test_initialization(self):
        """Test account initialization."""
        mock_client = Mock()
        data = {
            "status": "valid",
            "contact": ["mailto:admin@example.com"],
            "key": {"kty": "RSA", "n": "abc", "e": "AQAB"},
        }
        account = models.Account(mock_client, "https://example.com/acct/1", data)

        assert account.status == "valid"

    def test_get_contact_property(self):
        """Test get_contact property."""
        mock_client = Mock()
        data = {"contact": ["mailto:admin@example.com", "mailto:backup@example.com"]}
        account = models.Account(mock_client, "https://example.com/acct/1", data)

        contacts = account.get_contact
        assert len(contacts) == 2
        assert "mailto:admin@example.com" in contacts

    def test_key_property(self):
        """Test key property."""
        mock_client = Mock()
        data = {"key": {"kty": "RSA", "n": "abc123", "e": "AQAB"}}
        account = models.Account(mock_client, "https://example.com/acct/1", data)

        key = account.key
        assert key["kty"] == "RSA"
        assert key["n"] == "abc123"

    def test_key_thumbprint(self):
        """Test key_thumbprint property."""
        mock_client = Mock()
        data = {"key": {"kty": "RSA", "n": "abc123", "e": "AQAB"}}
        account = models.Account(mock_client, "https://example.com/acct/1", data)

        thumbprint = account.key_thumbprint
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 0


class TestChallenge:
    """Tests for Challenge model."""

    def test_initialization(self):
        """Test challenge initialization."""
        mock_client = Mock()
        data = {
            "type": "http-01",
            "status": "pending",
            "url": "https://example.com/chall/1",
            "token": "abc123",
        }
        challenge = models.Challenge(mock_client, "https://example.com/chall/1", data)

        assert challenge.status == "pending"
        assert challenge.type == "http-01"

    def test_type_property(self):
        """Test type property."""
        mock_client = Mock()
        data = {"type": "dns-01", "status": "valid"}
        challenge = models.Challenge(mock_client, "https://example.com/chall/1", data)

        assert challenge.type == "dns-01"

    def test_respond(self):
        """Test respond method."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "processing"}
        mock_client.signed_request.return_value = mock_response

        data = {"type": "http-01", "status": "pending", "token": "abc"}
        challenge = models.Challenge(mock_client, "https://example.com/chall/1", data)

        challenge.respond()

        mock_client.signed_request.assert_called_once_with("https://example.com/chall/1", {})
        assert challenge.status == "processing"

    def test_respond_failure(self):
        """Test respond method handles failure."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 400
        mock_client.signed_request.return_value = mock_response

        data = {"type": "http-01", "status": "pending"}
        challenge = models.Challenge(mock_client, "https://example.com/chall/1", data)

        with pytest.raises(RuntimeError, match="Failed to respond"):
            challenge.respond()


class TestAuthorization:
    """Tests for Authorization model."""

    def test_initialization(self):
        """Test authorization initialization."""
        mock_client = Mock()
        data = {"status": "pending", "identifier": {"type": "dns", "value": "example.com"}}
        authz = models.Authorization(mock_client, "https://example.com/authz/1", data)

        assert authz.status == "pending"

    def test_identifier_property(self):
        """Test identifier property."""
        mock_client = Mock()
        data = {"identifier": {"type": "dns", "value": "example.com"}}
        authz = models.Authorization(mock_client, "https://example.com/authz/1", data)

        identifier = authz.identifier
        assert identifier["type"] == "dns"
        assert identifier["value"] == "example.com"

    def test_challenges_property(self):
        """Test challenges property."""
        mock_client = Mock()

        # Mock the signed_request for update() call
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers.get.return_value = "1"
        mock_response.json.return_value = {
            "challenges": [
                {"type": "http-01", "url": "https://example.com/chall/1", "token": "abc"},
                {"type": "dns-01", "url": "https://example.com/chall/2", "token": "def"},
            ]
        }
        mock_client.signed_request.return_value = mock_response

        data = {
            "challenges": [
                {"type": "http-01", "url": "https://example.com/chall/1", "token": "abc"},
                {"type": "dns-01", "url": "https://example.com/chall/2", "token": "def"},
            ]
        }
        authz = models.Authorization(mock_client, "https://example.com/authz/1", data)

        challenges = authz.challenges
        assert len(challenges) == 2
        assert all(isinstance(c, models.Challenge) for c in challenges)
        assert challenges[0].type == "http-01"
        assert challenges[1].type == "dns-01"


class TestOrder:
    """Tests for Order model."""

    def test_initialization(self):
        """Test order initialization."""
        mock_client = Mock()
        data = {
            "status": "pending",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://example.com/authz/1"],
        }
        order = models.Order(mock_client, "https://example.com/order/1", data)

        assert order.status == "pending"

    def test_authorizations_property(self):
        """Test authorizations property."""
        mock_client = Mock()
        data = {"authorizations": ["https://example.com/authz/1", "https://example.com/authz/2"]}
        order = models.Order(mock_client, "https://example.com/order/1", data)

        authzs = order.authorizations
        assert len(authzs) == 2
        assert all(isinstance(a, models.Authorization) for a in authzs)

    def test_finalize_success(self):
        """Test successful finalization."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Create a mock CSR
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
            .sign(private_key, hashes.SHA256())
        )

        mock_client = Mock()
        mock_response = Mock()
        mock_response.json.return_value = {"status": "processing"}
        mock_client.signed_request.return_value = mock_response

        data = {"status": "ready", "finalize": "https://example.com/finalize/1"}
        order = models.Order(mock_client, "https://example.com/order/1", data)

        order.finalize(csr)

        mock_client.signed_request.assert_called_once()
        assert order.status == "processing"

    def test_finalize_wrong_status(self):
        """Test finalize fails when order not ready."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
            .sign(private_key, hashes.SHA256())
        )

        mock_client = Mock()
        data = {"status": "pending"}
        order = models.Order(mock_client, "https://example.com/order/1", data)

        with pytest.raises(RuntimeError, match="Invalid state"):
            order.finalize(csr)

    def test_certificate_success(self):
        """Test successful certificate retrieval."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.text = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        mock_client.signed_request.return_value = mock_response

        data = {"status": "valid", "certificate": "https://example.com/cert/1"}
        order = models.Order(mock_client, "https://example.com/order/1", data)

        cert = order.certificate()

        assert "BEGIN CERTIFICATE" in cert
        mock_client.signed_request.assert_called_once()

    def test_certificate_wrong_status(self):
        """Test certificate retrieval fails when order not valid."""
        mock_client = Mock()
        data = {"status": "processing"}
        order = models.Order(mock_client, "https://example.com/order/1", data)

        with pytest.raises(RuntimeError, match="Invalid state"):
            order.certificate()
