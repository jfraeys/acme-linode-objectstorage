"""Tests for core library interface."""

from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_linode_objectstorage import core, exceptions


class TestCertificateResult:
    """Tests for CertificateResult dataclass."""

    def test_initialization(self):
        """Test result initialization."""
        result = core.CertificateResult(
            domain="example.com", success=True, bucket_label="my-bucket", cluster="us-east-1"
        )

        assert result.domain == "example.com"
        assert result.success is True
        assert result.bucket_label == "my-bucket"
        assert result.cluster == "us-east-1"

    def test_bool_conversion_success(self):
        """Test boolean conversion for successful result."""
        result = core.CertificateResult(domain="example.com", success=True)

        assert bool(result) is True
        assert result  # Implicit bool check

    def test_bool_conversion_failure(self):
        """Test boolean conversion for failed result."""
        result = core.CertificateResult(domain="example.com", success=False)

        assert bool(result) is False
        assert not result  # Implicit bool check

    def test_repr(self):
        """Test string representation."""
        result = core.CertificateResult(domain="example.com", success=True)

        repr_str = repr(result)
        assert "example.com" in repr_str
        assert "SUCCESS" in repr_str

    def test_repr_failure(self):
        """Test string representation for failure."""
        result = core.CertificateResult(domain="example.com", success=False)

        repr_str = repr(result)
        assert "example.com" in repr_str
        assert "FAILED" in repr_str

    def test_default_error_message(self):
        """Test default error message."""
        result = core.CertificateResult(domain="example.com", success=False)

        assert result.error_message == ""


class TestAcmeLinodeManager:
    """Tests for AcmeLinodeManager class."""

    @pytest.fixture
    def mock_private_key(self):
        """Generate a mock private key."""
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @pytest.fixture
    def manager(self, mock_private_key):
        """Create a manager instance for testing."""
        return core.AcmeLinodeManager(
            linode_token="test-token-123",
            account_key=mock_private_key,
            dry_run=True,
            agree_tos=True,
        )

    def test_initialization_with_key(self, mock_private_key):
        """Test manager initialization with account key."""
        manager = core.AcmeLinodeManager(linode_token="test-token", account_key=mock_private_key)

        assert manager.linode_token == "test-token"
        assert manager.account_key == mock_private_key
        assert manager.dry_run is False
        assert manager.agree_tos is True

    def test_initialization_with_key_path(self, tmp_path, mock_private_key):
        """Test manager initialization with key path."""
        from cryptography.hazmat.primitives import serialization

        # Write key to file
        key_path = tmp_path / "account.pem"
        pem = mock_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)

        manager = core.AcmeLinodeManager(linode_token="test-token", account_key_path=key_path)

        assert manager.account_key is not None
        assert isinstance(manager.account_key, rsa.RSAPrivateKey)

    def test_initialization_without_token(self, mock_private_key):
        """Test that initialization without token raises error."""
        with pytest.raises(ValueError, match="linode_token is required"):
            core.AcmeLinodeManager(linode_token="", account_key=mock_private_key)

    def test_initialization_without_key(self):
        """Test that initialization without key raises error."""
        with pytest.raises(ValueError, match="account_key or account_key_path"):
            core.AcmeLinodeManager(linode_token="test-token")

    def test_initialization_with_invalid_key_path(self, tmp_path):
        """Test initialization with non-existent key path."""
        key_path = tmp_path / "nonexistent.pem"

        with pytest.raises(ValueError, match="not found"):
            core.AcmeLinodeManager(linode_token="test-token", account_key_path=key_path)

    def test_repr(self, manager):
        """Test string representation."""
        repr_str = repr(manager)

        assert "AcmeLinodeManager" in repr_str
        assert "DRY-RUN" in repr_str

    def test_repr_production(self, mock_private_key):
        """Test string representation in production mode."""
        manager = core.AcmeLinodeManager(
            linode_token="test-token", account_key=mock_private_key, dry_run=False
        )

        repr_str = repr(manager)
        assert "PRODUCTION" in repr_str

    def test_context_manager(self, manager):
        """Test context manager support."""
        with manager as m:
            assert m is manager

        # After exit, clients should be closed (we'll verify this doesn't error)

    @patch("acme_linode_objectstorage.core.linode.LinodeObjectStorageClient")
    def test_object_storage_property(self, mock_storage_class, manager):
        """Test lazy initialization of object storage client."""
        mock_storage = Mock()
        mock_storage_class.return_value = mock_storage

        # First access creates client
        storage1 = manager.object_storage
        assert mock_storage_class.called

        # Second access returns same client
        storage2 = manager.object_storage
        assert storage1 is storage2
        assert mock_storage_class.call_count == 1

    @patch("acme_linode_objectstorage.core.acme.AcmeClient")
    def test_acme_client_property(self, mock_acme_class, manager):
        """Test lazy initialization of ACME client."""
        mock_acme = Mock()
        mock_acme_class.return_value = mock_acme

        # First access creates client
        client1 = manager.acme_client
        assert mock_acme_class.called

        # Second access returns same client
        client2 = manager.acme_client
        assert client1 is client2

    def test_list_buckets(self, manager):
        """Test list_buckets method."""
        mock_buckets = [
            {"label": "bucket1", "cluster": "us-east-1"},
            {"label": "bucket2", "cluster": "eu-west-1"},
        ]

        with patch.object(manager, "_object_storage", None):
            with patch(
                "acme_linode_objectstorage.core.linode.LinodeObjectStorageClient"
            ) as mock_client:
                mock_instance = Mock()
                mock_instance.list_buckets.return_value = mock_buckets
                mock_client.return_value = mock_instance

                buckets = manager.list_buckets()

                assert buckets == mock_buckets
                assert len(buckets) == 2

    def test_close_method(self, manager):
        """Test close method."""
        # Create mock clients
        manager._object_storage = Mock()
        manager._acme_client = Mock()

        manager.close()

        manager._object_storage.close.assert_called_once()
        manager._acme_client.close.assert_called_once()

    def test_close_with_no_clients(self, manager):
        """Test close when no clients initialized."""
        # Should not raise error
        manager.close()


class TestAcmeLinodeManagerProvision:
    """Tests for certificate provisioning methods."""

    @pytest.fixture
    def manager(self):
        """Create a manager with mocked dependencies."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return core.AcmeLinodeManager(linode_token="test-token", account_key=key, dry_run=True)

    @patch("acme_linode_objectstorage.core.register_and_update_cert")
    @patch("acme_linode_objectstorage.core.generate_csr")
    @patch("acme_linode_objectstorage.core.generate_private_key")
    @patch("acme_linode_objectstorage.core.register_acme_account")
    def test_provision_certificate_success(
        self, mock_register_account, mock_gen_key, mock_gen_csr, mock_register, manager
    ):
        """Test successful certificate provisioning."""
        # Setup mocks
        mock_key = Mock()
        mock_csr = Mock()
        mock_account = Mock()

        mock_gen_key.return_value = mock_key
        mock_gen_csr.return_value = mock_csr
        mock_register.return_value = 0  # Success
        mock_register_account.return_value = mock_account

        # Mock bucket resolution
        mock_bucket = {"label": "test-bucket", "hostname": "example.com", "cluster": "us-east-1"}

        with patch.object(manager, "_resolve_bucket", return_value=mock_bucket):
            result = manager.provision_certificate("example.com")

        assert result.success
        assert result.domain == "example.com"
        assert result.bucket_label == "test-bucket"
        assert result.cluster == "us-east-1"

    def test_provision_certificate_bucket_not_found(self, manager):
        """Test provisioning when bucket not found."""
        with patch.object(
            manager, "_resolve_bucket", side_effect=exceptions.BucketNotFoundError("test")
        ):
            result = manager.provision_certificate("example.com")

        assert not result.success
        assert "not found" in result.error_message.lower()

    @patch("acme_linode_objectstorage.core.register_and_update_cert")
    @patch("acme_linode_objectstorage.core.generate_csr")
    @patch("acme_linode_objectstorage.core.generate_private_key")
    @patch("acme_linode_objectstorage.core.register_acme_account")
    def test_provision_certificate_failure(
        self, mock_register_account, mock_gen_key, mock_gen_csr, mock_register, manager
    ):
        """Test certificate provisioning failure."""
        mock_gen_key.return_value = Mock()
        mock_gen_csr.return_value = Mock()
        mock_register.return_value = 1  # Failure
        mock_register_account.return_value = Mock()

        mock_bucket = {"label": "test-bucket", "hostname": "example.com", "cluster": "us-east-1"}

        with patch.object(manager, "_resolve_bucket", return_value=mock_bucket):
            result = manager.provision_certificate("example.com")

        assert not result.success
        assert result.domain == "example.com"

    def test_provision_certificates_empty_list(self, manager):
        """Test provisioning with empty domain list."""
        results = manager.provision_certificates([])

        assert results == []

    def test_provision_certificates_sequential(self, manager):
        """Test sequential certificate provisioning."""
        domains = [{"domain": "example1.com"}, {"domain": "example2.com"}]

        with patch.object(manager, "provision_certificate") as mock_provision:
            mock_provision.side_effect = [
                core.CertificateResult(domain="example1.com", success=True),
                core.CertificateResult(domain="example2.com", success=True),
            ]

            results = manager.provision_certificates(domains, parallel=False)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert mock_provision.call_count == 2

    def test_provision_certificates_missing_domain(self, manager):
        """Test provisioning with missing domain field."""
        domains = [{"bucket_label": "test"}]  # No domain field

        results = manager.provision_certificates(domains, parallel=False)

        assert len(results) == 1
        assert not results[0].success
        assert "domain" in results[0].error_message.lower()

    @patch("acme_linode_objectstorage.core.generate_csr")
    @patch("acme_linode_objectstorage.core.generate_private_key")
    @patch("acme_linode_objectstorage.core.register_acme_account")
    def test_provision_certificate_includes_bucket_label_in_csr(
        self, mock_register_account, mock_gen_key, mock_gen_csr, manager
    ):
        """Test that certificate provisioning includes bucket label in CSR domains."""
        # Setup mocks
        mock_key = Mock()
        mock_csr = Mock()
        mock_account = Mock()

        mock_gen_key.return_value = mock_key
        mock_gen_csr.return_value = mock_csr
        mock_register_account.return_value = mock_account

        # Mock bucket with label "blizzard" (different from custom domain)
        mock_bucket = {
            "label": "blizzard",
            "hostname": "blizzard.jfraeys.com",
            "bucket_hostname": "blizzard.us-east-1.linodeobjects.com",
            "cluster": "us-east-1",
        }

        # Mock the register_and_update_cert to return success
        with patch("acme_linode_objectstorage.core.register_and_update_cert", return_value=0):
            with patch.object(manager, "_resolve_bucket", return_value=mock_bucket):
                result = manager.provision_certificate("blizzard.jfraeys.com")

        # Verify the certificate was provisioned successfully
        assert result.success
        assert result.domain == "blizzard.jfraeys.com"
        assert result.bucket_label == "blizzard"

        # Verify generate_csr was called with the correct domains
        # The CSR should include: custom domain, bucket hostname, and bucket label
        mock_gen_csr.assert_called_once()
        call_args = mock_gen_csr.call_args
        domain_arg = call_args[0][0]  # First positional argument (domain)
        additional_domains_arg = call_args[0][2]  # Third positional argument (additional_domains)

        assert domain_arg == "blizzard.jfraeys.com"
        assert additional_domains_arg is not None
        assert "blizzard.us-east-1.linodeobjects.com" in additional_domains_arg
        assert "blizzard" in additional_domains_arg  # Bucket label should be included
