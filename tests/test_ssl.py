"""Tests for SSL certificate management."""

from unittest.mock import Mock, patch

import pytest

from acme_linode_objectstorage import ssl


class TestSSLFunctions:
    """Tests for SSL certificate management functions."""

    @patch("acme_linode_objectstorage.ssl.perform_authorizations")
    @patch("acme_linode_objectstorage.ssl.finalize_order")
    @patch("acme_linode_objectstorage.ssl.upload_certificate")
    @patch("acme_linode_objectstorage.ssl.validate_bucket_for_ssl")
    def test_register_and_update_cert_includes_bucket_label_in_order(
        self, mock_validate_bucket, mock_upload_cert, mock_finalize_order, mock_perform_auth
    ):
        """Test that register_and_update_cert includes bucket label in ACME order."""
        # Setup mocks
        mock_validate_bucket.return_value = (True, "")
        mock_perform_auth.return_value = True
        mock_finalize_order.return_value = "mock_certificate"
        mock_upload_cert.return_value = True

        # Mock ACME client and order
        mock_acme_client = Mock()
        mock_order = Mock()
        mock_order.status = "valid"
        mock_acme_client.new_order.return_value = mock_order

        # Mock bucket with label "blizzard"
        mock_bucket = {
            "label": "blizzard",
            "hostname": "blizzard.jfraeys.com",
            "bucket_hostname": "blizzard.us-east-1.linodeobjects.com",
            "cluster": "us-east-1",
        }

        # Mock CSR and private key
        mock_csr = Mock()
        mock_private_key = Mock()
        mock_account = Mock()

        # Call the function
        result = ssl.register_and_update_cert(
            acme_client=mock_acme_client,
            object_storage=Mock(),
            bucket=mock_bucket,
            csr=mock_csr,
            private_key=mock_private_key,
            account=mock_account,
        )

        # Verify success
        assert result == 0

        # Verify new_order was called with the correct domains
        mock_acme_client.new_order.assert_called_once()
        call_args = mock_acme_client.new_order.call_args

        # First argument should be the hostname (custom domain)
        primary_domain = call_args[0][0]
        assert primary_domain == "blizzard.jfraeys.com"

        # Second argument should be additional domains including bucket label
        additional_domains = call_args[0][1]
        assert additional_domains is not None
        assert "blizzard.us-east-1.linodeobjects.com" in additional_domains  # bucket hostname
        assert "blizzard" in additional_domains  # bucket label
