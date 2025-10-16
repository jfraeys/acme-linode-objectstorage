"""Tests for custom exceptions."""

import pytest

from acme_linode_objectstorage import exceptions


class TestBucketNotFoundError:
    """Tests for BucketNotFoundError exception."""

    def test_creates_with_bucket_name(self):
        """Test exception creation with bucket name."""
        error = exceptions.BucketNotFoundError("my-bucket")

        assert error.bucket_name == "my-bucket"
        assert "my-bucket" in str(error)
        assert "not found" in str(error).lower()

    def test_is_exception(self):
        """Test that it's a proper exception."""
        error = exceptions.BucketNotFoundError("test")

        assert isinstance(error, Exception)

    def test_can_be_raised_and_caught(self):
        """Test that exception can be raised and caught."""
        with pytest.raises(exceptions.BucketNotFoundError) as exc_info:
            raise exceptions.BucketNotFoundError("test-bucket")

        assert exc_info.value.bucket_name == "test-bucket"


class TestBucketAccessError:
    """Tests for BucketAccessError exception."""

    def test_creates_with_name_and_status(self):
        """Test exception creation with bucket name and status code."""
        error = exceptions.BucketAccessError("my-bucket", 403)

        assert error.bucket_name == "my-bucket"
        assert error.status_code == 403
        assert "my-bucket" in str(error)
        assert "403" in str(error)

    def test_is_exception(self):
        """Test that it's a proper exception."""
        error = exceptions.BucketAccessError("test", 404)

        assert isinstance(error, Exception)

    def test_can_be_raised_and_caught(self):
        """Test that exception can be raised and caught."""
        with pytest.raises(exceptions.BucketAccessError) as exc_info:
            raise exceptions.BucketAccessError("test-bucket", 500)

        assert exc_info.value.bucket_name == "test-bucket"
        assert exc_info.value.status_code == 500

    def test_various_status_codes(self):
        """Test with various HTTP status codes."""
        for status_code in [400, 401, 403, 404, 500, 503]:
            error = exceptions.BucketAccessError("bucket", status_code)
            assert error.status_code == status_code
            assert str(status_code) in str(error)
