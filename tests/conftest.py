import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_linode_objectstorage import acme, linode, models


@pytest.fixture(scope="session")
def account_key():
    """Fixture to generate a private RSA key for the tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


@pytest.fixture
def acme_client(account_key):
    """Fixture to initialize an AcmeClient instance."""
    return acme.AcmeClient(account_key, dry_run=True)


@pytest.fixture
def resource(acme_client):
    data = {"status": "pending"}
    return models.Resource(
        acme_client,
        "https://acme-staging-v02.api.letsencrypt.org/acme/resource/1",
        data,
    )


@pytest.fixture
def account(acme_client):
    """Fixture to initialize an Account instance."""
    data = {"key": {"kty": "RSA", "n": "some-modulus", "e": "AQAB"}}
    return models.Account(
        acme_client, "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1", data
    )


@pytest.fixture
def challenge(acme_client):
    """Fixture to initialize a Challenge instance."""
    data = {"type": "http-01", "status": "pending"}
    return models.Challenge(
        acme_client, "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1", data
    )


@pytest.fixture
def authorization(acme_client):
    """Fixture to initialize an Authorization instance."""
    data = {
        "identifier": {"type": "dns", "value": "example.com"},
        "challenges": [{"url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1"}],
    }
    return models.Authorization(
        acme_client, "https://acme-staging-v02.api.letsencrypt.org/acme/authz/1", data
    )


@pytest.fixture
def order(acme_client):
    """Fixture to initialize an Order instance."""
    data = {
        "authorizations": ["https://acme-staging-v02.api.letsencrypt.org/acme/authz/1"],
        "status": "ready",
    }
    return models.Order(
        acme_client, "https://acme-staging-v02.api.letsencrypt.org/acme/order/1", data
    )


@pytest.fixture
def token():
    return "dummy_token"


@pytest.fixture
def client(token):
    return linode.LinodeObjectStorageClient(token)


@pytest.fixture
def requests_mock():
    """Fixture for requests-mock."""
    import requests_mock as rm

    with rm.Mocker() as m:
        yield m
