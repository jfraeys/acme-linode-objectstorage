import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from requests import models

from acme_linode_objectstorage import utils


def test_resource_initialization(resource):
    assert (
        resource.url == "https://acme-staging-v02.api.letsencrypt.org/acme/resource/1"
    )
    assert resource._data == {"status": "pending"}


def test_resource_status(resource):
    assert resource.status == "pending"


def test_resource_update(resource, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/resource/1"
    requests_mock.post(url, json={"status": "valid"}, headers={"Retry-After": "2"})

    resource.update()

    assert resource._data["status"] == "valid"
    assert resource._retry_after > time.monotonic()


def test_resource_poll_until_not(resource, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/resource/1"
    requests_mock.post(url, json={"status": "valid"}, headers={"Retry-After": "2"})

    resource.poll_until_not({"pending"})

    assert resource.status == "valid"


def test_resource_getitem(resource, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/resource/1"
    requests_mock.post(url, json={"status": "valid"}, headers={"Retry-After": "2"})

    assert resource["status"] == "pending"  # Before update
    resource.update()
    assert resource["status"] == "valid"  # After update


def test_resource_repr(resource):
    repr_str = repr(resource)
    assert (
        repr_str
        == "<Resource https://acme-staging-v02.api.letsencrypt.org/acme/resource/1 {'status': 'pending'}>"
    )


def test_account_key(account):
    assert account.key == {"kty": "RSA", "n": "some-modulus", "e": "AQAB"}


def test_account_key_thumbprint(account):
    thumbprint = utils.json_thumbprint(account.key)
    assert account.key_thumbprint == thumbprint


def test_challenge_type(challenge):
    assert challenge.type == "http-01"


def test_challenge_respond(challenge, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1"
    requests_mock.post(url, json={"status": "valid"})

    challenge.respond()
    assert challenge._data["status"] == "valid"


def test_authorization_identifier(authorization):
    assert authorization.identifier == {"type": "dns", "value": "example.com"}


def test_authorization_challenges(authorization, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/authz/1"
    requests_mock.post(
        url,
        json={
            "challenges": [
                {"url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1"}
            ]
        },
    )

    challenges = authorization.challenges
    assert len(challenges) == 1
    assert isinstance(challenges[0], models.Challenge)
    assert (
        challenges[0].url == "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1"
    )


def test_authorization_respond_to_challenges(authorization, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1"
    requests_mock.post(url, json={"status": "valid"})

    authorization.respond_to_challenges()
    challenges = authorization.challenges
    assert challenges[0]._data["status"] == "valid"


def test_order_authorizations(order, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/acme/authz/1"
    requests_mock.post(
        url, json={"identifier": {"type": "dns", "value": "example.com"}}
    )

    authorizations = order.authorizations
    assert len(authorizations) == 1
    assert (
        authorizations[0].url
        == "https://acme-staging-v02.api.letsencrypt.org/acme/authz/1"
    )


def test_order_finalize(order, requests_mock):
    finalize_url = "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/1"
    order._data["finalize"] = finalize_url

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com")])
        )
        .sign(order.client.account_key, hashes.SHA256(), default_backend())
    )

    requests_mock.post(finalize_url, json={"status": "valid"})

    order.finalize(csr)
    assert order._data["status"] == "valid"


def test_order_certificate(order, requests_mock):
    certificate_url = "https://acme-staging-v02.api.letsencrypt.org/acme/cert/1"
    order._data["certificate"] = certificate_url

    requests_mock.post(certificate_url, text="CERTIFICATE DATA")

    certificate = order.certificate()
    assert certificate == "CERTIFICATE DATA"
