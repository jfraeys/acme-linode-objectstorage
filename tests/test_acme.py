from unittest.mock import patch


def test_acme_client_initialization(acme_client):
    assert acme_client.account_key is not None
    assert acme_client.dry_run is True


def test_acme_client_new_account(acme_client, requests_mock):
    url = "https://acme-staging-v02.api.letsencrypt.org/directory/newAccount"
    requests_mock.post(url, headers={"Location": "test-location"}, json={})

    with patch(
        "acme_linode_objectstorage.utils.rsa_jwk_public", return_value={"fake": "jwk"}
    ):
        account = acme_client.new_account(terms_of_service_agreed=True)

    assert account is not None
    assert acme_client._key_id == "test-location"


def test_acme_client_new_order(acme_client, requests_mock):
    directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    new_order_url = f"{directory_url}/newOrder"
    requests_mock.get(directory_url, json={"newOrder": new_order_url})
    requests_mock.post(
        new_order_url, status_code=201, headers={"Location": "test-order"}, json={}
    )

    order = acme_client.new_order(["example.com"])

    assert order is not None
    assert acme_client._directory is not None


def test_acme_client_signed_request(acme_client, requests_mock):
    directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    new_nonce_url = f"{directory_url}/newNonce"
    new_account_url = f"{directory_url}/newAccount"
    requests_mock.get(
        directory_url, json={"newNonce": new_nonce_url, "newAccount": new_account_url}
    )
    requests_mock.head(new_nonce_url, headers={"Replay-Nonce": "test-nonce"})
    requests_mock.post(new_account_url, headers={"Location": "test-location"}, json={})

    with patch(
        "acme_linode_objectstorage.utils.rsa_jwk_public", return_value={"fake": "jwk"}
    ):
        acme_client.new_account(terms_of_service_agreed=True)

    signed_url = f"{directory_url}/someResource"
    requests_mock.post(
        signed_url, json={}, status_code=200, headers={"Replay-Nonce": "new-test-nonce"}
    )

    response = acme_client.signed_request(signed_url, payload={"test": "payload"})

    assert response.status_code == 200
    assert acme_client._nonce == "new-test-nonce"


def test_acme_client_new_nonce(acme_client, requests_mock):
    directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    new_nonce_url = f"{directory_url}/newNonce"
    requests_mock.get(directory_url, json={"newNonce": new_nonce_url})
    requests_mock.head(new_nonce_url, headers={"Replay-Nonce": "test-nonce"})

    acme_client._new_nonce()

    assert acme_client._nonce == "test-nonce"
