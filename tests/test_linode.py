import requests
import requests_mock

from acme_linode_objectstorage import linode

LINODE_API = "https://api.linode.com/"


def test_list_buckets(client):
    with requests_mock.Mocker() as m:
        url = f"{LINODE_API}v4/object-storage/buckets/"
        m.get(url, json={"data": [], "pages": 1})

        buckets = client.list_buckets()

        assert isinstance(buckets, list)
        assert len(buckets) == 0


def test_create_object_url(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        name = "test-object"
        method = "GET"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/object-url"
        m.post(url, json={"url": "http://example.com/test-object"})

        object_url = client.create_object_url(cluster, label, name, method)

        assert object_url == "http://example.com/test-object"


def test_update_object_acl(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        name = "test-object"
        acl = "private"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/object-acl"
        m.put(url, json={"acl": "private"})

        response = client.update_object_acl(cluster, label, name, acl)

        assert response["acl"] == "private"


def test_check_ssl_exists(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/ssl"
        # check_ssl_exists uses GET, not POST
        m.get(url, json={"ssl": True})

        ssl_exists = client.check_ssl_exists(cluster, label)

        assert ssl_exists is True


def test_check_ssl_not_exists(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/ssl"
        # Return empty response (no ssl key)
        m.get(url, json={})

        ssl_exists = client.check_ssl_exists(cluster, label)

        assert ssl_exists is False


def test_get_ssl(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/ssl"
        m.get(url, json={"ssl": True, "certificate": "cert-data"})

        ssl_config = client.get_ssl(cluster, label)

        assert ssl_config["ssl"] is True
        assert "certificate" in ssl_config


def test_create_ssl(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        certificate = "dummy_certificate"
        private_key = "dummy_private_key"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/ssl"
        m.post(url, json={"ssl": True})

        ssl_created = client.create_ssl(cluster, label, certificate, private_key)

        assert ssl_created


def test_delete_ssl(client):
    with requests_mock.Mocker() as m:
        cluster = "test-cluster"
        label = "test-bucket"
        url = f"{LINODE_API}v4/object-storage/buckets/{cluster}/{label}/ssl"
        m.delete(url, json={})

        ssl_deleted = client.delete_ssl(cluster, label)

        assert ssl_deleted


def test_bearer_auth():
    token = "dummy_token"
    auth = linode.BearerAuth(token)
    request = requests.Request()
    auth(request)
    assert request.headers["Authorization"] == f"Bearer {token}"
