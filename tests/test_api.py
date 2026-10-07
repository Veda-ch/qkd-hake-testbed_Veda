import base64

from fastapi.testclient import TestClient

from qkd_hake.qkd_mock.server import create_app
from qkd_hake.settings import Settings


def test_get_key_then_get_key_with_id() -> None:
    app = create_app(
        Settings(refill_bps=0, pool_depth=2, initial_keys=1, key_size_bits=256)
    )
    client = TestClient(app)
    issued = client.post(
        "/api/v1/keys/bob/enc_keys",
        headers={"X-SAE-ID": "alice"},
        json={"number": 1, "size": 256},
    )
    assert issued.status_code == 200
    first = issued.json()["keys"][0]

    retrieved = client.post(
        "/api/v1/keys/alice/dec_keys",
        headers={"X-SAE-ID": "bob"},
        json={"key_IDs": [{"key_ID": first["key_ID"]}]},
    )
    assert retrieved.status_code == 200
    second = retrieved.json()["keys"][0]
    assert base64.b64decode(first["key"]) == base64.b64decode(second["key"])


def test_empty_pool_returns_service_unavailable() -> None:
    app = create_app(
        Settings(refill_bps=0, pool_depth=1, initial_keys=0, key_size_bits=256)
    )
    response = TestClient(app).post(
        "/api/v1/keys/bob/enc_keys",
        headers={"X-SAE-ID": "alice"},
        json={"number": 1, "size": 256},
    )
    assert response.status_code == 503


def test_peer_quota_returns_service_unavailable() -> None:
    app = create_app(
        Settings(refill_bps=0, pool_depth=4, initial_keys=4, key_size_bits=256, per_peer_quota=1)
    )
    client = TestClient(app)
    request = {"headers": {"X-SAE-ID": "alice"}, "json": {"number": 1, "size": 256}}
    assert client.post("/api/v1/keys/bob/enc_keys", **request).status_code == 200
    assert client.post("/api/v1/keys/bob/enc_keys", **request).status_code == 503
