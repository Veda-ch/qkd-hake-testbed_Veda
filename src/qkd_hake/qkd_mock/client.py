from __future__ import annotations

import base64
import httpx

from qkd_hake.mitigations.mitigations import QKDUnavailable
from qkd_hake.qkd_mock.pool import QKDKeyPool


class QKDClient:
    """ETSI GS QKD 014 REST Client for Mock KME Server.

    ``http`` defaults to the ``httpx`` module; any object with httpx-style
    ``get``/``post`` (e.g. ``httpx.Client`` or FastAPI's ``TestClient``) works.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        local_sae_id: str = "alice",
        peer_sae_id: str = "bob",
        http=None,
    ) -> None:
        self.base_url = base_url
        self.local_sae_id = local_sae_id
        self.peer_sae_id = peer_sae_id
        self._http = http if http is not None else httpx

    @staticmethod
    def _check(response) -> None:
        # The mock KME answers 503 when the pool is exhausted or the per-peer
        # outstanding-key quota is hit: an expected QKD-unavailability signal.
        if response.status_code == 503:
            raise QKDUnavailable(response.text)
        response.raise_for_status()

    def get_status(self) -> dict:
        url = f"{self.base_url}/api/v1/keys/{self.peer_sae_id}/status"
        headers = {"X-SAE-ID": self.local_sae_id}
        response = self._http.get(url, headers=headers)
        self._check(response)
        return response.json()

    def get_key(self) -> tuple[bytes, str]:
        url = f"{self.base_url}/api/v1/keys/{self.peer_sae_id}/enc_keys"
        headers = {"X-SAE-ID": self.local_sae_id}
        response = self._http.post(url, headers=headers, json={"number": 1, "size": 256})
        self._check(response)
        key_data = response.json()["keys"][0]
        return base64.b64decode(key_data["key"]), key_data["key_ID"]

    def retrieve_key(self, key_id: str) -> bytes:
        url = f"{self.base_url}/api/v1/keys/{self.peer_sae_id}/dec_keys"
        headers = {"X-SAE-ID": self.local_sae_id}
        response = self._http.post(url, headers=headers, json={"key_IDs": [{"key_ID": key_id}]})
        self._check(response)
        key_data = response.json()["keys"][0]
        return base64.b64decode(key_data["key"])

    # Adapters to the HAKE client-function contract.
    def initiator_fn(self, action, key_id=None):
        """For AliceSession.message3: ``fn("status")`` / ``fn("get")``."""
        if action == "status":
            return self.get_status()
        if action == "get":
            return self.get_key()
        raise ValueError(f"unsupported QKD client action: {action!r}")

    def responder_fn(self, key_id: str) -> bytes:
        """For BobSession.message4: ``fn(key_id)``."""
        return self.retrieve_key(key_id)


class LocalPoolClient:
    """In-process adapter from a QKDKeyPool to the HAKE client-function contract."""

    def __init__(self, pool: QKDKeyPool, master_sae_id: str, slave_sae_id: str) -> None:
        self.pool = pool
        self.master_sae_id = master_sae_id
        self.slave_sae_id = slave_sae_id

    def initiator_fn(self, action, key_id=None):
        if action == "status":
            return self.pool.status()
        if action == "get":
            key = self.pool.issue(self.master_sae_id, self.slave_sae_id)[0]
            return key.key, key.key_id
        raise ValueError(f"unsupported QKD client action: {action!r}")

    def responder_fn(self, key_id: str) -> bytes:
        return self.pool.retrieve(self.master_sae_id, self.slave_sae_id, [key_id])[0].key
