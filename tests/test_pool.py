import pytest

from qkd_hake.qkd_mock.pool import PeerQuotaExceeded, PoolExhausted, QKDKeyPool, UnknownKeyID


def test_master_and_slave_receive_same_key() -> None:
    pool = QKDKeyPool(refill_bps=0, depth=2, initial_keys=1)
    issued = pool.issue("alice", "bob")[0]
    retrieved = pool.retrieve("alice", "bob", [issued.key_id])[0]
    assert retrieved.key == issued.key
    assert len(retrieved.key) == 32


def test_pool_exhaustion_is_explicit() -> None:
    pool = QKDKeyPool(refill_bps=0, depth=1, initial_keys=1)
    pool.issue("alice", "bob")
    with pytest.raises(PoolExhausted):
        pool.issue("alice", "bob")


def test_key_id_is_single_use_for_slave_retrieval() -> None:
    pool = QKDKeyPool(refill_bps=0, depth=1, initial_keys=1)
    issued = pool.issue("alice", "bob")[0]
    pool.retrieve("alice", "bob", [issued.key_id])
    with pytest.raises(UnknownKeyID):
        pool.retrieve("alice", "bob", [issued.key_id])


def test_per_peer_outstanding_quota_is_enforced_and_released() -> None:
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10, per_peer_quota=2)
    first = pool.issue("alice", "bob")[0]
    pool.issue("alice", "bob")
    with pytest.raises(PeerQuotaExceeded):
        pool.issue("alice", "bob")
    assert pool.status()["stored_key_count"] == 8  # refused request takes no key

    pool.retrieve("alice", "bob", [first.key_id])  # retrieval releases quota
    pool.issue("alice", "bob")


def test_per_peer_outstanding_quota_is_independent_per_peer() -> None:
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10, per_peer_quota=1)
    pool.issue("alice", "bob")
    pool.issue("carol", "bob")
    with pytest.raises(PeerQuotaExceeded):
        pool.issue("alice", "bob")
