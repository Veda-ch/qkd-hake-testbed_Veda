import pytest
import hmac
from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeError
from qkd_hake.protocol.combiner import SecurityMode, FallbackReason
from qkd_hake.mitigations.mitigations import MitigationManager, AdmissionControlError, QuotaExceededError
from qkd_hake.qkd_mock.pool import QKDKeyPool, PoolExhausted, PeerQuotaExceeded


# ---------------------------------------------------------------------------
# Shared helpers for the WP7 regression tests below. Existing tests above the
# helpers are left in their original hand-written form; new tests use these
# to run a full 4-message handshake without repeating the plumbing.
# ---------------------------------------------------------------------------

def _make_keypairs(alg: str = "ML-KEM-512"):
    kem = OQSKEM(alg)
    return kem.generate_keypair(), kem.generate_keypair()


def _run_handshake(
    kp_a,
    kp_b,
    alg: str = "ML-KEM-512",
    *,
    id_a: str = "alice",
    id_b: str = "bob",
    mitigation_mgr: MitigationManager | None = None,
    qkd_pool_client_fn=None,
    allow_explicit_fallback: bool = True,
    bob_qkd_pool_client_fn=None,
):
    """Run one complete Alice/Bob handshake and return (alice_res, bob_res)."""
    alice = AliceSession(
        id_a, kp_a.public_key, kp_a.secret_key, id_b, kp_b.public_key, alg,
        mitigation_mgr=mitigation_mgr,
    )
    bob = BobSession(id_a, kp_a.public_key, id_b, kp_b.public_key, kp_b.secret_key, alg)

    ct1, nonce_a = alice.message1()
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))
    ct_star, q_id, tau2 = alice.message3(
        (pk_e, tau1, ct2, nonce_b),
        qkd_pool_client_fn=qkd_pool_client_fn,
        allow_explicit_fallback=allow_explicit_fallback,
    )
    tau3, bob_res = bob.message4((ct_star, q_id, tau2), qkd_pool_client_fn=bob_qkd_pool_client_fn)
    alice_res = alice.derive_and_verify(tau3)
    return alice_res, bob_res


def _pool_alice_client(pool: QKDKeyPool, master: str = "alice", slave: str = "bob"):
    """Adapter from AliceSession's (action) client contract to a real QKDKeyPool."""
    def fn(action, key_id=None):
        if action == "status":
            return pool.status()
        if action == "get":
            key = pool.issue(master, slave)[0]
            return key.key, key.key_id
        raise AssertionError(f"unexpected action {action!r}")
    return fn


def _pool_bob_client(pool: QKDKeyPool, master: str = "alice", slave: str = "bob"):
    return lambda key_id: pool.retrieve(master, slave, [key_id])[0].key


class FakeClock:
    """Deterministic, manually-advanced clock for quota-window tests."""

    def __init__(self, start: float = 0.0) -> None:
        self._t = start

    def __call__(self) -> float:
        return self._t

    def advance(self, dt: float) -> None:
        self._t += dt


def test_hake_hybrid_handshake_success() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)

    # Mock QKD client functions
    qkd_key = b"q" * 32
    qkd_key_id = "test-qkd-key-id"

    def mock_qkd_client(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 100, "max_key_count": 100}
        elif action == "get":
            return qkd_key, qkd_key_id
        else:
            return qkd_key

    # Msg 1
    ct1, nonce_a = alice.message1()

    # Msg 2
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Msg 3
    ct_star, q_id, tau2 = alice.message3(
        (pk_e, tau1, ct2, nonce_b),
        qkd_pool_client_fn=mock_qkd_client,
        allow_explicit_fallback=False
    )
    assert q_id == qkd_key_id

    # Msg 4
    tau3, bob_res = bob.message4(
        (ct_star, q_id, tau2),
        qkd_pool_client_fn=lambda kid: qkd_key
    )

    alice_res = alice.derive_and_verify(tau3)

    assert alice_res.session_key == bob_res.session_key
    assert alice_res.security_mode == SecurityMode.HYBRID_QKD
    assert bob_res.security_mode == SecurityMode.HYBRID_QKD
    assert alice_res.fallback_reason == FallbackReason.NONE
    assert bob_res.fallback_reason == FallbackReason.NONE
    assert len(alice_res.session_key) == 32


def test_hake_pqc_fallback_success() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)

    # Msg 1
    ct1, nonce_a = alice.message1()

    # Msg 2
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Msg 3 (No QKD Client, allow fallback = True)
    ct_star, q_id, tau2 = alice.message3(
        (pk_e, tau1, ct2, nonce_b),
        qkd_pool_client_fn=None,
        allow_explicit_fallback=True
    )
    assert q_id == ""

    # Msg 4
    tau3, bob_res = bob.message4(
        (ct_star, q_id, tau2),
        qkd_pool_client_fn=None
    )

    alice_res = alice.derive_and_verify(tau3)

    assert alice_res.session_key == bob_res.session_key
    # Reconciled with protocol.combiner.SecurityMode: the real HAKE path now
    # emits the same "PQC_ONLY" value as the combiner enum instead of the
    # previous, differently-spelled "SECURITY_LEVEL_DEGRADED_PQC_ONLY".
    assert alice_res.security_mode == SecurityMode.PQC_ONLY
    assert bob_res.security_mode == SecurityMode.PQC_ONLY
    assert alice_res.fallback_reason == FallbackReason.QKD_UNAVAILABLE
    assert bob_res.fallback_reason == FallbackReason.PEER_DECLARED


def test_hake_admission_control_triggers() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)

    # Mock QKD client returning <5% occupancy
    def mock_qkd_client_low_occupancy(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 4, "max_key_count": 100}  # 4% occupancy
        return b"q" * 32, "id"

    # Msg 1 & 2 mock inputs
    ct1, nonce_a = alice.message1()
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Verify that when allow_explicit_fallback is False, it raises HandshakeError
    with pytest.raises(HandshakeError) as excinfo:
        alice.message3(
            (pk_e, tau1, ct2, nonce_b),
            qkd_pool_client_fn=mock_qkd_client_low_occupancy,
            allow_explicit_fallback=False
        )
    assert "below 5% admission control floor" in str(excinfo.value)


def test_hake_quota_limit_triggers() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    # Create mitigation manager with rate limit of 2 req/s
    mitigation_mgr = MitigationManager(rate_limit_per_peer=2)

    alice = AliceSession(
        "alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg,
        mitigation_mgr=mitigation_mgr
    )

    # 1st request
    mitigation_mgr.check_quota("alice")
    # 2nd request
    mitigation_mgr.check_quota("alice")

    # 3rd request should fail
    with pytest.raises(QuotaExceededError):
        mitigation_mgr.check_quota("alice")


def test_hake_tampering_fails() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)

    ct1, nonce_a = alice.message1()
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Tamper with Message 2 MAC tag
    tampered_tau1 = bytearray(tau1)
    tampered_tau1[0] ^= 0xff
    tampered_tau1 = bytes(tampered_tau1)

    with pytest.raises(HandshakeError) as excinfo:
        alice.message3(
            (pk_e, tampered_tau1, ct2, nonce_b),
            qkd_pool_client_fn=None,
            allow_explicit_fallback=True
        )
    assert "Alice failed to verify Bob's Message 2 MAC" in str(excinfo.value)


# ---------------------------------------------------------------------------
# WP7 hardening regression tests
# ---------------------------------------------------------------------------

# --- 1. Security-mode reconciliation ---------------------------------------

def test_wp7_real_hake_modes_match_combiner_security_mode() -> None:
    """The real HAKE path must use the same mode spellings as combiner.SecurityMode."""
    kp_a, kp_b = _make_keypairs()

    hybrid_res, _ = _run_handshake(
        kp_a, kp_b,
        qkd_pool_client_fn=lambda action, key_id=None: (
            {"stored_key_count": 100, "max_key_count": 100} if action == "status" else (b"q" * 32, "kid")
        ),
        bob_qkd_pool_client_fn=lambda kid: b"q" * 32,
    )
    assert hybrid_res.security_mode == SecurityMode.HYBRID_QKD

    pqc_res, _ = _run_handshake(kp_a, kp_b, qkd_pool_client_fn=None, allow_explicit_fallback=True)
    assert pqc_res.security_mode == SecurityMode.PQC_ONLY

    # SecurityMode.REJECTED is never placed in a HandshakeResult: rejection is
    # always a HandshakeError (no result object at all), so a successful
    # PQC-only fallback can never be confused with a rejected handshake.
    with pytest.raises(HandshakeError):
        _run_handshake(kp_a, kp_b, qkd_pool_client_fn=None, allow_explicit_fallback=False)


# --- 2. Narrowed fallback exception handling --------------------------------

@pytest.mark.parametrize("expected_exc", [PoolExhausted, PeerQuotaExceeded])
def test_wp7_expected_qkd_unavailability_produces_pqc_only_when_allowed(expected_exc) -> None:
    """PoolExhausted / PeerQuotaExceeded raised by the client on 'get' are expected."""
    kp_a, kp_b = _make_keypairs()

    def client(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 100, "max_key_count": 100}
        raise expected_exc("no key available")

    res, bob_res = _run_handshake(kp_a, kp_b, qkd_pool_client_fn=client, allow_explicit_fallback=True)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.QKD_UNAVAILABLE
    assert bob_res.security_mode == SecurityMode.PQC_ONLY


@pytest.mark.parametrize("failing_action", ["status", "get"])
def test_wp7_unexpected_exception_is_not_converted_to_pqc_only(failing_action: str) -> None:
    """A programming/transport error must propagate, never become a quiet downgrade."""
    kp_a, kp_b = _make_keypairs()

    def client(action, key_id=None):
        if action == failing_action:
            raise RuntimeError("unexpected KME wire error")
        if action == "status":
            return {"stored_key_count": 100, "max_key_count": 100}
        raise AssertionError("unreachable")

    with pytest.raises(RuntimeError):
        _run_handshake(kp_a, kp_b, qkd_pool_client_fn=client, allow_explicit_fallback=True)


def test_wp7_unexpected_exception_type_error_from_malformed_status() -> None:
    """A malformed status payload (e.g. missing key) must not be swallowed either."""
    kp_a, kp_b = _make_keypairs()

    def client(action, key_id=None):
        if action == "status":
            return {}  # missing required keys -> KeyError inside message3
        raise AssertionError("unreachable")

    with pytest.raises(KeyError):
        _run_handshake(kp_a, kp_b, qkd_pool_client_fn=client, allow_explicit_fallback=True)


def test_wp7_strict_mode_still_rejects_on_expected_conditions() -> None:
    """allow_explicit_fallback=False still fails closed for expected QKD-unavailability."""
    kp_a, kp_b = _make_keypairs()

    def exhausted_client(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 100, "max_key_count": 100}
        raise PoolExhausted("no keys left")

    with pytest.raises(HandshakeError):
        _run_handshake(kp_a, kp_b, qkd_pool_client_fn=exhausted_client, allow_explicit_fallback=False)

    with pytest.raises(HandshakeError):
        _run_handshake(kp_a, kp_b, qkd_pool_client_fn=None, allow_explicit_fallback=False)


# --- 3. Explicit, observable fallback result --------------------------------

def test_wp7_result_reason_distinguishes_quota_vs_admission_vs_unavailable() -> None:
    kp_a, kp_b = _make_keypairs()

    quota_mgr = MitigationManager(rate_limit_per_peer=1)
    quota_mgr.check_quota("alice")  # consume the only slot before the handshake
    res, _ = _run_handshake(kp_a, kp_b, mitigation_mgr=quota_mgr, qkd_pool_client_fn=None)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.QUOTA_EXCEEDED

    def low_occupancy_client(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 4, "max_key_count": 100}
        raise AssertionError("get must not be called when admission control refuses")

    res, _ = _run_handshake(kp_a, kp_b, qkd_pool_client_fn=low_occupancy_client)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.ADMISSION_CONTROL

    res, _ = _run_handshake(kp_a, kp_b, qkd_pool_client_fn=None)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.QKD_UNAVAILABLE


def test_wp7_bob_reflects_peer_declared_reason_not_alice_cause() -> None:
    """Bob never learns Alice's specific reason; he only sees an empty key ID."""
    kp_a, kp_b = _make_keypairs()

    quota_mgr = MitigationManager(rate_limit_per_peer=1)
    quota_mgr.check_quota("alice")
    alice_res, bob_res = _run_handshake(kp_a, kp_b, mitigation_mgr=quota_mgr, qkd_pool_client_fn=None)

    assert alice_res.fallback_reason == FallbackReason.QUOTA_EXCEEDED
    assert bob_res.fallback_reason == FallbackReason.PEER_DECLARED
    assert alice_res.security_mode == bob_res.security_mode == SecurityMode.PQC_ONLY


def test_wp7_bob_fails_closed_when_key_id_present_but_no_local_client() -> None:
    """Previously Bob mislabelled this as HYBRID_QKD with no QKD material; now it fails closed."""
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10)

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key)

    ct1, nonce_a = alice.message1()
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))
    ct_star, q_id, tau2 = alice.message3(
        (pk_e, tau1, ct2, nonce_b),
        qkd_pool_client_fn=_pool_alice_client(pool),
        allow_explicit_fallback=False,
    )
    assert q_id  # Alice did commit to a real QKD key ID

    with pytest.raises(HandshakeError, match="no key pool client"):
        bob.message4((ct_star, q_id, tau2), qkd_pool_client_fn=None)


# --- 4. Per-peer quota state lifecycle, exercised through message3 ---------

def test_wp7_quota_persists_across_handshakes_for_same_peer_via_message3() -> None:
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10)
    shared_mgr = MitigationManager(rate_limit_per_peer=2)

    modes = []
    for _ in range(3):
        res, _ = _run_handshake(
            kp_a, kp_b,
            mitigation_mgr=shared_mgr,
            qkd_pool_client_fn=_pool_alice_client(pool),
            bob_qkd_pool_client_fn=_pool_bob_client(pool),
        )
        modes.append(res.security_mode)

    assert modes == [SecurityMode.HYBRID_QKD, SecurityMode.HYBRID_QKD, SecurityMode.PQC_ONLY]


def test_wp7_quota_does_not_persist_without_a_shared_manager() -> None:
    """Documents the opt-in behaviour: a fresh per-session manager never accumulates."""
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10)

    modes = []
    for _ in range(5):
        res, _ = _run_handshake(
            kp_a, kp_b,
            mitigation_mgr=None,  # AliceSession builds a fresh MitigationManager each time
            qkd_pool_client_fn=_pool_alice_client(pool),
            bob_qkd_pool_client_fn=_pool_bob_client(pool),
        )
        modes.append(res.security_mode)

    assert modes == [SecurityMode.HYBRID_QKD] * 5


def test_wp7_quota_is_independent_per_peer() -> None:
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10)
    shared_mgr = MitigationManager(rate_limit_per_peer=1)

    res_peer1, _ = _run_handshake(
        kp_a, kp_b, id_a="peer-1",
        mitigation_mgr=shared_mgr,
        qkd_pool_client_fn=_pool_alice_client(pool, master="peer-1"),
        bob_qkd_pool_client_fn=_pool_bob_client(pool, master="peer-1"),
    )
    res_peer2, _ = _run_handshake(
        kp_a, kp_b, id_a="peer-2",
        mitigation_mgr=shared_mgr,
        qkd_pool_client_fn=_pool_alice_client(pool, master="peer-2"),
        bob_qkd_pool_client_fn=_pool_bob_client(pool, master="peer-2"),
    )

    # peer-2's first request must not be blocked by peer-1 having used its slot.
    assert res_peer1.security_mode == SecurityMode.HYBRID_QKD
    assert res_peer2.security_mode == SecurityMode.HYBRID_QKD


def test_wp7_quota_window_expires_via_message3() -> None:
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10)
    clock = FakeClock()
    shared_mgr = MitigationManager(rate_limit_per_peer=1, clock=clock)

    res1, _ = _run_handshake(
        kp_a, kp_b, mitigation_mgr=shared_mgr,
        qkd_pool_client_fn=_pool_alice_client(pool),
        bob_qkd_pool_client_fn=_pool_bob_client(pool),
    )
    res2, _ = _run_handshake(
        kp_a, kp_b, mitigation_mgr=shared_mgr,
        qkd_pool_client_fn=_pool_alice_client(pool),
        bob_qkd_pool_client_fn=_pool_bob_client(pool),
    )
    clock.advance(1.01)
    res3, _ = _run_handshake(
        kp_a, kp_b, mitigation_mgr=shared_mgr,
        qkd_pool_client_fn=_pool_alice_client(pool),
        bob_qkd_pool_client_fn=_pool_bob_client(pool),
    )

    assert res1.security_mode == SecurityMode.HYBRID_QKD
    assert res2.security_mode == SecurityMode.PQC_ONLY
    assert res2.fallback_reason == FallbackReason.QUOTA_EXCEEDED
    assert res3.security_mode == SecurityMode.HYBRID_QKD


def test_wp7_quota_strict_mode_rejects_via_message3() -> None:
    kp_a, kp_b = _make_keypairs()
    shared_mgr = MitigationManager(rate_limit_per_peer=1)
    shared_mgr.check_quota("alice")  # pre-consume the single slot

    with pytest.raises(HandshakeError, match="exceeded request rate quota"):
        _run_handshake(kp_a, kp_b, mitigation_mgr=shared_mgr, qkd_pool_client_fn=None, allow_explicit_fallback=False)


# --- 5. Admission control regression tests ----------------------------------

def test_wp7_admission_control_above_threshold_uses_qkd() -> None:
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=100, initial_keys=6)  # 6% occupancy

    res, bob_res = _run_handshake(
        kp_a, kp_b,
        qkd_pool_client_fn=_pool_alice_client(pool),
        bob_qkd_pool_client_fn=_pool_bob_client(pool),
    )
    assert res.security_mode == SecurityMode.HYBRID_QKD
    assert bob_res.security_mode == SecurityMode.HYBRID_QKD
    assert pool.status()["stored_key_count"] == 5  # exactly one key consumed


def test_wp7_admission_control_below_threshold_refuses() -> None:
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=100, initial_keys=4)  # 4% occupancy

    with pytest.raises(HandshakeError, match="below 5% admission control floor"):
        _run_handshake(
            kp_a, kp_b,
            qkd_pool_client_fn=_pool_alice_client(pool),
            allow_explicit_fallback=False,
        )
    assert pool.status()["stored_key_count"] == 4  # nothing consumed on refusal


def test_wp7_admission_control_fallback_enabled_consumes_no_key() -> None:
    kp_a, kp_b = _make_keypairs()
    pool = QKDKeyPool(refill_bps=0, depth=100, initial_keys=4)  # 4% occupancy

    res, bob_res = _run_handshake(
        kp_a, kp_b,
        qkd_pool_client_fn=_pool_alice_client(pool),
        allow_explicit_fallback=True,
    )
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.ADMISSION_CONTROL
    assert bob_res.security_mode == SecurityMode.PQC_ONLY
    assert pool.status()["stored_key_count"] == 4  # "get" was never called


def test_wp7_admission_control_exact_boundary() -> None:
    kp_a, kp_b = _make_keypairs()

    # Exactly 5% (100 * 0.05 == 5) is the documented admit boundary.
    admitted_pool = QKDKeyPool(refill_bps=0, depth=100, initial_keys=5)
    res, _ = _run_handshake(
        kp_a, kp_b,
        qkd_pool_client_fn=_pool_alice_client(admitted_pool),
        bob_qkd_pool_client_fn=_pool_bob_client(admitted_pool),
    )
    assert res.security_mode == SecurityMode.HYBRID_QKD

    # Just below 5% is refused: 6/128 = 4.69% (7/128 = 5.47% would be admitted).
    refused_pool = QKDKeyPool(refill_bps=0, depth=128, initial_keys=6)
    res, _ = _run_handshake(
        kp_a, kp_b,
        qkd_pool_client_fn=_pool_alice_client(refused_pool),
        allow_explicit_fallback=True,
    )
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.ADMISSION_CONTROL
