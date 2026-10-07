"""WP7 mitigation policies: configuration, client adapters and the policy pipeline."""
import csv
import json
import math
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qkd_hake.benchmarks.policy_eval import (
    FIELDS, HEAVY_PEER, evaluate_policy, peer_schedule, run_policy_comparison,
)
from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.mitigations.mitigations import (
    POLICY_NAMES, AdmissionControlError, MitigationManager, QKDUnavailable, policy_from_config,
)
from qkd_hake.protocol.combiner import FallbackReason, SecurityMode
from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeError
from qkd_hake.qkd_mock.client import LocalPoolClient, QKDClient
from qkd_hake.qkd_mock.pool import QKDKeyPool
from qkd_hake.qkd_mock.server import create_app
from qkd_hake.settings import Settings

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "experiments.json"
ALG = "ML-KEM-512"


@pytest.fixture(scope="module")
def keys():
    kem = OQSKEM(ALG)
    return kem.generate_keypair(), kem.generate_keypair()


def handshake(keys, mgr, alice_fn, bob_fn, allow_explicit_fallback=True, id_a="alice"):
    kp_a, kp_b = keys
    alice = AliceSession(id_a, kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, ALG,
                         mitigation_mgr=mgr)
    bob = BobSession(id_a, kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, ALG)
    m2 = bob.message2(alice.message1())
    m3 = alice.message3(m2, qkd_pool_client_fn=alice_fn,
                        allow_explicit_fallback=allow_explicit_fallback)
    tau3, bob_res = bob.message4(m3, qkd_pool_client_fn=bob_fn)
    alice_res = alice.derive_and_verify(tau3)
    assert alice_res.session_key == bob_res.session_key
    assert alice_res.security_mode == bob_res.security_mode
    return alice_res


# --- policy definitions / configuration -------------------------------------

def test_policy_from_config_maps_the_three_policies() -> None:
    u = policy_from_config("uncontrolled_explicit_downgrade")
    q = policy_from_config("per_peer_quota", per_peer_quota_rate_per_second=7)
    a = policy_from_config("admission_control", admission_threshold=0.1)

    assert (u.rate_limit_per_peer, u.admission_threshold, u.allow_explicit_fallback) == (0, 0.0, True)
    assert (q.rate_limit_per_peer, q.admission_threshold, q.allow_explicit_fallback) == (7, 0.0, True)
    assert (a.rate_limit_per_peer, a.admission_threshold, a.allow_explicit_fallback) == (0, 0.1, False)

    with pytest.raises(ValueError):
        policy_from_config("no_such_policy")


def test_every_configured_policy_resolves() -> None:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert tuple(cfg["policies"]) == POLICY_NAMES
    ps = cfg["policy_settings"]
    for name in cfg["policies"]:
        policy_from_config(
            name,
            per_peer_quota_rate_per_second=ps["per_peer_quota_rate_per_second"],
            admission_threshold=ps["admission_threshold"],
        )


def test_admission_threshold_is_configurable_and_zero_disables_it() -> None:
    with pytest.raises(AdmissionControlError, match="below 10% admission control floor"):
        MitigationManager(admission_threshold=0.10).check_admission_control(9, 100)
    MitigationManager(admission_threshold=0.10).check_admission_control(10, 100)
    MitigationManager(admission_threshold=0.0).check_admission_control(0, 100)
    with pytest.raises(ValueError):
        MitigationManager(admission_threshold=1.5)


# --- in-process KME adapter --------------------------------------------------

def test_local_pool_client_end_to_end_hybrid(keys) -> None:
    pool = QKDKeyPool(refill_bps=0, depth=10, initial_keys=10)
    client = LocalPoolClient(pool, "alice", "bob")
    res = handshake(keys, MitigationManager(), client.initiator_fn, client.responder_fn)
    assert res.security_mode == SecurityMode.HYBRID_QKD
    assert pool.status()["stored_key_count"] == 9


def test_disabled_admission_control_lets_last_keys_be_used(keys) -> None:
    pool = QKDKeyPool(refill_bps=0, depth=100, initial_keys=1)  # 1% occupancy
    client = LocalPoolClient(pool, "alice", "bob")

    gated = handshake(keys, MitigationManager(), client.initiator_fn, client.responder_fn)
    assert gated.fallback_reason == FallbackReason.ADMISSION_CONTROL

    uncontrolled = policy_from_config("uncontrolled_explicit_downgrade").new_manager()
    res = handshake(keys, uncontrolled, client.initiator_fn, client.responder_fn)
    assert res.security_mode == SecurityMode.HYBRID_QKD
    res = handshake(keys, uncontrolled, client.initiator_fn, client.responder_fn)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.QKD_UNAVAILABLE


# --- HTTP KME (REST server + QKDClient) --------------------------------------

def _http_clients(settings: Settings):
    tc = TestClient(create_app(settings))
    alice = QKDClient("http://testserver", local_sae_id="alice", peer_sae_id="bob", http=tc)
    bob = QKDClient("http://testserver", local_sae_id="bob", peer_sae_id="alice", http=tc)
    return alice, bob


def test_http_kme_end_to_end_hybrid(keys) -> None:
    alice, bob = _http_clients(Settings(refill_bps=0, pool_depth=10, initial_keys=10))
    res = handshake(keys, MitigationManager(), alice.initiator_fn, bob.responder_fn)
    assert res.security_mode == SecurityMode.HYBRID_QKD
    assert alice.get_status()["stored_key_count"] == 9


def test_http_503_is_expected_unavailability_not_a_crash(keys) -> None:
    alice, bob = _http_clients(Settings(refill_bps=0, pool_depth=1, initial_keys=0))
    with pytest.raises(QKDUnavailable):
        alice.get_key()

    uncontrolled = policy_from_config("uncontrolled_explicit_downgrade").new_manager()
    res = handshake(keys, uncontrolled, alice.initiator_fn, bob.responder_fn)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.QKD_UNAVAILABLE

    with pytest.raises(HandshakeError):
        handshake(keys, uncontrolled, alice.initiator_fn, bob.responder_fn,
                  allow_explicit_fallback=False)


def test_http_kme_per_peer_quota_triggers_explicit_fallback(keys) -> None:
    alice, bob = _http_clients(
        Settings(refill_bps=0, pool_depth=10, initial_keys=10, per_peer_quota=1))
    alice.get_key()  # leave one key outstanding (never retrieved by Bob)
    uncontrolled = policy_from_config("uncontrolled_explicit_downgrade").new_manager()
    res = handshake(keys, uncontrolled, alice.initiator_fn, bob.responder_fn)
    assert res.security_mode == SecurityMode.PQC_ONLY
    assert res.fallback_reason == FallbackReason.QKD_UNAVAILABLE


# --- policy pipeline (real handshakes, simulated clock) ----------------------

LIGHT = ["peer-light-1", "peer-light-2", "peer-light-3"]


@pytest.fixture(scope="module")
def pipeline_keys():
    kem = OQSKEM(ALG)
    return {pid: kem.generate_keypair() for pid in [HEAVY_PEER, *LIGHT]}, kem.generate_keypair()


def _case(pipeline_keys, name, supply_kbps, rate, seconds=20.0, depth=128):
    peer_keys, bob_keys = pipeline_keys
    row = evaluate_policy(
        policy_from_config(name), supply_kbps=supply_kbps, rate=rate, pool_depth=depth,
        measurement_seconds=seconds, repeat=1, algorithm=ALG, peer_keys=peer_keys,
        bob_keys=bob_keys, schedule_fn=lambda n: peer_schedule(n, 0.5, LIGHT),
    )
    assert row["hybrid_qkd"] + row["pqc_only"] + row["rejected"] == row["attempts"]
    assert row["qkd_keys_consumed"] == row["hybrid_qkd"]
    return row


def test_peer_schedule_splits_load() -> None:
    s = peer_schedule(8, 0.5, LIGHT)
    assert s.count(HEAVY_PEER) == 4
    assert {p for p in s if p != HEAVY_PEER} == set(LIGHT)


def test_pipeline_no_overload_all_policies_stay_hybrid(pipeline_keys) -> None:
    for name in POLICY_NAMES:
        row = _case(pipeline_keys, name, supply_kbps=100, rate=5)
        assert row["hybrid_qkd_pct"] == 100.0, name


def test_pipeline_uncontrolled_downgrades_explicitly_under_starvation(pipeline_keys) -> None:
    row = _case(pipeline_keys, "uncontrolled_explicit_downgrade", supply_kbps=1, rate=20)
    assert row["pqc_only"] > 0
    assert row["rejected"] == 0
    assert row["fallback_qkd_unavailable"] == row["pqc_only"]
    assert row["min_pool_occupancy_keys"] == 0  # pool fully drained


def test_pipeline_per_peer_quota_limits_the_heavy_peer(pipeline_keys) -> None:
    starved = _case(pipeline_keys, "per_peer_quota", supply_kbps=1, rate=20)
    assert starved["fallback_quota_exceeded"] > 0
    assert starved["rejected"] == 0
    assert starved["heavy_peer_hybrid_qkd_pct"] < starved["light_peers_hybrid_qkd_pct"]

    uncontrolled = _case(pipeline_keys, "uncontrolled_explicit_downgrade", supply_kbps=1, rate=20)
    assert starved["light_peers_hybrid_qkd_pct"] > uncontrolled["light_peers_hybrid_qkd_pct"]

    # With ample supply the quota still caps the heavy peer (its cost) and
    # never affects light peers that stay under quota.
    ample = _case(pipeline_keys, "per_peer_quota", supply_kbps=100, rate=20)
    assert ample["fallback_qkd_unavailable"] == 0
    assert ample["fallback_quota_exceeded"] > 0
    assert ample["light_peers_hybrid_qkd_pct"] == 100.0


def test_pipeline_admission_control_refuses_instead_of_degrading(pipeline_keys) -> None:
    depth = 128
    row = _case(pipeline_keys, "admission_control", supply_kbps=1, rate=20, depth=depth)
    assert row["pqc_only"] == 0
    assert row["rejected"] > 0
    # Admission is checked before each key is taken, so the pool never falls
    # more than one key below the 5% floor and is never fully drained.
    assert row["min_pool_occupancy_keys"] >= math.ceil(0.05 * depth) - 1
    assert row["min_pool_occupancy_keys"] > 0


def test_run_policy_comparison_writes_csv(tmp_path) -> None:
    out = run_policy_comparison(CONFIG, tmp_path, measurement_seconds=2.0, repeats=2,
                                supply_rates_kbps=[100], handshake_rates=[5])
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert out.name == "wp7_policy_comparison.csv"
    assert list(rows[0].keys()) == FIELDS
    assert [r["policy"] for r in rows] == [p for p in POLICY_NAMES for _ in range(2)]


def test_cli_policies_subcommand_is_wired(monkeypatch) -> None:
    import qkd_hake.cli as cli
    calls = {}
    monkeypatch.setattr(cli, "run_policy_comparison", lambda **kw: calls.update(kw))
    monkeypatch.setattr(sys, "argv", ["qkd-hake", "policies", "--measurement-seconds", "5",
                                      "--repeats", "2", "--config", "x.json"])
    cli.main()
    assert calls == {"config_path": "x.json", "measurement_seconds": 5.0, "repeats": 2}
