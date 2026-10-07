"""WP7 mitigation-policy comparison.

Runs real 4-message HAKE handshakes through each mitigation policy against a
finite, rate-limited QKD key pool (simulated clock shared by the pool and the
quota). Offered load comes from one heavy peer plus several light peers so the
per-peer quota is observable. Results go to results/wp7_policy_comparison.csv.

This is separate from the WP6 sweep (suite.sweep_bottleneck_analysis), which
measures raw pool starvation without the protocol or any mitigation.
"""
from __future__ import annotations

import csv
import json
import statistics
import time
from collections import Counter
from pathlib import Path

from qkd_hake.benchmarks.suite import SimulatedClock, np_percentile
from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.mitigations.mitigations import MitigationPolicy, policy_from_config
from qkd_hake.protocol.combiner import FallbackReason, SecurityMode
from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeError
from qkd_hake.qkd_mock.client import LocalPoolClient
from qkd_hake.qkd_mock.pool import QKDKeyPool

BOB_ID = "bob"
HEAVY_PEER = "peer-heavy"

FIELDS = [
    "policy", "rate_limit_per_peer", "admission_threshold", "allow_explicit_fallback",
    "qkd_supply_rate_kbps", "handshake_rate_req_s", "pool_depth_keys", "repeat",
    "measurement_seconds", "attempts",
    "hybrid_qkd", "pqc_only", "rejected",
    "hybrid_qkd_pct", "pqc_only_pct", "rejected_pct", "completed_pct",
    "fallback_quota_exceeded", "fallback_admission_control", "fallback_qkd_unavailable",
    "qkd_keys_consumed",
    "heavy_peer_attempts", "heavy_peer_hybrid_qkd_pct",
    "light_peers_attempts", "light_peers_hybrid_qkd_pct",
    "completed_latency_median_ms", "completed_latency_p95_ms", "rejected_latency_median_ms",
    "min_pool_occupancy_keys", "final_pool_occupancy_keys",
]


def peer_schedule(n: int, heavy_share: float, light_ids: list[str]) -> list[str]:
    """Deterministic request-to-peer assignment with ``heavy_share`` going to the heavy peer."""
    out: list[str] = []
    light_i = 0
    for i in range(n):
        if not light_ids or int((i + 1) * heavy_share) > int(i * heavy_share):
            out.append(HEAVY_PEER)
        else:
            out.append(light_ids[light_i % len(light_ids)])
            light_i += 1
    return out


def _pct(part: int, whole: int) -> float:
    return part / whole * 100.0 if whole else 0.0


def evaluate_policy(
    policy: MitigationPolicy,
    *,
    supply_kbps: float,
    rate: float,
    pool_depth: int,
    measurement_seconds: float,
    repeat: int,
    algorithm: str,
    peer_keys: dict,
    bob_keys,
    schedule_fn,
    key_size_bits: int = 256,
) -> dict:
    """Run one (policy, supply, rate) case and return one CSV row."""
    clock = SimulatedClock()
    pool = QKDKeyPool(
        refill_bps=int(supply_kbps * 1000), depth=pool_depth, initial_keys=pool_depth,
        key_size_bits=key_size_bits, clock=clock,
    )
    mgr = policy.new_manager(clock)
    attempts = max(1, int(rate * measurement_seconds))
    schedule = schedule_fn(attempts)

    modes: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    per_peer_attempts: Counter[str] = Counter()
    per_peer_hybrid: Counter[str] = Counter()
    completed_ms: list[float] = []
    rejected_ms: list[float] = []
    min_pool = pool_depth

    for peer in schedule:
        clock.advance(1.0 / rate)
        kp = peer_keys[peer]
        client = LocalPoolClient(pool, peer, BOB_ID)
        per_peer_attempts[peer] += 1

        t0 = time.perf_counter_ns()
        alice = AliceSession(peer, kp.public_key, kp.secret_key, BOB_ID, bob_keys.public_key,
                             algorithm, mitigation_mgr=mgr)
        bob = BobSession(peer, kp.public_key, BOB_ID, bob_keys.public_key, bob_keys.secret_key,
                         algorithm)
        ct1, nonce_a = alice.message1()
        msg2 = bob.message2((ct1, nonce_a))
        try:
            msg3 = alice.message3(msg2, qkd_pool_client_fn=client.initiator_fn,
                                  allow_explicit_fallback=policy.allow_explicit_fallback)
        except HandshakeError:
            # Policy rejection (strict mode): no session key is produced.
            rejected_ms.append((time.perf_counter_ns() - t0) / 1e6)
            modes[SecurityMode.REJECTED] += 1
        else:
            tau3, bob_res = bob.message4(msg3, qkd_pool_client_fn=client.responder_fn)
            alice_res = alice.derive_and_verify(tau3)
            completed_ms.append((time.perf_counter_ns() - t0) / 1e6)
            if (alice_res.session_key != bob_res.session_key
                    or alice_res.security_mode != bob_res.security_mode):
                raise RuntimeError("peers disagree on session key or security mode")
            modes[alice_res.security_mode] += 1
            reasons[alice_res.fallback_reason] += 1
            if alice_res.security_mode == SecurityMode.HYBRID_QKD:
                per_peer_hybrid[peer] += 1

        min_pool = min(min_pool, pool.status()["stored_key_count"])

    hybrid = modes[SecurityMode.HYBRID_QKD]
    pqc = modes[SecurityMode.PQC_ONLY]
    rejected = modes[SecurityMode.REJECTED]
    heavy_att = per_peer_attempts[HEAVY_PEER]
    light_att = attempts - heavy_att
    light_hybrid = hybrid - per_peer_hybrid[HEAVY_PEER]

    return {
        "policy": policy.name,
        "rate_limit_per_peer": policy.rate_limit_per_peer,
        "admission_threshold": policy.admission_threshold,
        "allow_explicit_fallback": policy.allow_explicit_fallback,
        "qkd_supply_rate_kbps": supply_kbps,
        "handshake_rate_req_s": rate,
        "pool_depth_keys": pool_depth,
        "repeat": repeat,
        "measurement_seconds": measurement_seconds,
        "attempts": attempts,
        "hybrid_qkd": hybrid,
        "pqc_only": pqc,
        "rejected": rejected,
        "hybrid_qkd_pct": round(_pct(hybrid, attempts), 4),
        "pqc_only_pct": round(_pct(pqc, attempts), 4),
        "rejected_pct": round(_pct(rejected, attempts), 4),
        "completed_pct": round(_pct(hybrid + pqc, attempts), 4),
        "fallback_quota_exceeded": reasons[FallbackReason.QUOTA_EXCEEDED],
        "fallback_admission_control": reasons[FallbackReason.ADMISSION_CONTROL],
        "fallback_qkd_unavailable": reasons[FallbackReason.QKD_UNAVAILABLE],
        # Every HYBRID_QKD session consumes exactly one key; no other path issues one.
        "qkd_keys_consumed": hybrid,
        "heavy_peer_attempts": heavy_att,
        "heavy_peer_hybrid_qkd_pct": round(_pct(per_peer_hybrid[HEAVY_PEER], heavy_att), 4),
        "light_peers_attempts": light_att,
        "light_peers_hybrid_qkd_pct": round(_pct(light_hybrid, light_att), 4),
        "completed_latency_median_ms": round(statistics.median(completed_ms), 4) if completed_ms else "",
        "completed_latency_p95_ms": round(np_percentile(completed_ms, 95), 4) if completed_ms else "",
        "rejected_latency_median_ms": round(statistics.median(rejected_ms), 4) if rejected_ms else "",
        "min_pool_occupancy_keys": min_pool,
        "final_pool_occupancy_keys": pool.status()["stored_key_count"],
    }


def run_policy_comparison(
    config_path: str | Path = "configs/experiments.json",
    output_dir: str | Path = "results",
    *,
    measurement_seconds: float = 30.0,
    repeats: int = 3,
    policies: list[str] | None = None,
    supply_rates_kbps: list[float] | None = None,
    handshake_rates: list[float] | None = None,
) -> Path:
    if measurement_seconds <= 0:
        raise ValueError("measurement_seconds must be positive")
    if repeats <= 0:
        raise ValueError("repeats must be positive")

    cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    ps = cfg.get("policy_settings", {})
    policy_names = policies or cfg["policies"]
    supplies = supply_rates_kbps or cfg["qkd_supply_kbps"]
    rates = handshake_rates or cfg["handshake_rates_per_second"]
    key_size_bits = cfg.get("qkd_key_size_bits", 256)
    pool_depth = ps.get("pool_depth_keys", 128)
    algorithm = ps.get("kem_algorithm", "ML-KEM-512")
    heavy_share = ps.get("heavy_peer_share", 0.5)
    light_ids = [f"peer-light-{i}" for i in range(1, ps.get("light_peers", 3) + 1)]

    policy_objs = [
        policy_from_config(
            name,
            per_peer_quota_rate_per_second=ps.get("per_peer_quota_rate_per_second", 5.0),
            admission_threshold=ps.get("admission_threshold", 0.05),
        )
        for name in policy_names
    ]

    kem = OQSKEM(algorithm)
    peer_keys = {pid: kem.generate_keypair() for pid in [HEAVY_PEER, *light_ids]}
    bob_keys = kem.generate_keypair()

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    csv_file = out_path / "wp7_policy_comparison.csv"

    print(f"Starting WP7 policy comparison: {len(policy_objs)} policies, "
          f"supply {list(supplies)} kbps, rates {list(rates)} req/s, "
          f"{measurement_seconds:.1f}s x {repeats} repeats, depth {pool_depth}, {algorithm}")

    with csv_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for policy in policy_objs:
            print(f"\nPolicy: {policy.name}")
            for supply in supplies:
                for rate in rates:
                    for repeat in range(1, repeats + 1):
                        row = evaluate_policy(
                            policy, supply_kbps=supply, rate=rate, pool_depth=pool_depth,
                            measurement_seconds=measurement_seconds, repeat=repeat,
                            algorithm=algorithm, peer_keys=peer_keys, bob_keys=bob_keys,
                            schedule_fn=lambda n: peer_schedule(n, heavy_share, light_ids),
                            key_size_bits=key_size_bits,
                        )
                        writer.writerow(row)
                    print(f"  supply={supply:>5} kbps | rate={rate:>4}/s | "
                          f"hybrid={row['hybrid_qkd_pct']:6.2f}% "
                          f"pqc_only={row['pqc_only_pct']:6.2f}% "
                          f"rejected={row['rejected_pct']:6.2f}% | "
                          f"heavy/light hybrid={row['heavy_peer_hybrid_qkd_pct']:.1f}/"
                          f"{row['light_peers_hybrid_qkd_pct']:.1f}%")

    print(f"\nWP7 policy comparison written to: {csv_file}")
    return csv_file
