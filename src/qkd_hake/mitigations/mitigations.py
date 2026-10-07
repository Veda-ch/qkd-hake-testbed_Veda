from __future__ import annotations
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable


class QKDUnavailable(Exception):
    """Expected condition: the QKD layer cannot supply a key right now.

    QKD pool clients passed to ``AliceSession.message3`` should raise this (or
    ``PoolExhausted`` / ``PeerQuotaExceeded`` from ``qkd_mock.pool``) for
    KME-side unavailability. Any other exception is treated as unexpected and
    is never converted into a PQC-only session.
    """


class AdmissionControlError(QKDUnavailable):
    pass


class QuotaExceededError(QKDUnavailable):
    pass


class MitigationManager:
    """Handshake-side QKD request-rate quota and admission control.

    Quota state lives in the manager instance and is keyed by peer ID, so one
    manager shared by many ``AliceSession`` objects rate-limits each peer
    across handshakes while keeping different peers independent. Share one
    instance per QKD link/experiment; do not use a module-level singleton.
    """

    def __init__(
        self,
        rate_limit_per_peer: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
        admission_threshold: float = 0.05,
    ) -> None:
        if not 0.0 <= admission_threshold <= 1.0:
            raise ValueError("admission_threshold must be within [0, 1]")
        self.rate_limit_per_peer = rate_limit_per_peer
        self.admission_threshold = admission_threshold
        self._clock = clock
        self._lock = threading.Lock()
        self.peer_request_history: dict[str, list[float]] = defaultdict(list)

    def check_quota(self, peer_id: str) -> None:
        """Enforce maximum QKD requests per second per peer."""
        if not self.rate_limit_per_peer:
            return
        with self._lock:
            now = self._clock()
            history = [t for t in self.peer_request_history[peer_id] if now - t < 1.0]
            if len(history) >= self.rate_limit_per_peer:
                self.peer_request_history[peer_id] = history
                raise QuotaExceededError(
                    f"Peer {peer_id} exceeded request rate quota of {self.rate_limit_per_peer}/s"
                )
            history.append(now)
            self.peer_request_history[peer_id] = history

    def check_admission_control(self, stored_keys: int, max_keys: int) -> None:
        """Fail-fast when pool occupancy drops below the admission threshold.

        The default threshold is 5%; a threshold of 0 disables admission control.
        """
        if not self.admission_threshold:
            return
        if max_keys > 0 and (stored_keys / max_keys) < self.admission_threshold:
            raise AdmissionControlError(
                f"KMS Pool occupancy ({stored_keys}/{max_keys}) below "
                f"{self.admission_threshold:.0%} admission control floor"
            )


POLICY_NAMES = ("uncontrolled_explicit_downgrade", "per_peer_quota", "admission_control")


@dataclass(frozen=True, slots=True)
class MitigationPolicy:
    """One WP7 starvation-handling policy, as named in configs/experiments.json.

    - uncontrolled_explicit_downgrade: no quota, no admission control; when
      QKD is unavailable the session continues as explicit PQC_ONLY.
    - per_peer_quota: per-peer QKD request-rate quota; requests over quota
      (or when QKD is unavailable) continue as explicit PQC_ONLY.
    - admission_control: refuse instead of degrading; handshakes are rejected
      when pool occupancy is below the admission threshold or QKD is unavailable.
    """

    name: str
    rate_limit_per_peer: float
    admission_threshold: float
    allow_explicit_fallback: bool

    def new_manager(self, clock: Callable[[], float] = time.monotonic) -> MitigationManager:
        """Fresh manager for one experiment run; share it across all its sessions."""
        return MitigationManager(
            rate_limit_per_peer=self.rate_limit_per_peer,
            clock=clock,
            admission_threshold=self.admission_threshold,
        )


def policy_from_config(
    name: str,
    *,
    per_peer_quota_rate_per_second: float = 5.0,
    admission_threshold: float = 0.05,
) -> MitigationPolicy:
    if name == "uncontrolled_explicit_downgrade":
        return MitigationPolicy(name, 0, 0.0, True)
    if name == "per_peer_quota":
        return MitigationPolicy(name, per_peer_quota_rate_per_second, 0.0, True)
    if name == "admission_control":
        return MitigationPolicy(name, 0, admission_threshold, False)
    raise ValueError(f"unknown mitigation policy: {name!r} (expected one of {POLICY_NAMES})")
