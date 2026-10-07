from __future__ import annotations

from dataclasses import dataclass
try:
    from enum import StrEnum
except ImportError:
    from enum import Enum
    class StrEnum(str, Enum):
        pass
import hashlib

from qkd_hake.crypto.kdf import labelled_expand, labelled_extract


class SecurityMode(StrEnum):
    HYBRID_QKD = "HYBRID_QKD"
    PQC_ONLY = "PQC_ONLY"
    REJECTED = "REJECTED"


class FallbackReason(StrEnum):
    """Why a handshake did not run in HYBRID_QKD mode (local view, not on the wire)."""

    NONE = "NONE"
    QKD_UNAVAILABLE = "QKD_UNAVAILABLE"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    ADMISSION_CONTROL = "ADMISSION_CONTROL"
    # Responder side only: the initiator signalled PQC-only (empty QKD key ID);
    # the initiator's reason is not transmitted.
    PEER_DECLARED = "PEER_DECLARED"


class QKDRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DerivedKeys:
    mode: SecurityMode
    session_key: bytes
    client_confirmation_key: bytes
    server_confirmation_key: bytes


def derive_keys(
    *,
    static_kem_secret: bytes,
    ephemeral_kem_secret: bytes,
    transcript: bytes,
    qkd_key: bytes | None,
    allow_explicit_pqc_fallback: bool,
) -> DerivedKeys:
    """Prototype combiner; replace labels only after matching the paper exactly."""
    if not static_kem_secret or not ephemeral_kem_secret:
        raise ValueError("both KEM components are required")
    if qkd_key is None and not allow_explicit_pqc_fallback:
        raise QKDRequired("QKD key unavailable; handshake rejected")

    mode = SecurityMode.HYBRID_QKD if qkd_key is not None else SecurityMode.PQC_ONLY
    transcript_hash = hashlib.sha3_256(
        mode.value.encode("ascii") + b"\x00" + transcript
    ).digest()
    prk = labelled_extract(transcript_hash, "static-kem", static_kem_secret)
    prk = labelled_extract(prk, "ephemeral-kem", ephemeral_kem_secret)
    if qkd_key is not None:
        prk = labelled_extract(prk, "qkd-key", qkd_key)
    else:
        prk = labelled_extract(prk, "explicit-pqc-only", b"")

    return DerivedKeys(
        mode=mode,
        session_key=labelled_expand(prk, "session-key", transcript_hash, 32),
        client_confirmation_key=labelled_expand(
            prk, "client-confirmation", transcript_hash, 32
        ),
        server_confirmation_key=labelled_expand(
            prk, "server-confirmation", transcript_hash, 32
        ),
    )
