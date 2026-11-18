"""
core.schnorr
============

Schnorr identification protocol, implemented transparently from first
principles on top of :mod:`core.math_params`.

Overview
--------

* **Key derivation** — a private scalar ``x ∈ [1, q-1]`` is derived from a
  passphrase with ``Argon2id`` (or PBKDF2-HMAC-SHA256) followed by HKDF-SHA256
  (RFC 5869, implemented manually over :mod:`hmac`), mapped into ``[0, q-1]``.
  A random keypair can also be generated. The public key is ``y = g^x mod p``.

* **Interactive 3-pass identification**

    1. Prover draws ``r ∈ [1, q-1]`` and sends the commitment ``t = g^r mod p``.
    2. Verifier draws a 128-bit challenge ``c ∈ [1, 2^128 - 1]``.
    3. Prover answers ``s = (r + c·x) mod q``.
    4. Verifier checks ``g^s ≡ t · y^c (mod p)`` with subgroup checks on
       ``t`` and ``y``.

* **Fiat-Shamir non-interactive transform** — the verifier's random challenge
  is replaced by ``c = SHA-256(g ‖ y ‖ t ‖ session_nonce) mod q`` so a single
  (t, s, session_nonce) triple authenticates a single request, e.g. API token
  signing.

* **Honest-verifier zero knowledge** — verification consumes only public
  values ``(g, y, t, c, s)``; ``x`` and ``r`` never leave the prover.

All randomness comes from :mod:`secrets`. Tag constants provide domain
separation between the two protocol modes.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from core.math_params import (
    GroupParameters,
    bytes_to_int,
    get_rfc3526_2048,
    int_to_bytes,
    is_valid_group_element,
)

# Domain-separation tags (ASCII, versioned).
_HKDF_INFO_SCALAR = b"schnorr-private-scalar-v1"
_FS_TAG = b"SCHNORR-FS-v1"
_KDF_ARGON2_SALT = b"schnorr-kdf:argon2:"
_KDF_PBKDF2_SALT = b"schnorr-kdf:pbkdf2:"
_KDF_HKDF_SALT = b"schnorr-kdf:hkdf:"

# Interactive challenges are 128-bit values drawn uniformly from [1, 2**128-1].
CHALLENGE_BITS = 128
MAX_CHALLENGE = (1 << CHALLENGE_BITS) - 1


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) — implemented over hmac/hashlib, no third-party dependency
# ---------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    """HKDF-SHA256 extract-then-expand. ``length`` ≤ 255*32 bytes."""
    if length > 255 * 32:
        raise ValueError("HKDF-SHA256 cannot produce more than 8160 bytes")
    salt = salt if salt is not None else b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    derived = b""
    previous = b""
    for counter in range(1, math.ceil(length / 32) + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        derived += previous
    return derived[:length]


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_private_scalar(
    passphrase: str,
    username: str,
    group: Optional[GroupParameters] = None,
    *,
    kdf: Optional[str] = "argon2id",
    argon2_time_cost: int = 3,
    argon2_memory_cost: int = 65536,
    argon2_parallelism: int = 4,
    pbkdf2_iterations: int = 600_000,
) -> int:
    """Deterministically derive the private scalar ``x ∈ [1, q-1]``.

    Pipeline: ``passphrase --(Argon2id|PBKDF2)--> 32-byte key material
    --(HKDF-SHA256, wide output)--> integer --(mod q)--> x``.

    The salts are public, deterministic functions of the username. That is
    intentional: the goal is *key diversification* (same passphrase, different
    user → different key), not password storage. The passphrase and the
    derived scalar never leave the caller's machine.
    """
    group = group or get_rfc3526_2048()
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    username_bytes = username.strip().lower().encode("utf-8")
    kdf = (kdf or "argon2id").lower()
    if kdf == "argon2id":
        from argon2.low_level import Type, hash_secret_raw

        salt = hashlib.sha256(_KDF_ARGON2_SALT + username_bytes).digest()
        material = hash_secret_raw(
            passphrase.encode("utf-8"),
            salt,
            time_cost=argon2_time_cost,
            memory_cost=argon2_memory_cost,
            parallelism=argon2_parallelism,
            hash_len=32,
            type=Type.ID,
        )
    elif kdf == "pbkdf2":
        salt = hashlib.sha256(_KDF_PBKDF2_SALT + username_bytes).digest()
        material = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, pbkdf2_iterations, 32)
    else:
        raise ValueError(f"unsupported kdf {kdf!r} (expected 'argon2id' or 'pbkdf2')")
    # Wide-output modulo mapping: bias is ≤ 2**-128 relative to q, negligible.
    hkdf_salt = hashlib.sha256(_KDF_HKDF_SALT + username_bytes).digest()
    width_bytes = (group.q.bit_length() + 128 + 7) // 8
    okm = hkdf_sha256(material, hkdf_salt, _HKDF_INFO_SCALAR, width_bytes)
    scalar = bytes_to_int(okm) % group.q
    if scalar == 0:  # probability ≈ 2^-(q bits); remap deterministically, never return 0
        scalar = 1
    return scalar


@dataclass(frozen=True)
class KeyPair:
    private_scalar: int
    public_key: int
    group_name: str

    @property
    def public_key_hex(self) -> str:
        return format(self.public_key, "x")


def generate_keypair(group: Optional[GroupParameters] = None) -> KeyPair:
    """Generate a fresh random keypair (x ∈ [1, q-1])."""
    group = group or get_rfc3526_2048()
    x = secrets.randbelow(group.q - 1) + 1
    return KeyPair(private_scalar=x, public_key=pow(group.g, x, group.p), group_name=group.name)


def keypair_from_passphrase(
    passphrase: str,
    username: str,
    group: Optional[GroupParameters] = None,
    *,
    kdf: Optional[str] = "argon2id",
) -> KeyPair:
    """Derive the deterministic passphrase keypair for ``username``."""
    group = group or get_rfc3526_2048()
    x = derive_private_scalar(passphrase, username, group, kdf=kdf)
    return KeyPair(private_scalar=x, public_key=pow(group.g, x, group.p), group_name=group.name)


def public_key_fingerprint(public_key: int) -> str:
    """Truncated SHA-256 fingerprint for logs/displays (never of the secret)."""
    return hashlib.sha256(format(public_key, "x").encode()).hexdigest()[:16]


def parse_hex_int(value: str) -> int:
    """Parse a (possibly ``0x``-prefixed) hex string into an int."""
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("expected a non-empty hexadecimal string")
    return int(text, 16)


# ---------------------------------------------------------------------------
# Fiat-Shamir challenge derivation
# ---------------------------------------------------------------------------

def fiat_shamir_challenge(
    g: int,
    y: int,
    t: int,
    session_nonce: bytes,
    q: int,
    byte_length: int,
) -> int:
    """``c = SHA-256(g ‖ y ‖ t ‖ session_nonce) mod q``.

    All group elements are encoded as fixed-width big-endian integers so the
    pre-image is unambiguous. ``session_nonce`` should be ≥ 128 bits of fresh
    randomness (or a tightly-scoped one-time value).
    """
    digest = hashlib.sha256()
    digest.update(_FS_TAG)
    digest.update(int_to_bytes(g, byte_length))
    digest.update(int_to_bytes(y, byte_length))
    digest.update(int_to_bytes(t, byte_length))
    digest.update(session_nonce)
    return bytes_to_int(digest.digest()) % q


@dataclass(frozen=True)
class FiatShamirProof:
    t: int
    c: int
    s: int
    session_nonce: bytes

    def to_dict(self, group: Optional[GroupParameters] = None) -> Dict[str, str]:
        return {
            "t": format(self.t, "x"),
            "c": format(self.c, "x"),
            "s": format(self.s, "x"),
            "session_nonce": self.session_nonce.hex(),
        }


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checks: Dict[str, bool]
    reason: str = ""

    def __bool__(self) -> bool:  # allows `if verifier.verify(...)`
        return self.ok


# ---------------------------------------------------------------------------
# Prover
# ---------------------------------------------------------------------------

class SchnorrProver:
    """Holds the private scalar and produces protocol messages.

    ``commitment()`` draws a fresh ephemeral nonce ``r`` from the CSPRNG on
    every call. Nonce reuse between two sessions with the same key leaks the
    private scalar (see THEORY.md §6.4 and ``simulation.mitm_lab``), so a
    fresh ``r`` per run is mandatory; the nonce is held only in memory and is
    discarded after ``response()`` is called.
    """

    def __init__(self, group: GroupParameters, private_scalar: int):
        if not (1 <= private_scalar < group.q):
            raise ValueError("private scalar must satisfy 1 <= x < q")
        self.group = group
        self.x = private_scalar
        self.y = pow(group.g, self.x, group.p)
        self._r: Optional[int] = None

    # -- interactive protocol -----------------------------------------------
    def commitment(self, r: Optional[int] = None) -> Tuple[int, int]:
        """Draw ``r`` (CSPRNG) and return ``(r, t = g^r mod p)``.

        Passing ``r`` explicitly exists only for the adversarial lab
        (nonce-reuse demonstration) and for tests.
        """
        if r is None:
            r = secrets.randbelow(self.group.q - 1) + 1
        if not (1 <= r < self.group.q):
            raise ValueError("nonce r must satisfy 1 <= r < q")
        self._r = r
        self._t = pow(self.group.g, r, self.group.p)
        return r, self._t

    def response(self, challenge: int) -> int:
        """Return ``s = (r + c·x) mod q`` for the stored commitment.

        Challenges are reduced modulo ``q`` internally; in the reference
        group ``q`` is 2047 bits so a 128-bit challenge never wraps, but
        reducing keeps the math correct for small experimentation groups.
        """
        if self._r is None:
            raise RuntimeError("commitment() must be called before response()")
        if not isinstance(challenge, int) or challenge < 0:
            raise ValueError("challenge must be a non-negative integer")
        s = (self._r + (challenge % self.group.q) * self.x) % self.group.q
        # Discard the ephemeral nonce and terminal commitment state.
        self._r = None
        self._t = None
        return s

    # -- Fiat-Shamir (non-interactive) ---------------------------------------
    def sign(self, session_nonce: Optional[bytes] = None) -> FiatShamirProof:
        """Produce a one-shot Fiat-Shamir proof (``t``, ``c``, ``s``)."""
        group = self.group
        q = group.q
        if session_nonce is None:
            session_nonce = secrets.token_bytes(32)
        _, t = self.commitment()
        c = fiat_shamir_challenge(self.group.g, self.y, t, session_nonce, q, self.group.byte_length)
        r = self._r
        assert r is not None
        s = (r + c * self.x) % q
        self._r = None
        self._t = None
        return FiatShamirProof(t=t, c=c, s=s, session_nonce=session_nonce)

    # -- helpers --------------------------------------------------------------
    def public_key(self) -> int:
        return self.y


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class SchnorrVerifier:
    """Stateless verification logic (state — TTL challenges — lives in the server)."""

    def __init__(self, group: GroupParameters):
        self.group = group

    def issue_challenge(self) -> int:
        """128-bit challenge drawn from the CSPRNG, uniform on [1, 2**128 - 1]."""
        return secrets.randbelow(MAX_CHALLENGE) + 1

    # -- building blocks -------------------------------------------------------
    def check_public_key(self, y: int) -> Dict[str, bool]:
        g = self.group
        return {
            "y_in_range": isinstance(y, int) and 1 < y < g.p,
            "y_not_order_2_element": y != g.p - 1,
            "y_in_order_q_subgroup": isinstance(y, int) and 0 < y < g.p and pow(y, g.q, g.p) == 1,
        }

    def check_commitment(self, t: int) -> Dict[str, bool]:
        g = self.group
        return {
            "t_in_range": isinstance(t, int) and 1 < t < g.p,
            "t_not_order_2_element": t != g.p - 1,
            "t_in_order_q_subgroup": isinstance(t, int) and 0 < t < g.p and pow(t, g.q, g.p) == 1,
        }

    def check_response_scalar(self, s: int) -> Dict[str, bool]:
        return {"s_in_scalar_range": isinstance(s, int) and 0 <= s < self.group.q}

    # -- core verification ------------------------------------------------------
    def verify_detailed(self, y: int, t: int, c: int, s: int) -> VerifyResult:
        g = self.group
        checks: Dict[str, bool] = {}
        checks.update(self.check_commitment(t))
        checks.update(self.check_public_key(y))
        checks.update(self.check_response_scalar(s))
        checks["challenge_in_scalar_range"] = isinstance(c, int) and c >= 0
        lhs = pow(g.g, s, g.p) if checks["s_in_scalar_range"] else -1
        rhs = (t * pow(y, c, g.p)) % g.p
        checks["schnorr_equation_g^s_eq_t·y^c"] = (
            lhs == rhs and all(checks.values())
        )
        ok = all(checks.values())
        reason = "" if ok else "failed: " + ", ".join(k for k, v in checks.items() if not v)
        return VerifyResult(ok=ok, checks=checks, reason=reason)

    def verify(self, y: int, t: int, c: int, s: int) -> bool:
        return self.verify_detailed(y, t, c, s).ok

    def verify_fiat_shamir(
        self,
        y: int,
        t: int,
        s: int,
        session_nonce: bytes,
        *,
        claimed_challenge: Optional[int] = None,
    ) -> VerifyResult:
        """Recompute ``c`` from the transcript and verify the equation."""
        g = self.group
        c = fiat_shamir_challenge(g.g, y, t, session_nonce, g.q, g.byte_length)
        result = self.verify_detailed(y, t, c, s)
        checks = dict(result.checks)
        if claimed_challenge is not None:
            checks["challenge_matches_transcript"] = hmac.compare_digest(
                int_to_bytes(claimed_challenge), int_to_bytes(c)
            )
        ok = result.ok and all(checks.values())
        reason = "" if ok else (result.reason or "challenge mismatch")
        return VerifyResult(ok=ok, checks=checks, reason=reason)


# ---------------------------------------------------------------------------
# Convenience: run one honest in-memory protocol execution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Transcript:
    t: int
    c: int
    s: int
    ok: bool


def run_honest_protocol(prover: SchnorrProver, verifier: SchnorrVerifier) -> Transcript:
    """Execute one full 3-pass exchange in memory (tests / simulations)."""
    _, t = prover.commitment()
    c = verifier.issue_challenge()
    s = prover.response(c)
    ok = verifier.verify(prover.y, t, c, s)
    return Transcript(t=t, c=c, s=s, ok=ok)


__all__ = [
    "CHALLENGE_BITS",
    "MAX_CHALLENGE",
    "FiatShamirProof",
    "KeyPair",
    "SchnorrProver",
    "SchnorrVerifier",
    "Transcript",
    "VerifyResult",
    "derive_private_scalar",
    "fiat_shamir_challenge",
    "generate_keypair",
    "hkdf_sha256",
    "is_valid_group_element",
    "keypair_from_passphrase",
    "parse_hex_int",
    "public_key_fingerprint",
    "run_honest_protocol",
]
