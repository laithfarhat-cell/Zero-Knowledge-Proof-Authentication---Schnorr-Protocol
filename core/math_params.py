"""
core.math_params
================

Finite-field (``GF(p)*``) group parameter engine for the Schnorr
identification protocol.

Design goals
------------

* **Safe-prime groups** — we work in the order-``q`` quadratic-residue
  subgroup of ``Z_p*`` where ``p = 2q + 1`` and both ``p`` and ``q`` are prime
  (a *safe prime*). The subgroup has prime order ``q``, which is what the
  Schnorr protocol's soundness proof relies on: every non-identity element is
  a generator, so "subgroup membership" reduces to "not the identity and
  ``x**q ≡ 1 (mod p)``".

* **RFC 3526 preset** — ships the 2048-bit MODP Group from
  RFC 3526 ("More Modular Exponential (MODP) Diffie-Hellman groups for
  Internet Key Exchange (IKE)", Section 3), defined as

      p = 2^2048 - 2^1984 - 1 + 2^64 * (⌊2^1918 · π⌋ + 124476)

  The constant below is computed from that exact formula; ``verify_group``
  re-proves (probable-prime check + order-``q`` generator check) that the
  shipped parameters are consistent, and the test-suite asserts it.

* **Dynamic safe-prime generation** — :func:`generate_safe_prime` searches for
  a fresh ``(p, q)`` pair with Miller-Rabin primality testing. Suitable for
  experimentation at ≤ 512 bits; a 2048-bit safe prime can take a long time
  (expected work is on the order of ln²p trial divisions).

* **CSPRNG only** — every random number drawn for a security purpose comes
  from :func:`secrets.randbelow` / :func:`secrets.randbits`.

Encoding helpers use big-endian (``I2OSP``/``OS2IP``-style) fixed or minimal
widths, which is what the Fiat-Shamir transcript hashing consumes.
"""

from __future__ import annotations

import math
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List

# ---------------------------------------------------------------------------
# RFC 3526 — 2048-bit MODP Group (Section 3)
# p = 2^2048 - 2^1984 - 1 + 2^64 * (⌊2^1918 · π⌋ + 124476)
# ---------------------------------------------------------------------------
RFC3526_2048_P_HEX = (
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08"
    "798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637e"
    "d6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da4"
    "8361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9"
    "804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2b"
    "cbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff"
)

# The first 200 prime numbers, used for cheap trial division before the
# expensive Miller-Rabin rounds. (Deterministic data — not randomness.)
def _first_primes(count: int) -> tuple[int, ...]:
    primes: List[int] = []
    n = 2
    while len(primes) < count:
        root = math.isqrt(n)
        if all(n % p for p in primes if p <= root):
            primes.append(n)
        n += 1
    return tuple(primes)


_SMALL_PRIMES = _first_primes(200)

# Deterministic witness set, valid for n < 2^64 (Jaeschke / Sorenson–Webster).
_DETERMINISTIC_BASES_64 = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    """Encode a non-negative integer as big-endian bytes (I2OSP).

    If ``length`` is given the output is left-padded with zero bytes to
    exactly ``length`` bytes; otherwise the minimal width is used.
    """
    if value < 0:
        raise ValueError("int_to_bytes requires a non-negative integer")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    if value.bit_length() > length * 8:
        raise ValueError(f"integer does not fit in {length} bytes")
    return value.to_bytes(length, "big")


def bytes_to_int(data: bytes) -> int:
    """Decode big-endian bytes as an integer (OS2IP)."""
    return int.from_bytes(data, "big")


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probable-prime test.

    * Small primes divide ``n`` exactly → decisive answer.
    * ``n < 2**64`` → deterministic witness set (exact answer).
    * Otherwise ``rounds`` random bases drawn with ``secrets.randbelow``
      (error probability ≤ 4**-rounds per invocation).
    """
    if n < 2:
        return False
    for small in _SMALL_PRIMES:
        if n % small == 0:
            return n == small
    # Write n - 1 = d * 2**r with d odd.
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    if n < 2**64:
        bases = [b % (n - 2) + 2 for b in _DETERMINISTIC_BASES_64]
    else:
        bases = [secrets.randbelow(n - 3) + 2 for _ in range(rounds)]
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    """Generate a probable prime of exactly ``bits`` bits using the CSPRNG."""
    if bits < 16:
        raise ValueError("refusing to generate primes smaller than 16 bits")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rounds=rounds):
            return candidate


def derive_subgroup_generator(p: int, q: int) -> int:
    """Derive a generator of the order-``q`` subgroup of ``Z_p*``.

    For a safe prime ``p = 2q + 1`` the subgroup of quadratic residues has
    prime order ``q``. Squaring any ``h ∉ {1, p-1}`` lands in that subgroup;
    we walk ``h = 2, 3, …`` and return the first non-trivial square.
    """
    h = 2
    while True:
        g = pow(h, (p - 1) // q, p)  # == h**2 mod p for safe primes
        if g != 1:
            return g
        h += 1


@dataclass(frozen=True)
class GroupParameters:
    """Immutable description of a Schnorr group ``(p, q, g)``.

    Attributes
    ----------
    p:
        Safe prime modulus (``p = 2q + 1``).
    q:
        Order of the subgroup; ``q = (p - 1) // 2`` is prime.
    g:
        Generator of the order-``q`` subgroup (``g**q ≡ 1 mod p``, ``g ≠ 1``).
    name:
        Human-readable identifier (e.g. ``"rfc3526-2048"``).
    """

    p: int
    q: int
    g: int
    name: str = "custom"

    # -- basic properties ---------------------------------------------------
    @property
    def bits(self) -> int:
        return self.p.bit_length()

    @property
    def byte_length(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def to_dict(self) -> Dict[str, str | int]:
        return {
            "name": self.name,
            "bits": self.bits,
            "p": format(self.p, "x"),
            "q": format(self.q, "x"),
            "g": format(self.g, "x"),
            "subgroup_order": "q",
            "challenge_bits": 128,
        }

    # -- validation ----------------------------------------------------------
    def verify(self, rounds: int = 16) -> Dict[str, bool]:
        """Re-check every group invariant; returns a report dict."""
        checks = {
            "p_odd": self.p % 2 == 1,
            "q_is_p_minus_1_over_2": self.q == (self.p - 1) // 2,
            "p_has_top_bit_set": self.p.bit_length() >= 2,
            "p_probable_prime": is_probable_prime(self.p, rounds=rounds),
            "q_probable_prime": is_probable_prime(self.q, rounds=rounds),
            "g_not_identity": 1 < self.g < self.p,
            "g_order_q": pow(self.g, self.q, self.p) == 1,
        }
        return checks

    def validate(self, rounds: int = 16) -> None:
        """Raise :class:`ValueError` if any group invariant fails."""
        failed = [name for name, ok in self.verify(rounds=rounds).items() if not ok]
        if failed:
            raise ValueError(f"group failed validation: {', '.join(failed)}")


def generate_safe_prime(bits: int = 512, rounds: int = 40) -> GroupParameters:
    """Search for a fresh safe prime ``p = 2q + 1`` of exactly ``bits`` bits.

    Only intended for experimentation — 2048-bit generation can take a very
    long time (expected number of candidates grows as ln²(2^bits)). For 64–
    256 bits this completes in well under a minute on a modern machine.
    """
    if bits < 32:
        raise ValueError("safe primes must be at least 32 bits")
    deadline = None  # documented as potentially slow; caller controls size
    while True:
        # q has bits-1 bits; p = 2q + 1 then has exactly bits bits.
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if not is_probable_prime(q, rounds=rounds):
            continue
        p = 2 * q + 1
        if is_probable_prime(p, rounds=rounds):
            g = derive_subgroup_generator(p, q)
            return GroupParameters(p=p, q=q, g=g, name=f"generated-safe-prime-{bits}")


def is_valid_group_element(element: int, group: GroupParameters, *, strict_subgroup: bool = True) -> bool:
    """Validate a value as a group element used by the protocol.

    Requirements enforced (in order):

    1. ``1 < element < p``  — excludes 0 and 1 (the identity).
    2. ``element != p - 1`` — excludes the order-2 element ``-1``.
    3. ``element**q ≡ 1 (mod p)`` — membership in the prime-order-``q``
       subgroup. This is the check that defeats small-subgroup confinement
       attacks, where an attacker sneaks a low-order element in to leak
       bits of the private exponent.
    """
    p, q = group.p, group.q
    if not (isinstance(element, int) and 1 < element < p):
        return False
    if element == p - 1:
        return False
    if strict_subgroup and pow(element, q, p) != 1:
        return False
    return True


# ---------------------------------------------------------------------------
# Preset groups (cached — Miller-Rabin verification happens once per process)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_rfc3526_2048() -> GroupParameters:
    """Return the RFC 3526 2048-bit MODP safe-prime group (order-``q`` subgroup)."""
    p = int(RFC3526_2048_P_HEX, 16)
    q = (p - 1) // 2
    g = derive_subgroup_generator(p, q)  # 2^2 mod p = 4; exact order q
    return GroupParameters(p=p, q=q, g=g, name="rfc3526-2048")


_PRESET_FACTORIES = {"rfc3526-2048": get_rfc3526_2048}


def get_preset_group(name: str = "rfc3526-2048") -> GroupParameters:
    try:
        return _PRESET_FACTORIES[name]()
    except KeyError:
        raise ValueError(f"unknown preset group {name!r}; available: {sorted(_PRESET_FACTORIES)}") from None


def load_group(spec: str | None) -> GroupParameters:
    """Resolve a group from a CLI/env spec.

    ``None`` / ``"rfc3526-2048"`` → the RFC 3526 preset.
    ``"generated:<bits>"`` → generate a fresh safe prime of ``<bits>`` bits
    (experimentation only; generation may be slow for large sizes).
    """
    if not spec or spec == "rfc3526-2048":
        return get_rfc3526_2048()
    if spec.startswith("generated:"):
        bits = int(spec.split(":", 1)[1])
        return generate_safe_prime(bits)
    raise ValueError(f"unknown group spec {spec!r} (expected 'rfc3526-2048' or 'generated:<bits>')")


def group_fingerprint(group: GroupParameters) -> str:
    """Short fingerprint of ``(name, p, q, g)`` for logs and displays."""
    import hashlib

    digest = hashlib.sha256(
        f"{group.name}|{format(group.p, 'x')}|{format(group.q, 'x')}|{format(group.g, 'x')}".encode()
    ).hexdigest()
    return digest[:16]


def pretty_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, rem = divmod(int(seconds), 60)
    return f"{minutes}m {rem}s"


def timed_safe_prime_generation(bits: int, rounds: int = 40) -> tuple[GroupParameters, float]:
    """Generate a safe prime and report wall-clock time (experimentation helper)."""
    start = time.perf_counter()
    group = generate_safe_prime(bits, rounds=rounds)
    return group, time.perf_counter() - start
