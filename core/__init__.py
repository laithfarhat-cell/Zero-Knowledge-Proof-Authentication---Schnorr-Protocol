"""
core
====

Public-key cryptographic primitives for the Schnorr zero-knowledge
authentication system. Everything here is implemented from first principles
on Python's arbitrary-precision integers and the ``secrets`` CSPRNG.

* :mod:`core.math_params` — safe-prime finite-field group engine (RFC 3526
  presets, Miller-Rabin, subgroup validation).
* :mod:`core.schnorr` — Schnorr identification protocol (prover / verifier),
  passphrase key derivation, and the Fiat-Shamir non-interactive transform.
"""

from core import math_params, schnorr  # noqa: F401

__all__ = ["math_params", "schnorr"]
__version__ = "1.0.0"
