# Zero-Knowledge Proof Authentication — Schnorr Protocol

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-53%20passing-green.svg)](tests/)
[![Crypto](https://img.shields.io/badge/crypto-from%20first%20principles-orange.svg)](core/)
[![ZKP](https://img.shields.io/badge/ZK-Schnorr%20Identification-purple.svg)](THEORY.md)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](Dockerfile)

A production-grade, educational, mathematically transparent **zero-knowledge proof
authentication system** based on the **Schnorr identification protocol** — written in
pure Python on top of FastAPI, SQLite, `secrets` and `hashlib`. No black-box ZKP
libraries: the finite field, the group, the KDF chain, the protocol and the
adversarial lab are all implemented in the open, line by line, and cross-checked by
53 tests.

> The server stores **only your public key** `y = g^x mod p`. Your passphrase and the
> derived scalar `x` never leave your machine — not at registration, not at login, not
> ever. See [THEORY.md](THEORY.md) for the completeness / special-soundness /
> honest-verifier-zero-knowledge proofs.

## The 3-pass protocol at a glance

```
   Prover (Client, holds x)                     Verifier (Server, stores y = gˣ)
   ─────────────────────────                    ───────────────────────────────
   r ←$ [1, q−1]  (secrets CSPRNG)
   t = gʳ mod p
        │  ① commitment  t                            │
        │ ──────────────────────────────────────────► │  check: 1 < t < p, t^q ≡ 1
        │                                              │  c ←$ [1, 2¹²⁸−1]  (single-use, 30 s TTL)
        │  ② challenge  c                              │
        │ ◄────────────────────────────────────────── │
   s = (r + c·x) mod q
        │  ③ response  s                               │
        │ ──────────────────────────────────────────► │  check: gˢ ≟ t · yᶜ  (mod p)
        │                                              │  ✓ mint bearer session (hash-only storage)
        ▼                                              ▼
   x never crosses the wire — only (t, c, s)
```

Fiat-Shamir mode collapses the round trip into a single signed request
(`c = SHA-256(g‖y‖t‖session_nonce) mod q`), suitable for one-shot API-token signing.

## Features

| Pillar | What you get |
| --- | --- |
| **Cryptographic group engine** | RFC 3526 2048-bit MODP safe-prime preset (verified against the published constant), Miller-Rabin primality via CSPRNG bases, on-demand safe-prime generation for experimentation, quadratic-residue order-`q` subgroup validation |
| **Schnorr engine** | Prover & Verifier for interactive 3-pass identification + Fiat-Shamir non-interactive proofs; Argon2id / PBKDF2-HMAC-SHA256 → HKDF-SHA256 passphrase key derivation (manual RFC 5869); challenge ∈ `[1, 2^128−1]`; `s = (r + c·x) mod q` |
| **Verifier service** | FastAPI + SQLite; single-use 30 s challenges (atomic consume), subgroup checks on every element, sliding-window rate limiter, SHA-256-hashed session tokens, `/params` discovery, `/me` introspection |
| **Interactive prover CLI** | `rich`-rendered step-by-step telemetry — every payload printed, `x` never displayed; register / login / fiat-shamir / me / params |
| **Adversarial MITM lab** | Automated attacks: eavesdropping & replay, forgery-before-challenge (soundness), active commitment/response tampering, unregistered-identity probing — plus BSGS discrete-log on a toy group and the two-transcript nonce-reuse key recovery |
| **Rigor** | `THEORY.md` proofs, 53-test pytest suite, Docker & docker-compose |

## Quickstart

### 1. Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the verifier

```bash
uvicorn server.api:app --host 0.0.0.0 --port 8000
# or: python -m server.api
```

### 3. Register and log in (new terminal)

```bash
python -m client.cli register alice      # prompts for a passphrase (never transmitted)
python -m client.cli login alice         # 3-pass protocol, full telemetry trace
python -m client.cli fiat-shamir alice   # one-shot proof for API-token signing
```

### 4. Run the adversarial lab

```bash
python -m simulation.mitm_lab            # replay / forgery / tampering — all repelled
```

### 5. Run the tests

```bash
pytest                                   # 53 tests, ~11 s
```

### Docker

```bash
docker build -t schnorr-zkp-auth .
docker run --rm -p 8000:8000 -v schnorr-data:/data schnorr-zkp-auth
docker compose up -d                     # verifier on :8000, SQLite on a named volume
docker compose run --rm client login alice   # interactive CLI, attaches to stdin/tty
docker compose run --rm lab                  # the attack lab, containerized
```

## HTTP API

| Method & path | Body → Response | Notes |
| --- | --- | --- |
| `GET /healthz` | → `{status, group, group_fingerprint}` | liveness |
| `GET /params` | → `{name, bits, p, q, g, challenge_bits, …}` | group discovery (hex) |
| `POST /register` | `{username, public_key, kdf}` → `201 {username, public_key_fingerprint}` | stores `y` only; `409` on duplicate; subgroup-checked |
| `GET /users/{username}` | → `{public_key, kdf, created_at}` | public profile, nothing secret |
| `POST /auth/challenge` | `{username, commitment}` → `{challenge, challenge_ttl_seconds}` | 404 unknown user; 422 on `t ∉ QR_p`; issues 128-bit, single-use, 30 s TTL |
| `POST /auth/verify` | `{username, response}` → `{token, expires_in}` | atomic consume (anti-replay); 401 on any failure; 429 after 10 failures / 5 min |
| `POST /auth/fiat-shamir` | `{username, t, s, session_nonce, issued_at}` → `{token}` | stateless; `issued_at` within ±300 s |
| `GET /me` | `Authorization: Bearer <token>` → `{username, expires_at}` | 401 on invalid/expired token |
| `POST /logout` | `Authorization: Bearer <token>` → `{status: revoked}` | revokes the session |

## Repository layout

```
├── core/
│   ├── math_params.py     # safe-prime engine: RFC 3526 preset, Miller-Rabin, subgroup checks
│   └── schnorr.py         # Prover/Verifier (interactive + Fiat-Shamir), KDFs, RFC 5869 HKDF
├── server/
│   ├── database.py        # SQLite: user registry, TTL single-use challenges, hashed sessions
│   ├── api.py             # FastAPI Verifier (rate limiting, /params, /me, logout)
│   └── testing.py         # ephemeral live-server fixture used by lab & tests
├── client/
│   └── cli.py             # rich interactive Prover CLI
├── simulation/
│   └── mitm_lab.py        # replay / forgery / tampering / BSGS / nonce-reuse / HVZK simulator
├── tests/
│   └── test_schnorr.py    # 53 tests: math, soundness, extractor, HTTP end-to-end, lab
├── THEORY.md              # completeness, special soundness (extractor), HVZK (simulator), pitfalls
├── Dockerfile · docker-compose.yml · pyproject.toml · requirements.txt
```

## Security notes (read this)

* **Good:** only public keys are stored; the secret scalar is never transmitted, logged,
  or displayed; transcripts are unlinkable zero-knowledge views; challenges are
  single-use and TTL-bound; sessions are hashed at rest.
* **Not covered by ZKP magic:** Schnorr identification is not a password-authenticated
  key exchange — a stolen database enables *offline dictionary* attacks against weak
  passphrases (mitigated by Argon2id; for full PAKE guarantees use OPAQUE). See
  [THEORY.md §9](THEORY.md#9-what-this-system-is--and-is-not).
* **Nonce discipline is everything.** `r` is drawn fresh from `secrets` per commitment;
  reusing it leaks `x` entirely — the lab demonstrates the recovery.
* Run behind **TLS** in production for metadata hygiene, and set
  `SCHNORR_CORS_ORIGINS` explicitly instead of `*`.
* `SCHNORR_GROUP` defaults to `rfc3526-2048`; `generated:<bits>` explores fresh safe
  primes (e.g. `512`) — never below 256 bits outside a lab.

## Disclaimer

Educational yet production-hardened reference implementation. It has not undergone a
third-party cryptographic audit. For regulated environments, have the design reviewed
by a qualified cryptographer and prefer audited PAKE protocols (e.g., OPAQUE/RFC 9497).

## License

MIT — see [LICENSE](LICENSE).
