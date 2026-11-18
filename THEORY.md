# THEORY — The Mathematics of Schnorr Zero-Knowledge Identification

This document is the rigorous companion to the code. It derives, from first
principles, why the implementation in `core/` lets a client prove **knowledge
of a secret** to a server while revealing **nothing about that secret**.

---

## 1. Notation and setting

| Symbol        | Meaning                                                        |
| ------------- | -------------------------------------------------------------- |
| `p`           | a safe prime, `p = 2q + 1`, both prime                         |
| `q`           | prime order of the Schnorr subgroup, `q = (p − 1)/2`           |
| `g`           | a generator of the unique subgroup of `Z_p*` of order `q`       |
| `x`           | the prover's private scalar, `x ∈ [1, q − 1]`                  |
| `y`           | the public key, `y = g^x mod p`                                |
| `r`           | the prover's ephemeral nonce, `r ∈ [1, q − 1]` (per session)   |
| `t`           | the commitment, `t = g^r mod p`                                |
| `c`           | the verifier's challenge, `c ∈ [1, 2^128 − 1]`                 |
| `s`           | the prover's response, `s = (r + c·x) mod q`                   |
| `id`, `nonce` | context strings bound into the Fiat-Shamir hash                |

All exponent arithmetic on scalars is modulo `q`; all power residues are
modulo `p`. Python's arbitrary-precision integers make the arithmetic exact;
`secrets` is the only source of randomness.

### 1.1 Safe primes and the order-q subgroup

`Z_p*` has `p − 1 = 2q` elements. The map `z ↦ z² mod p` is a homomorphism
into its kernel's orthogonal complement; concretely, the set of quadratic
residues

```
QR_p = { u ∈ Z_p* : u^q ≡ 1 (mod p) }
```

is a subgroup of prime order `q` (it is exactly the image of the squaring map,
has `(p−1)/2 = q` elements, and any non-identity element generates it).
Working in `QR_p` is deliberate:

* every non-identity element has the *same* prime order `q` — there is no
  small subgroup structure for an attacker to confine the protocol to;
* subgroup membership is a single modular exponentiation (`u^q ≟ 1`).

RFC 3526 ("More MODP Diffie-Hellman groups for IKE") defines, in its Section 3,
the 2048-bit prime

```
p = 2^2048 − 2^1984 − 1 + 2^64 · (⌊2^1918·π⌋ + 124476)
```

and our preset uses exactly that constant (verified at test time against its
decimal/hex identity and re-proven probable-prime, and `g = 4`, which has exact
order `q` since it is a square of `2 ∉ {1, p−1}`... see `core/math_params.py`).

---

## 2. The protocol (interactive, 3-pass)

**Setup.** Prover and verifier both know `(p, q, g)`. The prover holds `x`;
the verifier stores `(username ↦ y)` and nothing else.

```
Prover (x)                                            Verifier (y = g^x)
─────────                                             ──────────────────
r ←$ [1, q−1]            ──(1) t = g^r mod p ──►
                                                     c ←$ [1, 2^128 − 1]
                          ◄──(2) c ───────────────
s = r + c·x mod q        ──(3) s ──────────────►     check g^s ≟ t · y^c (mod p)
```

Accept iff the equation holds **and** all elements are validated (§6).

---

## 3. Completeness

*Claim.* If the prover knows `x` and follows the protocol, the verifier
always accepts.

*Proof.*

```
g^s ≡ g^(r + c·x) ≡ g^r · (g^x)^c ≡ t · y^c  (mod p).
```

The equation holds exactly, not merely with high probability. ∎

This is a *perfect* correctness property: an honest run never fails, so any
failure in production is evidence of tampering, loss, or corruption — never of
"bad luck".

---

## 4. Special soundness (the knowledge extractor)

*Intuition.* If someone can answer **two** different challenges about the
**same** commitment, they must know `x` — and we can compute it.

**Theorem (special soundness).** Given two accepting transcripts
`(t, c₁, s₁)` and `(t, c₂, s₂)` with `c₁ ≠ c₂`, one can extract `x` in
polynomial time.

*Construction (knowledge extractor).* Acceptingness gives

```
g^s₁ ≡ t · y^c₁   (mod p)
g^s₂ ≡ t · y^c₂   (mod p)
```

Divide the equations (invert the second; multiplication by constants commutes):

```
g^(s₁−s₂) ≡ y^(c₁−c₂) ≡ g^(x·(c₁−c₂))   (mod p)
```

Since `g` has order `q`, exponents match modulo `q`:

```
s₁ − s₂ ≡ x·(c₁ − c₂)   (mod q)
```

`c₁ ≠ c₂` and both lie in `[1, 2^128 − 1] ⊂ [0, q)` (because `q > 2^2046`),
so `c₁ − c₂ ≢ 0 (mod q)` is invertible:

```
                 x ≡ (s₁ − s₂) · (c₁ − c₂)⁻¹   (mod q)
```

Two re-wound interactions — one honest commitment, two forked challenges —
yield the witness. Hence any prover that succeeds with probability better
than the guessing bound (below) *knows* `x`; it cannot merely be a lucky
guesser, because a guessed `c` cannot be adapted retroactively to produce a
matching `s`.

**Soundness error.** Fixing `t`, a cheating prover's success probability is
the probability it can name `s` before seeing `c`. For one attempt this is at
most `1/q`; with a 128-bit challenge issued per session and the challenge
space `C = {1,…,2^128−1}`, the practical bound is

```
ε_sound ≤ 1/|C| ≈ 2^−128        (plus a negligible q⁻¹ term)
```

and, because challenges are single-use and TTL-bound (§6.2), this bound holds
*per recorded session* — offline brute force of the transcript yields nothing.

The test-suite encodes the extractor directly
(`tests/test_schnorr.py::TestSpecialSoundnessExtractor`) and so does the lab's
nonce-reuse demonstration (§6.1).

---

## 5. Honest-verifier zero knowledge

*Intuition.* Anything the verifier sees, it could have fabricated itself.

**Definition (HVZK simulator).** A simulator `S(y)` with access only to the
public key produces transcripts that are (a) accepting and (b) identically
distributed to real transcripts.

*Construction.* Choose `c ←$ [1, 2^128 − 1]` and `s ←$ [0, q−1]` uniformly.
Set

```
t := g^s · y^(−c)   (mod p)
```

Then the triple `(t, c, s)` passes the verification equation by construction:

```
g^s = y^c · t  ⟹  g^s = t · y^c  (mod p).                      ✓
```

*Distribution.* In the real protocol `r` is uniform in `[1, q−1]`, so `t =
g^r` is uniform in `QR_p \ {1}`; `c` is uniform in `[1, 2^128−1]`; and `s` is
a deterministic bijection of `r` given `(c, x)`, hence uniform too. In the
simulation, `(c, s)` are uniform and independent, and `t = g^s y^{−c}` is a
bijective image of `s` for fixed `c`, hence uniform over the same set. The
joint distributions coincide exactly. ∎

**Consequence.** A transcript leaks zero bits about `x`: it can be generated
by anyone holding only `(p, q, g, y)`. Moreover, transcripts from *two*
sessions reuse nothing — fresh `r` ⇒ independent `(t, s)`.

The HVZK simulator is runnable: `python -m simulation.mitm_lab` →
"HVZK Transcript Simulator" — and it produces accepting transcripts 3/3 times
without ever seeing a secret.

---

## 6. Requirements & pitfalls (and how the code enforces them)

### 6.1 Fresh nonce per commitment — never reuse `r`

If `r` is reused for two sessions with the same key, the extractor of §4
recovers `x` *immediately*:

```
s₁ = r + c₁·x
s₂ = r + c₂·x
─────────────
x = (s₁ − s₂)/(c₁ − c₂)   (mod q)
```

`simulation/mitm_lab.py` demonstrates this recovery end-to-end. Defense in
code: `SchnorrProver.commitment()` draws `r = secrets.randbelow(q−1)+1` on
every call, holds it only in memory, and destroys it in `response()`.

### 6.2 Single-use, TTL-bound challenges

The server stores at most one pending challenge per username with a strict
**30-second** TTL. `/auth/verify` consumes the row atomically
(`SELECT … ; DELETE …` in one transaction, `server/database.py`) regardless
of outcome. A replayed `(t, c, s)` therefore finds nothing to consume, and a
stale response is useless against a fresh challenge. Expiry is enforced both
in SQL (`expires_at`) and at read time (defence in depth).

### 6.3 The 128-bit challenge bound

Interactive challenges are uniform in `[1, 2^128 − 1]` — large enough that
guessing is hopeless, small enough to transmit and compare cheaply, and
independent of `q`. (For Fiat-Shamir, `c` is instead reduced mod `q`; the
transcript hash binds it to the full context.)

### 6.4 Subgroup membership & small-subgroup confinement

Accepting `t` (or `y`) outside `QR_p` lets an attacker force the protocol
into a small subgroup and leak `x` bit-by-bit (Lim–Lee style). We require,
for every group element entering verification:

```
1 < e < p        (not identity, not 0)
e ≠ p − 1        (not the order-2 element)
e^q ≡ 1 (mod p)  (membership in the order-q subgroup)
```

`core/math_params.py::is_valid_group_element` implements exactly this, and
the API applies it at registration (public keys) and at `/auth/challenge`
(commitments).

### 6.5 Key derivation transparency

`x = HKDF-SHA256(Argon2id(passphrase, salt=SHA256(tag‖username)), …) mod q`.

* Argon2id (RFC 9106) supplies memory-hard work factor against offline
  guessing of weak passphrases; PBKDF2-HMAC-SHA256 (600 000 iterations,
  OWASP-recommended floor) is available as `kdf="pbkdf2"`.
* HKDF (RFC 5869, implemented manually over `hmac` in `core/schnorr.py`)
  domain-separates the Schnorr scalar from anything else that might ever be
  derived from the same passphrase.
* The modulo-q mapping consumes `⌈(2047+128)/8⌉ = 272` bytes; the induced
  bias is ≤ 2⁻¹²⁸ — cryptographically negligible.
* Salts are a *public* function of the username. This is intentional: the
  passphrase never leaves the client, and the salt's job is key
  diversification, not storage. (If you need revocation or rotation, store
  the salt server-side and fetch it before derivation — a straightforward
  extension.)
* `x = 0` is remapped deterministically to `1` (probability ≈ 2⁻²⁰⁴⁷); keys
  are never the identity.

### 6.6 Nonce cancellation is not authentication

A transcript valid today proves knowledge of `x` *at verification time*;
it does not authenticate future requests. Sessions are minted as random
256-bit bearer tokens whose **SHA-256 hashes** (not the tokens) are stored,
with a 1-hour TTL — matching the threat model where transcripts may be
captured.

---

## 7. Fiat-Shamir: from identification to signatures

Replace the verifier's coin flip with a hash of the conversation so far
(Micali–Fiat–Shamir heuristic, random-oracle model):

```
c = SHA-256( "SCHNORR-FS-v1" ‖ I2OSP(g, L) ‖ I2OSP(y, L) ‖ I2OSP(t, L) ‖ session_nonce )  mod q
```

with `L = ⌈bits(p)/8⌉ = 256` — fixed-width encodings make the pre-image
unambiguous. The signer then answers `s = r + c·x mod q`. Verification
recomputes `c` and checks the same equation. A forged proof requires either
an `x` or finding a hash collision with a usable `t` — both infeasible.

Limits (be honest about them):

* Fiat-Shamir proofs are **replayable** unless bound to something fresh. Our
  server additionally requires `issued_at` within ±300 s of server time;
  callers needing hard single-use semantics should use the interactive mode.
* The transform is proven sound in the *random oracle model*; SHA-256 is
  treated as such. This is standard and pragmatic, not dogmatic.

---

## 8. Concrete parameter sizes and the discrete-log wall

The best known generic attack on `log_g h` in a group of order `q` is
baby-step giant-step / Pollard-rho, at `O(√q)` group operations:

| Group                                | `√q` (approx.) | Consequence                          |
| ------------------------------------ | --------------- | ------------------------------------ |
| 40-bit toy (used by `mitm_lab`)      | `2^19.5`        | recovered in milliseconds            |
| 256-bit                              | `2^127.5`       | infeasible today                     |
| **2048-bit RFC 3526 (this project)** | **`2^1023.5`**  | **≈ 10^308× the toy cost; hopeless** |

Targeted finite-field algorithms (index calculus, NFS) do better than generic
bounds for `Z_p*`, which is precisely why Schnorr operates in the **order-q
subgroup** chosen so that known attacks stay infeasible at 2048 bits.

---

## 9. What this system is — and is not

**Is:** a zero-knowledge *identification* protocol with a server that stores
only `y`. An attacker who dumps the database learns public keys, not secrets;
passphrases never cross the network, even hashed.

**Is not** a password-authenticated key exchange (PAKE) like OPAQUE: a
verifier holding `y` *can* mount an offline dictionary attack on weak
passphrases against a recorded registration. Mitigations here: memory-hard
Argon2id derivation, and the `y` values are verifier-independent only if you
issued them independently. If you need PAKE security, bolt OPAQUE on instead —
the architecture here (params endpoint, registration registry, session
minting) accommodates it cleanly.

**Operational notes:** run behind TLS in production (defense in depth — ZKP
does not need encryption for secrecy of `x`, but TLS protects metadata and
padding oracles in surrounding systems); rotate session tokens; monitor
repeated `401`s (the built-in sliding-window limiter slows online guessing
to a crawl); log fingerprints, never scalars.

---

## 10. References

* C. P. Schnorr. *Efficient signature generation for smart cards.* Journal of
  Cryptology, 1991. (Identification scheme, Thm. — the protocol above.)
* A. Fiat, A. Shamir. *How to prove yourself.* CRYPTO '86.
* S. Micali. *CS proofs.* FOCS '94. (Fiat-Shamir transform, random oracles.)
* RFC 3526 — More MODP Diffie-Hellman groups for IKE (2048-bit group, §3).
* RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
* RFC 9106 — Argon2 memory-hard function for password hashing and KDF.
* Lim, C. H., Lee, P. J. *A key recovery attack on discrete log-based schemes
  using a prime order subgroup.* CRYPTO '97. (Why §6.4 membership checks.)
* Bellare, M., Rogaway, P. *Random oracles are practical.* CCS '93.
