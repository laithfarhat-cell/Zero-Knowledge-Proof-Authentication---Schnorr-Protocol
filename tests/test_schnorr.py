"""
tests.test_schnorr
==================

Comprehensive pytest suite for the Schnorr ZKP authentication system.

Coverage map
------------

* group parameters        — RFC 3526 preset invariants, Miller-Rabin, safe-prime generation
* subgroup validation     — identity, order-2 element, non-residues, out-of-range values
* key derivation          — determinism, domain separation, scalar ranges, both KDFs
* honest protocol         — completeness (accept), end-to-end in memory
* soundness               — tampered s / t / y / challenge, out-of-range scalars
* special soundness       — extractor: x = (s₁-s₂)(c₁-c₂)⁻¹ from two rewinding transcripts
* Fiat-Shamir             — roundtrip, wrong nonce, wrong message, challenge binding
* server API              — register / challenge / verify / replay / expiry / rate limit / sessions
* adversarial lab         — every attack scenario must be repelled
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid

import pytest

from core.math_params import (
    bytes_to_int,
    generate_safe_prime,
    get_rfc3526_2048,
    int_to_bytes,
    is_probable_prime,
    is_valid_group_element,
    load_group,
)
from core.schnorr import (
    SchnorrProver,
    SchnorrVerifier,
    derive_private_scalar,
    fiat_shamir_challenge,
    hkdf_sha256,
    keypair_from_passphrase,
    run_honest_protocol,
)
from simulation.mitm_lab import run_lab

GROUP = get_rfc3526_2048()


def _uid(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _register(api_client, username: str, public_key: int, kdf: str = "argon2id"):
    return api_client.post("/register", json={"username": username, "public_key": format(public_key, "x"), "kdf": kdf})


def _full_login(api_client, username: str, prover: SchnorrProver):
    _, t = prover.commitment()
    resp = api_client.post("/auth/challenge", json={"username": username, "commitment": format(t, "x")})
    assert resp.status_code == 200, resp.text
    c = int(resp.json()["challenge"], 16)
    s = prover.response(c)
    final = api_client.post("/auth/verify", json={"username": username, "response": format(s, "x")})
    return final


# ===========================================================================
# Group parameters & Miller-Rabin
# ===========================================================================

class TestGroupParameters:
    def test_preset_group_matches_rfc3526_hex(self):
        p = GROUP.p
        # The 2048-bit MODP Group of RFC 3526 §3 is the single published constant;
        # assert identity (and implicitly p ≡ 7 mod 8, top/bottom bits set).
        assert p.bit_length() == 2048
        assert p == int(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08"
            "798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637e"
            "d6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da4"
            "8361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9"
            "804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2b"
            "cbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
            16,
        )

    def test_preset_group_invariants(self):
        report = GROUP.verify(rounds=8)
        assert all(report.values()), report
        assert GROUP.q == (GROUP.p - 1) // 2
        assert pow(GROUP.g, GROUP.q, GROUP.p) == 1
        assert GROUP.g != 1

    def test_miller_rabin_idents_primes_and_composites(self):
        assert is_probable_prime(2, rounds=4)
        assert is_probable_prime(7919, rounds=4)          # 1000th prime
        assert is_probable_prime(2**127 - 1, rounds=4)    # Mersenne prime
        for carmichael in (561, 1105, 1729, 2465, 2821):
            assert not is_probable_prime(carmichael, rounds=4), carmichael
        assert not is_probable_prime(2**128 + 1, rounds=4)

    def test_generate_safe_prime_small(self):
        toy = generate_safe_prime(64, rounds=16)
        assert toy.p == 2 * toy.q + 1
        assert toy.p.bit_length() == 64
        assert pow(toy.g, toy.q, toy.p) == 1
        assert toy.g != 1

    def test_generate_safe_prime_rejects_tiny_params(self):
        with pytest.raises(ValueError):
            generate_safe_prime(16)

    def test_load_group_specs(self):
        assert load_group("rfc3526-2048").name == "rfc3526-2048"
        with pytest.raises(ValueError):
            load_group("bogus-spec")

    def test_int_bytes_roundtrip(self):
        assert bytes_to_int(int_to_bytes(0)) == 0
        assert bytes_to_int(int_to_bytes(123456789)) == 123456789
        assert int_to_bytes(255, 4) == b"\x00\x00\x00\xff"
        with pytest.raises(ValueError):
            int_to_bytes(-1)
        with pytest.raises(ValueError):
            int_to_bytes(256, 1)


class TestSubgroupValidation:
    def test_identity_rejected(self):
        assert not is_valid_group_element(1, GROUP)

    def test_order_2_element_rejected(self):
        assert not is_valid_group_element(GROUP.p - 1, GROUP)

    def test_out_of_range_rejected(self):
        assert not is_valid_group_element(0, GROUP)
        assert not is_valid_group_element(GROUP.p, GROUP)
        assert not is_valid_group_element(GROUP.p + 5, GROUP)

    def test_non_residue_rejected(self):
        # Quadratic non-residue: a ∉ subgroup (a^q ≡ -1). p ≡ 7 mod 8 ⇒ 2 is a QR, so scan.
        candidate = 3
        while pow(candidate, GROUP.q, GROUP.p) == 1:
            candidate += 2
        assert not is_valid_group_element(candidate, GROUP)

    def test_generator_and_subgroup_members_accepted(self):
        assert is_valid_group_element(GROUP.g, GROUP)
        assert is_valid_group_element(pow(GROUP.g, 12345, GROUP.p), GROUP)


# ===========================================================================
# Key derivation
# ===========================================================================

class TestKeyDerivation:
    def test_passphrase_derivation_is_deterministic(self):
        x1 = derive_private_scalar("open sesame", "alice", GROUP)
        x2 = derive_private_scalar("open sesame", "alice", GROUP)
        assert x1 == x2

    def test_passphrase_binding_to_username(self):
        x_alice = derive_private_scalar("open sesame", "alice", GROUP)
        x_bob = derive_private_scalar("open sesame", "bob", GROUP)
        assert x_alice != x_bob

    def test_different_passphrases_different_keys(self):
        x1 = derive_private_scalar("one", "alice", GROUP)
        x2 = derive_private_scalar("two", "alice", GROUP)
        assert x1 != x2

    def test_scalar_in_valid_range(self):
        for i in range(4):
            x = derive_private_scalar(f"pass-{i}", "alice", GROUP)
            assert 1 <= x < GROUP.q

    def test_pbkdf2_kdf_supported(self):
        x1 = derive_private_scalar("open sesame", "alice", GROUP, kdf="pbkdf2")
        x2 = derive_private_scalar("open sesame", "alice", GROUP, kdf="pbkdf2")
        assert x1 == x2 and 1 <= x1 < GROUP.q

    def test_hkdf_rfc5869_shape(self):
        okm = hkdf_sha256(b"key material", b"salt", b"info", 42)
        assert len(okm) == 42
        assert hkdf_sha256(b"key material", b"salt", b"info", 42) == okm
        assert hkdf_sha256(b"key material", b"other salt", b"info", 42) != okm

    def test_keypair_from_passphrase_public_key(self):
        kp = keypair_from_passphrase("open sesame", "alice", GROUP)
        assert kp.public_key == pow(GROUP.g, kp.private_scalar, GROUP.p)


# ===========================================================================
# Honest protocol — completeness
# ===========================================================================

class TestHonestProtocol:
    def test_honest_roundtrip_accepts(self):
        prover = SchnorrProver(GROUP, 0xC0FFEE % (GROUP.q - 1) + 1)
        verifier = SchnorrVerifier(GROUP)
        for _ in range(3):
            assert run_honest_protocol(prover, verifier).ok

    def test_run_honest_protocol_transcript_fields(self):
        prover = SchnorrProver(GROUP, 12345)
        transcript = run_honest_protocol(prover, SchnorrVerifier(GROUP))
        assert 1 < transcript.t < GROUP.p
        assert 1 <= transcript.c <= 2**128 - 1
        assert 0 <= transcript.s < GROUP.q


# ===========================================================================
# Soundness — tampering must fail
# ===========================================================================

class TestSoundness:
    def setup_method(self):
        self.verifier = SchnorrVerifier(GROUP)
        self.prover = SchnorrProver(GROUP, 424242)
        _, self.t = self.prover.commitment()
        self.c = self.verifier.issue_challenge()
        self.s = self.prover.response(self.c)

    def test_valid_acceptance(self):
        assert self.verifier.verify(self.prover.y, self.t, self.c, self.s)

    def test_tampered_response_rejected(self):
        assert not self.verifier.verify(self.prover.y, self.t, self.c, self.s + 1)

    def test_tampered_commitment_rejected(self):
        forged_t = (self.t * GROUP.g) % GROUP.p
        assert not self.verifier.verify(self.prover.y, forged_t, self.c, self.s)

    def test_tampered_challenge_rejected(self):
        assert not self.verifier.verify(self.prover.y, self.t, self.c + 1, self.s)

    def test_tampered_public_key_rejected(self):
        forged_y = pow(GROUP.g, 777, GROUP.p)
        assert not self.verifier.verify(forged_y, self.t, self.c, self.s)

    def test_identity_commitment_rejected(self):
        assert not self.verifier.verify(self.prover.y, 1, self.c, 0)

    def test_order_2_commitment_rejected(self):
        assert not self.verifier.verify(self.prover.y, GROUP.p - 1, self.c, 0)

    def test_identity_public_key_rejected(self):
        assert not self.verifier.verify(1, self.t, self.c, self.s)

    def test_scalar_out_of_range_rejected(self):
        assert not self.verifier.verify(self.prover.y, self.t, self.c, GROUP.q)
        assert not self.verifier.verify(self.prover.y, self.t, self.c, -1)

    def test_detailed_report_names_failed_checks(self):
        report = self.verifier.verify_detailed(self.prover.y, 1, self.c, self.s)
        assert not report.ok
        assert "t_in_range" in report.reason


class TestSpecialSoundnessExtractor:
    def test_two_rewinding_transcripts_yield_x(self):
        """Knowledge extractor: (t,c₁,s₁), (t,c₂,s₂) with c₁≠c₂ ⇒ x = (s₁-s₂)(c₁-c₂)⁻¹."""
        prover = SchnorrProver(GROUP, 0xDEADBEEF % (GROUP.q - 1) + 1)
        verifier = SchnorrVerifier(GROUP)
        fixed_r = 0xBADC0FFEE % (GROUP.q - 1) + 1
        transcripts = []
        for _ in range(2):
            _, t = prover.commitment(r=fixed_r)
            c = verifier.issue_challenge()
            s = prover.response(c)
            transcripts.append((t, c, s))
        (t1, c1, s1), (t2, c2, s2) = transcripts
        assert t1 == t2 and c1 != c2
        x_extracted = (s1 - s2) * pow(c1 - c2, -1, GROUP.q) % GROUP.q
        assert x_extracted == prover.x


# ===========================================================================
# Fiat-Shamir
# ===========================================================================

class TestFiatShamir:
    def test_sign_verify_roundtrip(self):
        prover = SchnorrProver(GROUP, 31337)
        verifier = SchnorrVerifier(GROUP)
        proof = prover.sign()
        assert verifier.verify_fiat_shamir(prover.y, proof.t, proof.s, proof.session_nonce).ok

    def test_challenge_is_deterministic_given_transcript(self):
        g, y, t = GROUP.g, pow(GROUP.g, 5, GROUP.p), pow(GROUP.g, 9, GROUP.p)
        nonce = b"\x01" * 32
        c1 = fiat_shamir_challenge(g, y, t, nonce, GROUP.q, GROUP.byte_length)
        c2 = fiat_shamir_challenge(g, y, t, nonce, GROUP.q, GROUP.byte_length)
        assert c1 == c2
        assert 0 <= c1 < GROUP.q

    def test_wrong_nonce_fails(self):
        prover = SchnorrProver(GROUP, 31337)
        verifier = SchnorrVerifier(GROUP)
        proof = prover.sign()
        assert not verifier.verify_fiat_shamir(prover.y, proof.t, proof.s, b"\x02" * 32).ok

    def test_tampered_s_fails(self):
        prover = SchnorrProver(GROUP, 31337)
        verifier = SchnorrVerifier(GROUP)
        proof = prover.sign()
        assert not verifier.verify_fiat_shamir(prover.y, proof.t, proof.s + 1, proof.session_nonce).ok

    def test_claimed_challenge_mismatch_detected(self):
        prover = SchnorrProver(GROUP, 31337)
        verifier = SchnorrVerifier(GROUP)
        proof = prover.sign()
        result = verifier.verify_fiat_shamir(prover.y, proof.t, proof.s, proof.session_nonce, claimed_challenge=proof.c + 1)
        assert not result.ok
        assert result.checks.get("challenge_matches_transcript") is False


# ===========================================================================
# Server API — end to end over HTTP
# ===========================================================================

class TestServerAPI:
    def test_health_and_params(self, api):
        client, _, _ = api
        assert client.get("/healthz").json()["status"] == "ok"
        params = client.get("/params").json()
        assert params["bits"] == 2048 and params["challenge_bits"] == 128
        assert int(params["p"], 16) == GROUP.p

    def test_register_login_me_logout_flow(self, api):
        client, _, _ = api
        username = _uid("alice")
        kp = keypair_from_passphrase("correct horse", username, GROUP)
        assert _register(client, username, kp.public_key).status_code == 201
        prover = SchnorrProver(GROUP, kp.private_scalar)
        login = _full_login(client, username, prover)
        assert login.status_code == 200
        token = login.json()["token"]
        me = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200 and me.json()["username"] == username
        assert client.post("/logout", headers={"Authorization": f"Bearer {token}"}).json()["status"] == "revoked"
        assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_register_duplicate_rejected(self, api):
        client, _, _ = api
        username = _uid("dup")
        kp = keypair_from_passphrase("pw", username, GROUP)
        assert _register(client, username, kp.public_key).status_code == 201
        assert _register(client, username, kp.public_key).status_code == 409

    def test_register_rejects_non_subgroup_keys(self, api):
        client, _, _ = api
        username = _uid("bad")
        for bad_key in (1, GROUP.p - 1, GROUP.p + 7):
            resp = _register(client, f"{username}{bad_key}", bad_key)
            assert resp.status_code == 422

    def test_challenge_unknown_user_404(self, api):
        client, _, _ = api
        assert client.post("/auth/challenge", json={"username": _uid("ghost"), "commitment": "4"}).status_code == 404

    def test_challenge_rejects_identity_commitment(self, api):
        client, _, _ = api
        username = _uid("victim")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        resp = client.post("/auth/challenge", json={"username": username, "commitment": "1"})
        assert resp.status_code == 422

    def test_verify_without_pending_challenge_401(self, api):
        client, _, _ = api
        username = _uid("nochallenge")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        resp = client.post("/auth/verify", json={"username": username, "response": "1"})
        assert resp.status_code == 401

    def test_replay_of_consumed_challenge_fails(self, api):
        client, _, _ = api
        username = _uid("replay")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        prover = SchnorrProver(GROUP, kp.private_scalar)
        _, t = prover.commitment()
        ch = client.post("/auth/challenge", json={"username": username, "commitment": format(t, "x")})
        c = int(ch.json()["challenge"], 16)
        s = prover.response(c)
        first = client.post("/auth/verify", json={"username": username, "response": format(s, "x")})
        assert first.status_code == 200
        replay = client.post("/auth/verify", json={"username": username, "response": format(s, "x")})
        assert replay.status_code == 401

    def test_tampered_response_yields_401_and_consumes_challenge(self, api):
        client, _, _ = api
        username = _uid("tamper")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        prover = SchnorrProver(GROUP, kp.private_scalar)
        _, t = prover.commitment()
        client.post("/auth/challenge", json={"username": username, "commitment": format(t, "x")})
        bad = client.post("/auth/verify", json={"username": username, "response": "1"})
        assert bad.status_code == 401
        # challenge consumed by the failed attempt — no silent second chance
        again = client.post("/auth/verify", json={"username": username, "response": "2"})
        assert again.status_code == 401

    def test_expired_challenge_is_rejected(self, api):
        client, app, path = api
        username = _uid("expiry")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        prover = SchnorrProver(GROUP, kp.private_scalar)
        _, t = prover.commitment()
        ch = client.post("/auth/challenge", json={"username": username, "commitment": format(t, "x")})
        assert ch.status_code == 200
        # Backdate the stored challenge so it is 31 seconds in the past.
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE challenges SET expires_at = ? WHERE username = ?", (time.time() - 31.0, username))
        c = int(ch.json()["challenge"], 16)
        s = prover.response(c)
        resp = client.post("/auth/verify", json={"username": username, "response": format(s, "x")})
        assert resp.status_code == 401

    def test_rate_limit_trips_after_repeated_failures(self, api):
        client, _, _ = api
        username = _uid("ratelimit")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        statuses = [client.post("/auth/verify", json={"username": username, "response": "1"}).status_code for _ in range(11)]
        assert statuses[-1] == 429

    def test_fiat_shamir_flow_end_to_end(self, api):
        client, _, _ = api
        username = _uid("fiat")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        prover = SchnorrProver(GROUP, kp.private_scalar)
        proof = prover.sign()
        payload = {
            "username": username,
            "t": format(proof.t, "x"),
            "s": format(proof.s, "x"),
            "session_nonce": proof.session_nonce.hex(),
            "issued_at": time.time(),
        }
        resp = client.post("/auth/fiat-shamir", json=payload)
        assert resp.status_code == 200 and resp.json()["token"]

    def test_fiat_shamir_rejects_stale_proof(self, api):
        client, _, _ = api
        username = _uid("stale")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        prover = SchnorrProver(GROUP, kp.private_scalar)
        proof = prover.sign()
        payload = {
            "username": username,
            "t": format(proof.t, "x"),
            "s": format(proof.s, "x"),
            "session_nonce": proof.session_nonce.hex(),
            "issued_at": time.time() - 3600.0,  # one hour old
        }
        assert client.post("/auth/fiat-shamir", json=payload).status_code == 401

    def test_fiat_shamir_rejects_tampered_s(self, api):
        client, _, _ = api
        username = _uid("fiatbad")
        kp = keypair_from_passphrase("pw", username, GROUP)
        _register(client, username, kp.public_key)
        prover = SchnorrProver(GROUP, kp.private_scalar)
        proof = prover.sign()
        payload = {
            "username": username,
            "t": format(proof.t, "x"),
            "s": format(proof.s + 1, "x"),
            "session_nonce": proof.session_nonce.hex(),
            "issued_at": time.time(),
        }
        assert client.post("/auth/fiat-shamir", json=payload).status_code == 401


# ===========================================================================
# Adversarial lab
# ===========================================================================

class TestAdversarialLab:
    def test_all_attacks_are_repelled(self):
        report = run_lab(group_spec="rfc3526-2048", toy_bits=32)
        assert report.secure, [a.name for a in report.attacks if not a.repelled]

    def test_simulator_demo_present(self):
        report = run_lab(group_spec="rfc3526-2048", toy_bits=32)
        demos = {d.name for d in report.demos}
        assert any("Simulator" in name for name in demos)
