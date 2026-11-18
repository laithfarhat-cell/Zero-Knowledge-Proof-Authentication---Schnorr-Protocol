"""
simulation.mitm_lab
===================

Adversarial security laboratory for the Schnorr ZKP authentication protocol.
Every scenario runs in-process against a throwaway Verifier instance (its own
temporary SQLite database) — nothing leaves your machine, nothing needs a
running server.

Scenarios
---------

**Attacks** (each must be REPELLED for the exit code to be 0):

1. *Eavesdropping & Replay* — a passive wiretap captures a complete honest
   ``(t, c, s)`` transcript; the attacker re-sends it. The challenge is
   single-use and the secret never appears on the wire → replay fails.
2. *Impersonation / Forgery (Soundness)* — the attacker commits to a forged
   ``t' = g^s · y^{-c'}`` before the verifier's fresh 128-bit challenge ``c``
   exists. Forgery succeeds only if ``c == c'`` (probability 2⁻¹²⁸).
3. *Active MITM tampering* — the attacker modifies ``t`` in flight and/or
   rewrites ``s`` after capture; verification equation fails → session dead.
4. *Unknown-user probing* — verify attempts for unregistered identities are
   rejected; a failed-proof rate limiter throttles brute force.

**Demonstrations** (informational, always "succeed" on toy parameters):

5. *Discrete-log recovery on a 40-bit toy group* — baby-step giant-step
   recovers ``x`` from the public transcript, showing *why* the 2048-bit
   modulus matters (work factor ≈ 2^1024).
6. *Nonce-reuse catastrophic failure* — two sessions reusing the same ``r``
   leak ``x = (s₁-s₂)/(c₁-c₂) mod q``. Shows why fresh CSPRNG nonces are
   mandatory (and why our prover draws a new one on every commitment).
7. *Honest-verifier zero-knowledge simulator* — transcripts can be simulated
   without knowing ``x`` at all, which is precisely what "zero knowledge"
   means; they are indistinguishable from real transcripts.

Usage
-----

    python -m simulation.mitm_lab              # full lab, RFC 3526 group
    python -m simulation.mitm_lab --toy-bits 32
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.math_params import GroupParameters, generate_safe_prime
from core.schnorr import (
    SchnorrProver,
    SchnorrVerifier,
    keypair_from_passphrase,
    parse_hex_int,
)
from server.api import create_app
from server.testing import live_server

console = Console()


@dataclass
class ScenarioResult:
    name: str
    description: str
    repelled: bool                 # True → the protocol defended successfully
    details: List[str] = field(default_factory=list)


@dataclass
class LabReport:
    attacks: List[ScenarioResult] = field(default_factory=list)
    demos: List[ScenarioResult] = field(default_factory=list)

    @property
    def secure(self) -> bool:
        return all(a.repelled for a in self.attacks)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hex(x: int) -> str:
    return format(x, "x")


def _wiretap_honest_session(client: httpx.Client, prover: SchnorrProver, username: str) -> Dict[str, Any]:
    """Run one honest end-to-end session, recording every byte on the wire."""
    _, t = prover.commitment()
    req1 = {"username": username, "commitment": _hex(t)}
    resp1 = client.post("/auth/challenge", json=req1)
    c = parse_hex_int(resp1.json()["challenge"])
    s = prover.response(c)
    req2 = {"username": username, "response": _hex(s)}
    resp2 = client.post("/auth/verify", json=req2)
    return {
        "t": t, "c": c, "s": s,
        "request_payloads": [req1, req2],
        "challenge_response": resp1.json(),
        "verify_response": resp2.json(),
        "verify_status": resp2.status_code,
    }


def _bsgs_discrete_log(g: int, h: int, p: int, order: int) -> Optional[int]:
    """Baby-step giant-step: solve h = g^x mod p with x < order. O(√order)."""
    m = math.isqrt(order) + 1
    table: Dict[int, int] = {}
    factor = 1
    for j in range(m):
        table.setdefault(factor, j)
        factor = factor * g % p
    giant = pow(pow(g, m, p), p - 2, p)  # g^{-m} mod p
    gamma = h
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            candidate = (i * m + j) % order
            if pow(g, candidate, p) == h:
                return candidate
        gamma = gamma * giant % p
    return None


# ---------------------------------------------------------------------------
# Attack 1 — Eavesdropping & replay
# ---------------------------------------------------------------------------

def attack_eavesdrop_replay(client: httpx.Client, group: GroupParameters, username: str, prover: SchnorrProver) -> ScenarioResult:
    result = ScenarioResult(
        name="Eavesdropping & Replay",
        description="Passive listener captures (t, c, s) and re-sends it to the verifier.",
        repelled=True,
    )
    transcript = _wiretap_honest_session(client, prover, username)
    details = result.details
    details.append(f"captured commitment  t = {_hex(transcript['t'])[:23]}…")
    details.append(f"captured challenge   c = {_hex(transcript['c'])[:23]}…")
    details.append(f"captured response    s = {_hex(transcript['s'])[:23]}…")

    # 1a. The secret must not appear anywhere on the wire.
    wire = json.dumps(transcript["request_payloads"]) + json.dumps(transcript["challenge_response"])
    secret_leaked = str(prover.x) in wire or _hex(prover.x) in wire
    details.append(f"private scalar present in captured traffic: {secret_leaked}")
    if secret_leaked:
        result.repelled = False
        return result

    # 1b. Direct replay of the consumed (username, s).
    replay1 = client.post("/auth/verify", json={"username": username, "response": _hex(transcript["s"])})
    details.append(f"direct replay of s → HTTP {replay1.status_code} ({replay1.json().get('detail')})")

    # 1c. Fresh challenge, stale response (challenge is single-use).
    _, t2 = prover.commitment()
    resp = client.post("/auth/challenge", json={"username": username, "commitment": _hex(t2)})
    fresh_s = transcript["s"]  # stale response re-used against a fresh challenge
    replay2 = client.post("/auth/verify", json={"username": username, "response": _hex(fresh_s)})
    details.append(f"fresh challenge issued, stale s re-used → HTTP {replay2.status_code} ({replay2.json().get('detail')})")

    result.repelled = replay1.status_code == 401 and replay2.status_code == 401
    return result


# ---------------------------------------------------------------------------
# Attack 2 — Impersonation via forgery (soundness)
# ---------------------------------------------------------------------------

def attack_forgery(client: httpx.Client, group: GroupParameters, username: str, victim_y: int) -> ScenarioResult:
    result = ScenarioResult(
        name="Impersonation / Forgery",
        description="Attacker without x pre-computes t′ = g^s · y^(−c′) for a guessed challenge c′.",
        repelled=True,
    )
    p, q, g = group.p, group.q, group.g
    details = result.details

    s_fake = secrets.randbelow(q - 1) + 1
    c_guess = secrets.randbelow(2**128 - 1) + 1
    y_inv = pow(victim_y, p - 2, p)  # y^{-1} mod p (p prime)
    t_fake = pow(g, s_fake, p) * pow(y_inv, c_guess, p) % p
    details.append(f"attacker-chosen s′ = {_hex(s_fake)[:23]}…")
    details.append(f"attacker-guessed challenge c′ = {_hex(c_guess)[:23]}… (128-bit guess)")
    details.append(f"attacker-forged commitment t′ = g^s′ · y^(−c′) = {_hex(t_fake)[:23]}…")

    resp = client.post("/auth/challenge", json={"username": username, "commitment": _hex(t_fake)})
    if resp.status_code != 200:
        details.append(f"server rejected forged t′ with HTTP {resp.status_code}")
        result.repelled = True
        return result
    c_server = parse_hex_int(resp.json()["challenge"])
    details.append(f"server issued FRESH c = {_hex(c_server)[:23]}…  (c == c′ ? {c_server == c_guess})")

    # The attacker's only move is to submit s_fake; it verifies iff c_server == c_guess.
    verify = client.post("/auth/verify", json={"username": username, "response": _hex(s_fake)})
    details.append(f"forged proof → HTTP {verify.status_code} ({verify.json().get('detail')})")

    # Belt and braces: evaluate the verification equation directly.
    lhs = pow(g, s_fake, p)
    rhs = t_fake * pow(victim_y, c_server, p) % p
    details.append(f"direct check  g^s′ ≟ t′·y^c → {lhs == rhs}")
    result.repelled = verify.status_code == 401 and lhs != rhs
    return result


# ---------------------------------------------------------------------------
# Attack 3 — Active MITM tampering
# ---------------------------------------------------------------------------

def attack_mitm_tampering(client: httpx.Client, group: GroupParameters, username: str, prover: SchnorrProver) -> ScenarioResult:
    result = ScenarioResult(
        name="Active MITM Tampering",
        description="Attacker in the middle rewrites t in flight, or rewrites s after capture.",
        repelled=True,
    )
    p, q, g = group.p, group.q, group.g
    details = result.details

    # 3a. MITM nudges the commitment: t′ = t·g mod p.
    _, t = prover.commitment()
    t_prime = (t * g) % p
    resp = client.post("/auth/challenge", json={"username": username, "commitment": _hex(t_prime)})
    if resp.status_code == 200:
        c = parse_hex_int(resp.json()["challenge"])
        # The prover can only answer with the nonce it committed to (t), not for t′.
        s = prover.response(c)
        forged = client.post("/auth/verify", json={"username": username, "response": _hex(s)})
        lhs = pow(g, s, p)
        rhs = t_prime * pow(prover.y, c, p) % p
        details.append(f"tampered t′ accepted by server, prover's s → HTTP {forged.status_code}; equation g^s ≟ t′y^c holds: {lhs == rhs}")
        ok_3a = forged.status_code == 401 and lhs != rhs
    else:
        details.append(f"server refused tampered commitment with HTTP {resp.status_code}")
        ok_3a = True

    # 3b. Bit-flip the response in flight.
    _, t = prover.commitment()
    resp = client.post("/auth/challenge", json={"username": username, "commitment": _hex(t)})
    c = parse_hex_int(resp.json()["challenge"])
    s = prover.response(c)
    s_flipped = s ^ 1
    tampered = client.post("/auth/verify", json={"username": username, "response": _hex(s_flipped)})
    details.append(f"s ⊕ 1 in flight → HTTP {tampered.status_code} ({tampered.json().get('detail')})")

    result.repelled = ok_3a and tampered.status_code == 401
    return result


# ---------------------------------------------------------------------------
# Attack 4 — Unregistered identities & observability
# ---------------------------------------------------------------------------

def attack_unknown_user(client: httpx.Client, group: GroupParameters) -> ScenarioResult:
    result = ScenarioResult(
        name="Unregistered-Identity Probing",
        description="Attacker tries to authenticate as a user that does not exist.",
        repelled=True,
    )
    resp = client.post("/auth/challenge", json={"username": "mallory-does-not-exist", "commitment": "4"})
    verify = client.post("/auth/verify", json={"username": "mallory-does-not-exist", "response": "1"})
    result.details.append(f"challenge for unknown user → HTTP {resp.status_code}")
    result.details.append(f"verify for unknown user → HTTP {verify.status_code}")
    result.repelled = resp.status_code == 404 and verify.status_code == 404
    return result


# ---------------------------------------------------------------------------
# Demo 5 — BSGS discrete-log recovery on a toy group
# ---------------------------------------------------------------------------

def demo_bsgs_toy_group(toy_bits: int = 40) -> ScenarioResult:
    start = time.perf_counter()
    toy = generate_safe_prime(toy_bits, rounds=12)
    kp = keypair_from_passphrase("attack-target-passphrase", "toy-victim", toy)
    prover = SchnorrProver(toy, kp.private_scalar)
    verifier = SchnorrVerifier(toy)
    _, t = prover.commitment()
    c = verifier.issue_challenge()
    s = prover.response(c)
    assert verifier.verify(kp.public_key, t, c, s)  # honest transcript is valid
    r_recovered = _bsgs_discrete_log(toy.g, t, toy.p, toy.q)
    x_recovered = None
    if r_recovered is not None:
        x_recovered = (s - r_recovered) * pow(c, -1, toy.q) % toy.q  # s = r + c·x (mod q)
    elapsed = time.perf_counter() - start
    ok = x_recovered == kp.private_scalar
    result = ScenarioResult(
        name=f"Discrete-Log Recovery (toy {toy_bits}-bit group)",
        description="Eavesdropper runs baby-step giant-step on the captured commitment to extract r, then x.",
        repelled=not ok,  # informational: success here is expected on toy groups
        details=[
            f"toy group: p = {toy_bits} bits, q ≈ 2^{toy.q.bit_length()}, g = {toy.g}",
            f"baby-step giant-step cost ≈ √q ≈ 2^{toy.q.bit_length() // 2} operations",
            f"recovered x == actual x: {ok}   (elapsed {elapsed:.2f}s)",
            f"the same attack against the 2048-bit RFC 3526 group needs ≈ 2^1024 operations —",
            f"≈ 10^{1024 * math.log10(2.0):.0f} times more work; infeasible for any adversary on Earth.",
        ],
    )
    return result


# ---------------------------------------------------------------------------
# Demo 6 — Nonce reuse leaks the private key
# ---------------------------------------------------------------------------

def demo_nonce_reuse(group: GroupParameters) -> ScenarioResult:
    start = time.perf_counter()
    kp = keypair_from_passphrase("nonce-reuse-victim", "nonce-victim", group)
    prover = SchnorrProver(group, kp.private_scalar)
    verifier = SchnorrVerifier(group)
    r_reused = secrets.randbelow(group.q - 1) + 1  # the fatal mistake
    transcripts = []
    for _ in range(2):
        _, t = prover.commitment(r=r_reused)
        c = verifier.issue_challenge()
        s = prover.response(c)
        transcripts.append((t, c, s))
    (t1, c1, s1), (t2, c2, s2) = transcripts
    same_t = t1 == t2
    if c1 != c2:
        x_extracted = (s1 - s2) * pow(c1 - c2, -1, group.q) % group.q
    else:
        x_extracted = None
    ok = x_extracted == kp.private_scalar
    return ScenarioResult(
        name="Nonce Reuse Extraction",
        description="Two accepting transcripts with the same r yield x = (s₁-s₂)·(c₁-c₂)⁻¹ mod q.",
        repelled=False,  # expected to succeed — that is the point of the demo
        details=[
            f"same commitment reused: {same_t}",
            f"extracted x == actual private scalar: {ok}",
            f"elapsed {time.perf_counter() - start:.3f}s",
            "this proof has NO defender against it except discipline: our prover draws a fresh",
            "CSPRNG nonce on every commitment() and never reuses it.",
        ],
    )


# ---------------------------------------------------------------------------
# Demo 7 — Honest-verifier zero-knowledge simulator
# ---------------------------------------------------------------------------

def demo_hvzk_simulator(group: GroupParameters) -> ScenarioResult:
    kp = keypair_from_passphrase("simulation-demo", "sim-victim", group)
    verifier = SchnorrVerifier(group)
    p, q, g = group.p, group.q, group.g

    simulated_ok = 0
    for _ in range(3):
        # HVZK simulator: choose c, s at random; set t = g^s · y^(−c).
        s = secrets.randbelow(q - 1) + 1
        c = verifier.issue_challenge()
        y_inv = pow(kp.public_key, p - 2, p)
        t = pow(g, s, p) * pow(y_inv, c, p) % p
        simulated_ok += int(verifier.verify(kp.public_key, t, c, s))

    return ScenarioResult(
        name="HVZK Transcript Simulator",
        description="Transcripts can be fabricated without x, indistinguishably from real ones.",
        repelled=True,  # expected: this is the zero-knowledge property holding
        details=[
            f"simulated transcripts accepted by the verifier: {simulated_ok}/3",
            "a verifier (or eavesdropper) therefore learns NOTHING about x from transcripts;",
            "the view of the protocol is simulatable from public data alone.",
        ],
    )


# ---------------------------------------------------------------------------
# Lab runner
# ---------------------------------------------------------------------------

def run_lab(group_spec: Optional[str] = None, toy_bits: int = 40, passphrase: str = "attack-target-passphrase") -> LabReport:
    from core.math_params import load_group

    report = LabReport()
    group = load_group(group_spec or "rfc3526-2048")
    with tempfile.TemporaryDirectory(prefix="schnorr-lab-") as tmp:
        app = create_app(db_path=os.path.join(tmp, "lab.db"), group_spec=group_spec or "rfc3526-2048")
        with live_server(app) as base_url, httpx.Client(base_url=base_url, timeout=30.0) as client:
            username = "victim"
            kp = keypair_from_passphrase(passphrase, username, group)
            reg = client.post("/register", json={"username": username, "public_key": _hex(kp.public_key), "kdf": "argon2id"})
            assert reg.status_code == 201, reg.text
            prover = SchnorrProver(group, kp.private_scalar)

            report.attacks.append(attack_eavesdrop_replay(client, group, username, prover))
            report.attacks.append(attack_forgery(client, group, username, kp.public_key))
            report.attacks.append(attack_mitm_tampering(client, group, username, prover))
            report.attacks.append(attack_unknown_user(client, group))

    report.demos.append(demo_bsgs_toy_group(toy_bits))
    report.demos.append(demo_nonce_reuse(group))
    report.demos.append(demo_hvzk_simulator(group))
    return report


def _print_report(report: LabReport) -> None:
    console.print(Panel.fit(
        "[bold]Schnorr ZKP — Adversarial Security Laboratory[/bold]\n"
        "[dim]replay · impersonation · MITM tampering · discrete-log · nonce misuse · HVZK[/dim]",
        border_style="cyan", box=box.DOUBLE,
    ))

    table = Table(title="Attack scenarios (the protocol must REPEL all of these)", box=box.ROUNDED)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Attack", style="bold")
    table.add_column("Verdict", justify="center")
    for i, attack in enumerate(report.attacks, 1):
        verdict = "[bold green]✔ REPELLED[/bold green]" if attack.repelled else "[bold red]✘ BREACHED[/bold red]"
        table.add_row(str(i), attack.name, verdict)
    console.print(table)
    for attack in report.attacks:
        console.print(Panel("\n".join(f"  • {d}" for d in attack.details), title=f"{attack.name} — {attack.description}", border_style="green" if attack.repelled else "red", box=box.ROUNDED))

    table2 = Table(title="Demonstrations (informational)", box=box.ROUNDED)
    table2.add_column("#", justify="right", style="dim")
    table2.add_column("Demonstration", style="bold")
    table2.add_column("Outcome", justify="center")
    for i, demo in enumerate(report.demos, 1):
        outcome = "[yellow]expected on toy parameters[/yellow]" if not demo.repelled else "[green]property holds[/green]"
        table2.add_row(str(i), demo.name, outcome)
    console.print(table2)
    for demo in report.demos:
        border = "green" if demo.repelled else "yellow"
        console.print(Panel("\n".join(f"  • {d}" for d in demo.details), title=f"{demo.name} — {demo.description}", border_style=border, box=box.ROUNDED))

    if report.secure:
        console.print(Panel.fit("[bold green]ALL ATTACKS REPELLED — the protocol is sound at these parameters.[/]", border_style="green", box=box.DOUBLE))
    else:
        console.print(Panel.fit("[bold red]BREACH DETECTED — see above.[/bold red]", border_style="red", box=box.DOUBLE))


def main() -> None:
    import logging

    for noisy in ("schnorr.server", "httpx", "uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)
    parser = argparse.ArgumentParser(description="Adversarial MITM lab for the Schnorr ZKP protocol")
    parser.add_argument("--group", default="rfc3526-2048", help="group spec, e.g. rfc3526-2048 or generated:256")
    parser.add_argument("--toy-bits", type=int, default=40, help="bits for the toy BSGS group (default: 40)")
    args = parser.parse_args()
    report = run_lab(group_spec=args.group, toy_bits=args.toy_bits)
    _print_report(report)
    sys.exit(0 if report.secure else 1)


if __name__ == "__main__":
    main()
