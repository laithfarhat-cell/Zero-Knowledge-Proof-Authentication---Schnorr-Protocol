"""
client.cli
==========

Interactive command-line Prover for the Schnorr ZKP authentication system.

Every step of the protocol is rendered with ``rich`` — the commitment ``t``,
the challenge ``c``, the response ``s`` and the exact JSON payloads sent over
the wire — so you can visually confirm that **the private scalar and the
passphrase never leave this machine**.

Examples
--------

    \$ python -m client.cli register alice
    \$ python -m client.cli login alice
    \$ python -m client.cli fiat-shamir alice
    \$ python -m client.cli me --token <token>
    \$ python -m client.cli params

Global options: ``--server`` (or ``SCHNORR_SERVER``), ``--full`` to print
complete hex values instead of truncated previews, ``--kdf`` to select the
passphrase KDF used at registration/login time (default ``argon2id``).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from typing import Any, Dict, Optional

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.math_params import GroupParameters
from core.schnorr import (
    SchnorrProver,
    derive_private_scalar,
    keypair_from_passphrase,
    parse_hex_int,
    public_key_fingerprint,
)

console = Console()
DEFAULT_SERVER = os.environ.get("SCHNORR_SERVER", "http://127.0.0.1:8000")


def _preview(value: str, full: bool, head: int = 28, tail: int = 16) -> str:
    if full or len(value) <= head + tail + 8:
        return value
    return f"{value[:head]}…{value[-tail:]}  ({len(value)//2} bytes)"


def _print_payload(title: str, payload: Dict[str, Any], full: bool, style: str = "cyan") -> None:
    rendered = dict(payload)
    if not full:
        for key, value in list(rendered.items()):
            if isinstance(value, str) and len(value) > 96:
                rendered[key] = _preview(value, full=False)
    console.print(Panel(json.dumps(rendered, indent=2, default=str, ensure_ascii=False), title=title, border_style=style, box=box.ROUNDED))


def _fetch_group(client: httpx.Client, server: str, full: bool) -> GroupParameters:
    resp = client.get("/params")
    resp.raise_for_status()
    data = resp.json()
    group = GroupParameters(p=int(data["p"], 16), q=int(data["q"], 16), g=int(data["g"], 16), name=data["name"])
    table = Table(title="Cryptographic group (fetched from server)", box=box.SIMPLE_HEAVY)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("name", str(data["name"]))
    table.add_row("modulus p", _preview(data["p"], full, 40, 24))
    table.add_row("order q = (p-1)/2", _preview(data["q"], full, 40, 24))
    table.add_row("generator g", _preview(data["g"], full))
    table.add_row("bits", str(data["bits"]))
    table.add_row("group fingerprint", str(data.get("group_fingerprint", "-")))
    console.print(table)
    return group


def _get_passphrase(confirm: bool = False) -> str:
    first = getpass.getpass("Passphrase: ")
    if not first:
        console.print("[red]passphrase must not be empty[/red]")
        sys.exit(2)
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            console.print("[red]passphrases do not match[/red]")
            sys.exit(2)
    return first


def _http(server: str) -> httpx.Client:
    return httpx.Client(base_url=server.rstrip("/"), timeout=30.0)


def _check_server(client: httpx.Client, server: str) -> bool:
    try:
        client.get("/healthz").raise_for_status()
        return True
    except httpx.HTTPError as exc:
        console.print(Panel(f"Could not reach the verifier at [bold]{server}[/bold]\n\n{exc}\n\nStart it with: [bold]uvicorn server.api:app[/bold]",
                            title="server unreachable", border_style="red"))
        return False


def cmd_params(args: argparse.Namespace) -> int:
    with _http(args.server) as client:
        if not _check_server(client, args.server):
            return 1
        _fetch_group(client, args.server, args.full)
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    with _http(args.server) as client:
        if not _check_server(client, args.server):
            return 1
        group = _fetch_group(client, args.server, args.full)
        passphrase = _get_passphrase(confirm=True)
        kdf = args.kdf or "argon2id"
        with console.status("Deriving private scalar (Argon2id → HKDF-SHA256)…"):
            kp = keypair_from_passphrase(passphrase, args.username, group, kdf=kdf)
        payload = {"username": args.username, "public_key": kp.public_key_hex, "kdf": kdf}
        _print_payload("POST /register — request payload (no secret!)", payload, args.full, "green")
        resp = client.post("/register", json=payload)
        if resp.status_code == 201:
            console.print(Panel(
                f"[bold green]Registered[/bold green] user [bold]{args.username}[/bold]\n"
                f"public key fingerprint: [bold]{public_key_fingerprint(kp.public_key)}[/bold]\n\n"
                "The server stored only your public key. Your passphrase and derived scalar never left this machine.",
                title="registration complete", border_style="green"))
            return 0
        console.print(f"[red]register failed:[/red] HTTP {resp.status_code} — {resp.text}")
        return 1


def cmd_login(args: argparse.Namespace) -> int:
    with _http(args.server) as client:
        if not _check_server(client, args.server):
            return 1
        group = _fetch_group(client, args.server, args.full)
        profile = client.get(f"/users/{args.username}")
        if profile.status_code == 404:
            console.print(f"[red]unknown user[/red] {args.username!r} — register first: python -m client.cli register {args.username}")
            return 1
        profile_data = profile.json()
        kdf = args.kdf or profile_data.get("kdf", "argon2id")
        console.print(f"[dim]server told us the KDF for this account: {kdf}[/dim]")
        passphrase = _get_passphrase()
        with console.status("Deriving private scalar (never transmitted)…"):
            x = derive_private_scalar(passphrase, args.username, group, kdf=kdf)
        prover = SchnorrProver(group, x)

        console.rule("[bold]Schnorr 3-pass identification[/bold]")
        # --- Step 1: commitment -------------------------------------------
        _, t = prover.commitment()
        payload1 = {"username": args.username, "commitment": format(t, "x")}
        _print_payload("① Prover → Verifier · commitment  t = g^r mod p", payload1, args.full, "cyan")
        resp = client.post("/auth/challenge", json=payload1)
        if resp.status_code != 200:
            console.print(f"[red]challenge failed:[/red] HTTP {resp.status_code} — {resp.text}")
            return 1
        challenge_data = resp.json()
        _print_payload("② Verifier → Prover · challenge  c ∈ [1, 2¹²⁸−1]", challenge_data, args.full, "yellow")
        c = parse_hex_int(challenge_data["challenge"])

        # --- Step 2: response ----------------------------------------------
        s = prover.response(c)
        payload3 = {"username": args.username, "response": format(s, "x")}
        _print_payload("③ Prover → Verifier · response  s = (r + c·x) mod q", payload3, args.full, "cyan")
        resp = client.post("/auth/verify", json=payload3)
        _print_payload("Verifier decision", resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}, args.full, "green" if resp.status_code == 200 else "red")
        if resp.status_code != 200:
            console.print("[red]authentication FAILED[/red]")
            return 1
        token = resp.json().get("token", "")
        console.print(Panel(
            f"[bold green]Authenticated.[/bold green]\n\n"
            f"token: [bold]{_preview(token, args.full, 40, 24)}[/bold]\n"
            f"(store with: [bold]export SCHNORR_TOKEN={token if args.full else '<token>'}[/bold])",
            title="access token", border_style="green"))
        return 0


def cmd_fiat_shamir(args: argparse.Namespace) -> int:
    with _http(args.server) as client:
        if not _check_server(client, args.server):
            return 1
        group = _fetch_group(client, args.server, args.full)
        profile = client.get(f"/users/{args.username}")
        if profile.status_code == 404:
            console.print(f"[red]unknown user[/red] {args.username!r}")
            return 1
        kdf = args.kdf or profile.json().get("kdf", "argon2id")
        passphrase = _get_passphrase()
        with console.status("Deriving private scalar…"):
            x = derive_private_scalar(passphrase, args.username, group, kdf=kdf)
        prover = SchnorrProver(group, x)
        issued_at = time.time()
        proof = prover.sign()
        payload = {
            "username": args.username,
            "t": format(proof.t, "x"),
            "s": format(proof.s, "x"),
            "session_nonce": proof.session_nonce.hex(),
            "issued_at": issued_at,
        }
        _print_payload("POST /auth/fiat-shamir — one-shot proof", payload, args.full, "cyan")
        console.print(f"[dim]embedded challenge c = SHA256(g‖y‖t‖nonce) mod q = {_preview(format(proof.c, 'x'), args.full)}[/dim]")
        resp = client.post("/auth/fiat-shamir", json=payload)
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}
        _print_payload("Verifier decision", body, args.full, "green" if resp.status_code == 200 else "red")
        return 0 if resp.status_code == 200 else 1


def cmd_me(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("SCHNORR_TOKEN")
    if not token:
        console.print("[red]provide --token or set SCHNORR_TOKEN[/red]")
        return 2
    with _http(args.server) as client:
        if not _check_server(client, args.server):
            return 1
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        console.print_json(data=resp.json()) if resp.status_code == 200 else console.print(f"[red]{resp.status_code}[/red] — {resp.text}")
        return 0 if resp.status_code == 200 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Schnorr ZKP Prover CLI", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=DEFAULT_SERVER, help="verifier base URL (default: %(default)s)")
    parser.add_argument("--full", action="store_true", help="print full hex values (no truncation)")
    parser.add_argument("--kdf", default=None, choices=["argon2id", "pbkdf2"], help="passphrase KDF (default: server-reported / argon2id)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("params", help="show the cryptographic group parameters")
    p.set_defaults(func=cmd_params)

    p = sub.add_parser("register", help="register a new user (stores only the public key)")
    p.add_argument("username")
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("login", help="run the interactive 3-pass Schnorr protocol")
    p.add_argument("username")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("fiat-shamir", help="one-shot Fiat-Shamir proof (single request)")
    p.add_argument("username")
    p.set_defaults(func=cmd_fiat_shamir)

    p = sub.add_parser("me", help="introspect a bearer token")
    p.add_argument("--token", default=None)
    p.set_defaults(func=cmd_me)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        rc = args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]aborted[/yellow]")
        rc = 130
    except httpx.HTTPError as exc:
        console.print(f"[red]network error:[/red] {exc}")
        rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
