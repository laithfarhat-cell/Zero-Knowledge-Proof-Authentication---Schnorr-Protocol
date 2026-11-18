"""
server.api
==========

FastAPI Verifier service for Schnorr zero-knowledge authentication.

Endpoints
---------
``GET  /``                    service banner / discovery
``GET  /healthz``             liveness probe
``GET  /params``              cryptographic group parameters (p, q, g, ...)
``POST /register``            register a username + public key (never a secret)
``GET  /users/{username}``    public profile (public key + KDF used) — nothing secret
``POST /auth/challenge``      issue a single-use 128-bit challenge for (username, t)
``POST /auth/verify``         verify the response, consume the challenge, mint a token
``POST /auth/fiat-shamir``    stateless one-request proof (Fiat-Shamir heuristic)
``GET  /me``                  introspect the bearer token
``POST /logout``              revoke the bearer token

Security properties enforced here
---------------------------------
* Only public keys are stored; secrets never arrive at the server.
* Challenges are single-use, expire after ``CHALLENGE_TTL_SECONDS`` (30 s) and
  are bound to the commitment ``t`` they were issued for.
* A sliding-window rate limiter throttles verification failures per username.
* Session tokens are stored as SHA-256 hashes, not in plain text.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from core.math_params import group_fingerprint, is_valid_group_element, load_group
from core.schnorr import (
    CHALLENGE_BITS,
    SchnorrVerifier,
    parse_hex_int,
    public_key_fingerprint,
)
from server.database import CHALLENGE_TTL_SECONDS, SESSION_TTL_SECONDS, Database

logger = logging.getLogger("schnorr.server")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,64}$")
FIAT_SHAMIR_MAX_AGE_SECONDS = float(os.environ.get("SCHNORR_FS_MAX_AGE", "300"))
_RATE_WINDOW = 300.0
_RATE_MAX_FAILURES = 10


# ---------------------------------------------------------------------------
# Rate limiting (in-memory sliding window, per key)
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    def __init__(self, max_failures: int = _RATE_MAX_FAILURES, window_seconds: float = _RATE_WINDOW):
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        with self._lock:
            hits = self._failures.get(key)
            if not hits:
                return True
            cutoff = time.time() - self.window
            while hits and hits[0] < cutoff:
                hits.popleft()
            return len(hits) < self.max_failures

    def record_failure(self, key: str) -> None:
        with self._lock:
            hits = self._failures[key]
            cutoff = time.time() - self.window
            while hits and hits[0] < cutoff:
                hits.popleft()
            hits.append(time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")


def _parse_hex(value: str, field: str) -> int:
    if not _HEX_RE.match(value or ""):
        raise ValueError(f"{field} must be a non-empty hexadecimal string")
    return parse_hex_int(value)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    public_key: str = Field(..., description="public key y = g^x mod p, hex-encoded")
    kdf: str = Field(default="argon2id", pattern="^(argon2id|pbkdf2)$")

    @field_validator("username")
    @classmethod
    def _username_ok(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("username must match ^[A-Za-z0-9_.-]{3,64}$")
        return v


class ChallengeRequest(BaseModel):
    username: str
    commitment: str = Field(..., description="commitment t = g^r mod p, hex-encoded")


class VerifyRequest(BaseModel):
    username: str
    response: str = Field(..., description="response s, hex-encoded")


class FiatShamirRequest(BaseModel):
    username: str
    t: str = Field(..., description="commitment, hex-encoded")
    s: str = Field(..., description="response scalar, hex-encoded")
    session_nonce: str = Field(..., description="≥16-byte hex session nonce bound into the challenge")
    issued_at: float = Field(..., description="unix time the proof was produced; must be fresh")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(db_path: Optional[str] = None, group_spec: Optional[str] = None) -> FastAPI:
    logging.basicConfig(level=os.environ.get("SCHNORR_LOG_LEVEL", "INFO"))
    spec = group_spec or os.environ.get("SCHNORR_GROUP", "rfc3526-2048")
    group = load_group(spec)
    db = Database(db_path or os.environ.get("SCHNORR_DB_PATH") or None)
    verifier = SchnorrVerifier(group)
    limiter = SlidingWindowRateLimiter()
    db.purge_expired()

    app = FastAPI(
        title="Schnorr ZKP Authentication",
        description="Zero-knowledge proof (Schnorr identification protocol) verifier service.",
        version="1.0.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("SCHNORR_CORS_ORIGINS", "*").split(","),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.state.db = db
    app.state.group = group
    app.state.verifier = verifier
    app.state.limiter = limiter

    logger.info("group=%s fingerprint=%s bits=%d", group.name, group_fingerprint(group), group.bits)

    # -- dependencies --------------------------------------------------------
    def get_db() -> Database:
        return db

    # -- meta endpoints ------------------------------------------------------
    @app.get("/")
    def index():
        return {
            "service": "schnorr-zkp-auth",
            "protocol": "Schnorr identification (3-pass) + Fiat-Shamir",
            "docs": "/docs",
            "params": "/params",
        }

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "group": group.name, "group_fingerprint": group_fingerprint(group)}

    @app.get("/params")
    def params():
        data = group.to_dict()
        data["group_fingerprint"] = group_fingerprint(group)
        data["challenge_ttl_seconds"] = CHALLENGE_TTL_SECONDS
        data["challenge_bits"] = CHALLENGE_BITS
        data["fiat_shamir_max_age_seconds"] = FIAT_SHAMIR_MAX_AGE_SECONDS
        return data

    # -- registration ----------------------------------------------------------
    @app.post("/register", status_code=201)
    def register(req: RegisterRequest, database: Database = Depends(get_db)):
        try:
            y = _parse_hex(req.public_key, "public_key")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if not is_valid_group_element(y, group):
            raise HTTPException(status_code=422, detail="public key is not a valid order-q subgroup element")
        created = database.create_user(req.username, format(y, "x"), req.kdf)
        if not created:
            raise HTTPException(status_code=409, detail="username already registered")
        logger.info("registered user=%s fingerprint=%s", req.username, public_key_fingerprint(y))
        return {
            "status": "registered",
            "username": req.username,
            "public_key_fingerprint": public_key_fingerprint(y),
            "kdf": req.kdf,
        }

    @app.get("/users/{username}")
    def user_profile(username: str, database: Database = Depends(get_db)):
        row = database.get_user(username)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown user")
        y = int(row["public_key_hex"], 16)
        return {
            "username": row["username"],
            "public_key": row["public_key_hex"],
            "public_key_fingerprint": public_key_fingerprint(y),
            "kdf": row["kdf"],
            "created_at": row["created_at"],
        }

    # -- interactive 3-pass protocol -------------------------------------------
    @app.post("/auth/challenge")
    def auth_challenge(req: ChallengeRequest, database: Database = Depends(get_db)):
        row = database.get_user(req.username)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown user")
        try:
            t = _parse_hex(req.commitment, "commitment")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if not is_valid_group_element(t, group):
            raise HTTPException(status_code=422, detail="commitment is not a valid order-q subgroup element")
        c = verifier.issue_challenge()
        expires_at = database.store_challenge(req.username, format(t, "x"), format(c, "x"), CHALLENGE_TTL_SECONDS)
        logger.info("challenge issued user=%s t_fp=%s", req.username, public_key_fingerprint(t))
        return {
            "username": req.username,
            "challenge": format(c, "x"),
            "challenge_bits": CHALLENGE_BITS,
            "challenge_ttl_seconds": CHALLENGE_TTL_SECONDS,
            "expires_at": expires_at,
        }

    @app.post("/auth/verify")
    def auth_verify(req: VerifyRequest, database: Database = Depends(get_db)):
        if not limiter.is_allowed(f"verify:{req.username}"):
            raise HTTPException(status_code=429, detail="too many failed attempts — try again later")
        row = database.get_user(req.username)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown user")
        try:
            s = _parse_hex(req.response, "response")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        y = int(row["public_key_hex"], 16)

        # Atomic read-and-delete: the challenge is single-use no matter the outcome.
        pending = database.consume_challenge(req.username)
        if pending is None:
            limiter.record_failure(f"verify:{req.username}")
            raise HTTPException(status_code=401, detail="no pending challenge (missing, expired or already used)")
        t = int(pending["commitment_hex"], 16)
        c = int(pending["challenge_hex"], 16)

        result = verifier.verify_detailed(y, t, c, s)
        if not result.ok:
            limiter.record_failure(f"verify:{req.username}")
            logger.warning("verify FAILED user=%s reason=%s", req.username, result.reason)
            raise HTTPException(status_code=401, detail="verification failed")

        limiter.reset(f"verify:{req.username}")
        session = database.create_session(req.username, SESSION_TTL_SECONDS)
        logger.info("verify OK user=%s", req.username)
        return {
            "status": "authenticated",
            "username": req.username,
            **session,
        }

    # -- Fiat-Shamir (stateless) --------------------------------------------------
    @app.post("/auth/fiat-shamir")
    def auth_fiat_shamir(req: FiatShamirRequest, database: Database = Depends(get_db)):
        if not limiter.is_allowed(f"fiatshamir:{req.username}"):
            raise HTTPException(status_code=429, detail="too many failed attempts — try again later")
        row = database.get_user(req.username)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown user")
        try:
            t = _parse_hex(req.t, "t")
            s = _parse_hex(req.s, "s")
            nonce = bytes.fromhex(req.session_nonce.lower().removeprefix("0x"))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"invalid hex input: {exc}")
        if len(nonce) < 16:
            raise HTTPException(status_code=422, detail="session_nonce must be at least 16 bytes")
        now = time.time()
        if abs(now - req.issued_at) > FIAT_SHAMIR_MAX_AGE_SECONDS:
            limiter.record_failure(f"fiatshamir:{req.username}")
            raise HTTPException(status_code=401, detail="proof expired or issued_at in the future")
        y = int(row["public_key_hex"], 16)

        result = verifier.verify_fiat_shamir(y, t, s, nonce)
        if not result.ok:
            limiter.record_failure(f"fiatshamir:{req.username}")
            logger.warning("fiat-shamir FAILED user=%s reason=%s", req.username, result.reason)
            raise HTTPException(status_code=401, detail="fiat-shamir verification failed")

        limiter.reset(f"fiatshamir:{req.username}")
        session = database.create_session(req.username, SESSION_TTL_SECONDS)
        logger.info("fiat-shamir OK user=%s", req.username)
        return {"status": "authenticated", "username": req.username, "mode": "fiat-shamir", **session}

    # -- session introspection ------------------------------------------------------
    def _bearer_token(authorization: Optional[str]) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        return authorization.split(" ", 1)[1].strip()

    @app.get("/me")
    def me(authorization: Optional[str] = Header(default=None), database: Database = Depends(get_db)):
        token = _bearer_token(authorization)
        session = database.lookup_session(token)
        if session is None:
            raise HTTPException(status_code=401, detail="invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
        return {
            "username": session["username"],
            "created_at": session["created_at"],
            "expires_at": session["expires_at"],
        }

    @app.post("/logout")
    def logout(authorization: Optional[str] = Header(default=None), database: Database = Depends(get_db)):
        token = _bearer_token(authorization)
        revoked = database.revoke_session(token)
        return {"status": "revoked" if revoked else "no-such-session"}

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        "server.api:app",
        host=os.environ.get("SCHNORR_HOST", "0.0.0.0"),
        port=int(os.environ.get("SCHNORR_PORT", "8000")),
        reload=False,
    )


if __name__ == "__main__":
    main()
