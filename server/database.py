"""
server.database
===============

SQLite persistence layer for the Verifier service.

Tables
------
``users``
    Registered public keys. Only ``username`` and the public key ``y`` (hex)
    are stored — never a passphrase, never a derived secret.
``challenges``
    Single-use, short-lived interactive challenges. One pending challenge per
    username (a fresh ``/auth/challenge`` atomically replaces the previous
    one). Rows older than their TTL are treated as non-existent and are
    purged opportunistically; consumed challenges are deleted immediately so
    a captured ``(t, c, s)`` transcript cannot be replayed.
``sessions``
    Bearer session tokens. Only the SHA-256 hash of the token is stored, so a
    database leak does not leak usable credentials.

Design notes
------------
* A new short-lived connection is used per operation (SQLite handles the
  locking); the schema is created idempotently on startup.
* All values that are big integers are stored as lowercase hex text.
* Every query uses bound parameters — no string interpolation anywhere.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    public_key_hex  TEXT NOT NULL,
    kdf             TEXT NOT NULL DEFAULT 'argon2id',
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    username        TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
    commitment_hex  TEXT NOT NULL,
    challenge_hex   TEXT NOT NULL,
    issued_at       REAL NOT NULL,
    expires_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash      TEXT PRIMARY KEY,
    username        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);
"""

DEFAULT_DB_PATH = os.environ.get("SCHNORR_DB_PATH", "schnorr_auth.db")
CHALLENGE_TTL_SECONDS = 30.0
SESSION_TTL_SECONDS = 3600.0


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Database:
    """Thread-safe SQLite registry (one short-lived connection per call)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_DB_PATH
        self._is_memory = self.path == ":memory:"
        if self._is_memory:
            # A shared-cache in-memory database keeps data across connections.
            self.path = "file:schnorr_mem?mode=memory&cache=shared"
        self._memory_anchor: Optional[sqlite3.Connection] = None
        if self._is_memory:
            # Hold one anchor connection so the shared in-memory db survives.
            self._memory_anchor = self._connect()
        self._init_schema()

    # -- connection handling --------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            uri=self._is_memory,
            timeout=10.0,
            isolation_level=None,  # explicit transactions
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not self._is_memory:
            conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        finally:
            conn.close()

    @contextmanager
    def _ro(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
        finally:
            conn.close()

    def close(self) -> None:
        if self._memory_anchor is not None:
            self._memory_anchor.close()
            self._memory_anchor = None

    # -- users ------------------------------------------------------------------
    def create_user(self, username: str, public_key_hex: str, kdf: str = "argon2id") -> bool:
        """Insert a new user. Returns False if the username already exists."""
        with self._tx() as conn:
            try:
                conn.execute(
                    "INSERT INTO users(username, public_key_hex, kdf, created_at) VALUES (?,?,?,?)",
                    (username, public_key_hex.lower(), kdf.lower(), time.time()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_user(self, username: str) -> Optional[Dict[str, str]]:
        with self._ro() as conn:
            row = conn.execute(
                "SELECT username, public_key_hex, kdf, created_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> List[Dict[str, str]]:
        with self._ro() as conn:
            rows = conn.execute(
                "SELECT username, public_key_hex, kdf, created_at FROM users ORDER BY username"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- challenges --------------------------------------------------------------
    def store_challenge(self, username: str, commitment_hex: str, challenge_hex: str, ttl: float = CHALLENGE_TTL_SECONDS) -> float:
        """Store a fresh single-use challenge (replacing any pending one)."""
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO challenges(username, commitment_hex, challenge_hex, issued_at, expires_at) "
                "VALUES (?,?,?,?,?)",
                (username, commitment_hex.lower(), challenge_hex.lower(), now, now + ttl),
            )
        return now + ttl

    def consume_challenge(self, username: str) -> Optional[Dict[str, str]]:
        """Atomically read and delete the pending challenge for ``username``.

        Returns None when no live challenge exists. Expiry is enforced here
        (defence in depth — the API double-checks as well).
        """
        now = time.time()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT commitment_hex, challenge_hex, issued_at, expires_at FROM challenges WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM challenges WHERE username = ?", (username,))
            if row["expires_at"] < now:
                return None
            return dict(row)

    def purge_expired(self) -> int:
        """Delete expired challenges and sessions; returns rows removed."""
        now = time.time()
        with self._tx() as conn:
            c1 = conn.execute("DELETE FROM challenges WHERE expires_at < ?", (now,)).rowcount
            c2 = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,)).rowcount
        return c1 + c2

    # -- sessions -----------------------------------------------------------------
    def create_session(self, username: str, ttl: float = SESSION_TTL_SECONDS) -> Dict[str, object]:
        """Mint a bearer token; only its SHA-256 hash is persisted."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO sessions(token_hash, username, created_at, expires_at) VALUES (?,?,?,?)",
                (_hash_token(token), username, now, now + ttl),
            )
        return {"token": token, "token_type": "bearer", "expires_in": int(ttl), "created_at": now}

    def lookup_session(self, token: str) -> Optional[Dict[str, object]]:
        """Return session metadata for a live token, else None (expired rows are deleted)."""
        if not token:
            return None
        now = time.time()
        token_hash = _hash_token(token)
        with self._tx() as conn:
            row = conn.execute(
                "SELECT username, created_at, expires_at FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] < now:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
            return {"username": row["username"], "created_at": row["created_at"], "expires_at": row["expires_at"]}

    def revoke_session(self, token: str) -> bool:
        with self._tx() as conn:
            return conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),)).rowcount > 0
