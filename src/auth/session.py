"""
Session management for CryptoVault authentication.

Generates HMAC-SHA256 session tokens with expiry and stores
hashed tokens on disk for validation and revocation.
"""

import os
import time
import hmac
import hashlib
import json
from pathlib import Path
from typing import Optional


SECRET_PATH = Path("keys") / "session_secret.bin"
SESSIONS_PATH = Path("keystore") / "sessions.json"


class SessionManager:
    def __init__(self, secret_path: Path = SECRET_PATH, store_path: Path = SESSIONS_PATH):
        self.secret_path = secret_path
        self.store_path = store_path
        self.secret = self._load_or_create_secret()
        self.sessions = self._load_sessions()

    def _load_or_create_secret(self) -> bytes:
        self.secret_path.parent.mkdir(parents=True, exist_ok=True)
        if self.secret_path.exists():
            return self.secret_path.read_bytes()
        secret = os.urandom(32)
        self.secret_path.write_bytes(secret)
        return secret

    def _load_sessions(self) -> dict:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        if self.store_path.exists():
            try:
                return json.loads(self.store_path.read_text())
            except Exception:
                return {}
        return {}

    def _save_sessions(self) -> None:
        self.store_path.write_text(json.dumps(self.sessions, indent=2, sort_keys=True))

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, username: str, ttl_seconds: int = 3600) -> str:
        ts = time.time()
        payload = f"{username}:{ts}:{os.urandom(8).hex()}".encode("utf-8")
        token = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        token_hash = self._hash_token(token)
        self.sessions[token_hash] = {
            "username": username,
            "issued_at": ts,
            "expires_at": ts + ttl_seconds,
            "revoked": False,
        }
        self._save_sessions()
        return token

    def validate(self, token: str) -> bool:
        token_hash = self._hash_token(token)
        entry = self.sessions.get(token_hash)
        if not entry:
            return False
        if entry.get("revoked"):
            return False
        if time.time() > entry.get("expires_at", 0):
            return False
        return True

    def revoke(self, token: str) -> None:
        token_hash = self._hash_token(token)
        if token_hash in self.sessions:
            self.sessions[token_hash]["revoked"] = True
            self._save_sessions()
