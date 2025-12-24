"""
Login module for CryptoVault authentication system.
Handles user authentication with secure password verification.

Updates:
- Default to Argon2id for password hashing, with PBKDF2 fallback support.
- Rate limiting and account lockout after repeated failures.
- Optional session token issuance via HMAC-SHA256.
"""

import hashlib
import hmac
import os
import time
from typing import Tuple, Dict, Optional
import json

from argon2.low_level import hash_secret, Type as Argon2Type
from argon2.low_level import verify_secret

from .session import SessionManager


class LoginManager:
    """Manages user login authentication with secure password hashing."""

    def __init__(self, user_database_path: str = "users.json"):
        """
        Initialize LoginManager with user database.

        Args:
            user_database_path: Path to store user credentials
        """
        self.user_database_path = user_database_path
        self.users = self._load_users()

    def _load_users(self) -> Dict:
        """Load user database from JSON file."""
        if os.path.exists(self.user_database_path):
            try:
                with open(self.user_database_path, "r") as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save_users(self) -> None:
        """Save user database to JSON file."""
        with open(self.user_database_path, "w") as f:
            json.dump(self.users, f, indent=2)

    def hash_password(
        self, password: str, salt: Optional[bytes] = None, scheme: str = "argon2id"
    ) -> Tuple[str, str]:
        """
        Hash password.

        Default: Argon2id with explicit salt.
        Fallback: PBKDF2-SHA256 when scheme="pbkdf2".

        Returns:
            Tuple of (hashed_password_encoded_or_hex, salt_hex)
        """
        if scheme == "argon2id":
            if salt is None:
                salt = os.urandom(16)
            encoded = hash_secret(
                password.encode("utf-8"),
                salt,
                time_cost=3,
                memory_cost=65536,  # 64 MiB
                parallelism=2,
                hash_len=32,
                type=Argon2Type.ID,
            )
            return encoded.decode("utf-8"), salt.hex()
        else:
            if salt is None:
                salt = os.urandom(32)
            hashed = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, 100000
            )
            return hashed.hex(), salt.hex()

    def verify_password(
        self, password: str, stored_hash: str, stored_salt: str, scheme: Optional[str] = None
    ) -> bool:
        """
        Verify password against stored hash.

        Supports Argon2id (auto-detected or via scheme) and PBKDF2.
        """
        try:
            if (scheme and scheme == "argon2id") or stored_hash.startswith("$argon2"):
                return bool(
                    verify_secret(
                        stored_hash.encode("utf-8"), password.encode("utf-8"), Argon2Type.ID
                    )
                )
        except Exception:
            return False

        # PBKDF2 fallback
        salt = bytes.fromhex(stored_salt)
        hashed, _ = self.hash_password(password, salt, scheme="pbkdf2")
        return hmac.compare_digest(hashed, stored_hash)

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate user with username and password.

        Args:
            username: Username
            password: Password

        Returns:
            Tuple of (success, message)
        """
        if username not in self.users:
            return False, "User not found"

        user_data = self.users[username]

        # Rate limiting / lockout check
        now = time.time()
        lockout_until = user_data.get("lockout_until")
        if lockout_until and now < lockout_until:
            return False, "Account temporarily locked. Try again later."

        # Verify password
        scheme = user_data.get("password_scheme")
        if not self.verify_password(
            password, user_data["password_hash"], user_data["salt"], scheme=scheme
        ):
            attempts = int(user_data.get("failed_attempts", 0)) + 1
            user_data["failed_attempts"] = attempts
            # Lockout after 5 failures for 15 minutes
            if attempts >= 5:
                user_data["lockout_until"] = now + 15 * 60
                user_data["failed_attempts"] = 0
            self._save_users()
            return False, "Invalid password"

        # Reset counters on success
        user_data["failed_attempts"] = 0
        user_data["lockout_until"] = None
        self._save_users()

        if not user_data.get("active", True):
            return False, "Account is inactive"

        return True, f"Welcome {username}!"

    def issue_session_token(self, username: str, ttl_seconds: int = 3600) -> str:
        """
        Generate and store an HMAC-SHA256 session token with expiry.
        Returns the token string.
        """
        sm = SessionManager()
        token = sm.create_session(username, ttl_seconds=ttl_seconds)
        return token

    def is_user_registered(self, username: str) -> bool:
        """Check if user is registered."""
        return username in self.users

    def update_last_login(self, username: str) -> None:
        """Update last login timestamp for user."""
        from datetime import datetime

        if username in self.users:
            self.users[username]["last_login"] = datetime.now().isoformat()
            self._save_users()
