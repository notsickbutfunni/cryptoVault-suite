"""
Login module for CryptoVault authentication system.
Handles user authentication with secure password verification.
"""

import hashlib
import hmac
import os
from typing import Tuple, Dict, Optional
import json


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
        self, password: str, salt: Optional[bytes] = None
    ) -> Tuple[str, str]:
        """
        Hash password using PBKDF2 with SHA-256.

        Args:
            password: Plain text password
            salt: Optional salt (generates random if None)

        Returns:
            Tuple of (hashed_password_hex, salt_hex)
        """
        if salt is None:
            salt = os.urandom(32)

        # PBKDF2 with 100,000 iterations
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hashed.hex(), salt.hex()

    def verify_password(
        self, password: str, stored_hash: str, stored_salt: str
    ) -> bool:
        """
        Verify password against stored hash.

        Args:
            password: Password to verify
            stored_hash: Stored password hash
            stored_salt: Stored salt

        Returns:
            True if password matches, False otherwise
        """
        salt = bytes.fromhex(stored_salt)
        hashed, _ = self.hash_password(password, salt)
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

        if not self.verify_password(
            password, user_data["password_hash"], user_data["salt"]
        ):
            return False, "Invalid password"

        if not user_data.get("active", True):
            return False, "Account is inactive"

        return True, f"Welcome {username}!"

    def is_user_registered(self, username: str) -> bool:
        """Check if user is registered."""
        return username in self.users

    def update_last_login(self, username: str) -> None:
        """Update last login timestamp for user."""
        from datetime import datetime

        if username in self.users:
            self.users[username]["last_login"] = datetime.now().isoformat()
            self._save_users()
