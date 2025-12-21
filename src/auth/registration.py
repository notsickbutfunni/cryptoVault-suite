"""
Registration module for CryptoVault authentication system.
Handles user account creation with security validations.
"""

import re
import os
from typing import Tuple, Dict
import json
from .login import LoginManager


class RegistrationManager:
    """Manages user account registration with validation."""

    PASSWORD_MIN_LENGTH = 12
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 32

    def __init__(self, user_database_path: str = "users.json"):
        """
        Initialize RegistrationManager.

        Args:
            user_database_path: Path to user database
        """
        self.login_manager = LoginManager(user_database_path)
        self.user_database_path = user_database_path

    def validate_username(self, username: str) -> Tuple[bool, str]:
        """
        Validate username format.

        Args:
            username: Username to validate

        Returns:
            Tuple of (valid, message)
        """
        if len(username) < self.USERNAME_MIN_LENGTH:
            return (
                False,
                f"Username must be at least {self.USERNAME_MIN_LENGTH} characters",
            )

        if len(username) > self.USERNAME_MAX_LENGTH:
            return (
                False,
                f"Username must be at most {self.USERNAME_MAX_LENGTH} characters",
            )

        if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            return (
                False,
                "Username can only contain letters, numbers, underscores, dots, and hyphens",
            )

        if self.login_manager.is_user_registered(username):
            return False, "Username already exists"

        return True, "Username is valid"

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength.

        Args:
            password: Password to validate

        Returns:
            Tuple of (valid, message)
        """
        if len(password) < self.PASSWORD_MIN_LENGTH:
            return (
                False,
                f"Password must be at least {self.PASSWORD_MIN_LENGTH} characters",
            )

        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"[0-9]", password))
        has_special = bool(
            re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password)
        )

        if not (has_upper and has_lower and has_digit and has_special):
            return False, (
                "Password must contain uppercase, lowercase, digit, and special character. "
                f"Current: upper={has_upper}, lower={has_lower}, digit={has_digit}, special={has_special}"
            )

        return True, "Password is strong"

    def register(
        self, username: str, password: str, email: str = ""
    ) -> Tuple[bool, str]:
        """
        Register new user account.

        Args:
            username: Desired username
            password: Password
            email: Optional email address

        Returns:
            Tuple of (success, message)
        """
        # Validate username
        valid, msg = self.validate_username(username)
        if not valid:
            return False, msg

        # Validate password
        valid, msg = self.validate_password(password)
        if not valid:
            return False, msg

        # Hash password
        password_hash, salt = self.login_manager.hash_password(password)

        # Create user record
        from datetime import datetime

        user_data = {
            "username": username,
            "password_hash": password_hash,
            "salt": salt,
            "email": email,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "totp_enabled": False,
            "totp_secret": None,
            "backup_codes": [],
        }

        self.login_manager.users[username] = user_data
        self.login_manager._save_users()

        return True, f"User '{username}' registered successfully"

    def delete_account(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Delete user account (requires password verification).

        Args:
            username: Username
            password: Password for verification

        Returns:
            Tuple of (success, message)
        """
        success, msg = self.login_manager.login(username, password)
        if not success:
            return False, "Cannot delete: authentication failed"

        del self.login_manager.users[username]
        self.login_manager._save_users()
        return True, "Account deleted successfully"
