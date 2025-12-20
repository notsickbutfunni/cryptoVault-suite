"""
TOTP (Time-based One-Time Password) module for CryptoVault.
Implements RFC 6238 TOTP for multi-factor authentication.
"""

import pyotp
import qrcode
import io
import base64
from typing import Tuple, Optional
import json
import os


class TOTPManager:
    """Manages TOTP-based two-factor authentication."""
    
    def __init__(self, user_database_path: str = "users.json"):
        """
        Initialize TOTPManager.
        
        Args:
            user_database_path: Path to user database
        """
        self.user_database_path = user_database_path
        self.users = self._load_users()
    
    def _load_users(self) -> dict:
        """Load user database."""
        if os.path.exists(self.user_database_path):
            try:
                with open(self.user_database_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            except (json.JSONDecodeError, IOError):
                pass
        return {}
    
    def _save_users(self) -> None:
        """Save user database."""
        with open(self.user_database_path, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def generate_secret(self, username: str) -> Tuple[str, str]:
        """
        Generate TOTP secret for user.
        
        Args:
            username: Username
            
        Returns:
            Tuple of (secret, provisioning_uri)
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name='CryptoVault'
        )
        return secret, provisioning_uri
    
    def get_qr_code(self, provisioning_uri: str) -> str:
        """
        Generate QR code for TOTP setup.
        
        Args:
            provisioning_uri: TOTP provisioning URI
            
        Returns:
            Base64 encoded PNG image
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return img_str
    
    def enable_totp(self, username: str, secret: str) -> Tuple[bool, str]:
        """
        Enable TOTP for user.
        
        Args:
            username: Username
            secret: TOTP secret
            
        Returns:
            Tuple of (success, message)
        """
        if username not in self.users:
            return False, "User not found"
        
        self.users[username]['totp_secret'] = secret
        self.users[username]['totp_enabled'] = True
        self.users[username]['backup_codes'] = self._generate_backup_codes()
        self._save_users()
        
        return True, "TOTP enabled successfully"
    
    def disable_totp(self, username: str) -> Tuple[bool, str]:
        """
        Disable TOTP for user.
        
        Args:
            username: Username
            
        Returns:
            Tuple of (success, message)
        """
        if username not in self.users:
            return False, "User not found"
        
        self.users[username]['totp_enabled'] = False
        self.users[username]['totp_secret'] = None
        self.users[username]['backup_codes'] = []
        self._save_users()
        
        return True, "TOTP disabled successfully"
    
    def verify_totp(self, username: str, token: str, window: int = 1) -> Tuple[bool, str]:
        """
        Verify TOTP token from user.
        
        Args:
            username: Username
            token: 6-digit TOTP token
            window: Time window for verification (±time_step)
            
        Returns:
            Tuple of (valid, message)
        """
        if username not in self.users:
            return False, "User not found"
        
        user_data = self.users[username]
        
        if not user_data.get('totp_enabled'):
            return False, "TOTP not enabled for this user"
        
        secret = user_data.get('totp_secret')
        if not secret:
            return False, "TOTP secret not configured"
        
        totp = pyotp.TOTP(secret)
        
        # Verify with time window (±window * 30 seconds)
        is_valid = totp.verify(token, valid_window=window)
        
        if is_valid:
            return True, "TOTP verified successfully"
        else:
            return False, "Invalid TOTP token"
    
    def verify_backup_code(self, username: str, code: str) -> Tuple[bool, str]:
        """
        Verify and consume backup code.
        
        Args:
            username: Username
            code: Backup code
            
        Returns:
            Tuple of (valid, message)
        """
        if username not in self.users:
            return False, "User not found"
        
        user_data = self.users[username]
        backup_codes = user_data.get('backup_codes', [])
        
        if code in backup_codes:
            # Remove used backup code
            backup_codes.remove(code)
            self._save_users()
            return True, "Backup code verified and consumed"
        
        return False, "Invalid or already used backup code"
    
    @staticmethod
    def _generate_backup_codes(count: int = 10) -> list:
        """
        Generate backup codes for emergency access.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        import secrets
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8 character hex string
            codes.append(code)
        return codes
    
    def get_backup_codes(self, username: str) -> Tuple[bool, list]:
        """
        Get remaining backup codes for user.
        
        Args:
            username: Username
            
        Returns:
            Tuple of (success, backup_codes)
        """
        if username not in self.users:
            return False, []
        
        codes = self.users[username].get('backup_codes', [])
        return True, codes