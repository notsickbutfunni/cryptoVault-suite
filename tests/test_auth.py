"""
Comprehensive tests for CryptoVault authentication system.
Tests LoginManager, RegistrationManager, and TOTPManager.
"""

import pytest
import os
import json
import tempfile
from datetime import datetime
import sys

# NEW:
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.auth.login import LoginManager
from src.auth.registration import RegistrationManager
from src.auth.totp import TOTPManager


class TestLoginManager:
    """Test suite for LoginManager."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.remove(path)
    
    @pytest.fixture
    def login_manager(self, temp_db):
        """Create LoginManager instance with temp database."""
        return LoginManager(temp_db)
    
    def test_hash_password_creates_unique_hashes(self, login_manager):
        """Test that same password produces different hashes with different salts."""
        password = "TestPassword123!@#"
        hash1, salt1 = login_manager.hash_password(password)
        hash2, salt2 = login_manager.hash_password(password)
        
        # Different salts should produce different hashes
        assert salt1 != salt2
        assert hash1 != hash2
    
    def test_verify_password_success(self, login_manager):
        """Test successful password verification."""
        password = "SecurePass123!@#"
        password_hash, salt = login_manager.hash_password(password)
        
        # Verify correct password
        assert login_manager.verify_password(password, password_hash, salt)
    
    def test_verify_password_failure(self, login_manager):
        """Test failed password verification."""
        password = "SecurePass123!@#"
        wrong_password = "WrongPass123!@#"
        password_hash, salt = login_manager.hash_password(password)
        
        # Verify wrong password fails
        assert not login_manager.verify_password(wrong_password, password_hash, salt)
    
    def test_user_not_found(self, login_manager):
        """Test login with non-existent user."""
        success, message = login_manager.login("nonexistent", "password123")
        assert not success
        assert "not found" in message.lower()
    
    def test_is_user_registered(self, login_manager):
        """Test user registration check."""
        # Add user manually
        password_hash, salt = login_manager.hash_password("Test123!@#")
        login_manager.users['testuser'] = {
            'password_hash': password_hash,
            'salt': salt,
            'active': True
        }
        
        assert login_manager.is_user_registered('testuser')
        assert not login_manager.is_user_registered('unknown')


class TestRegistrationManager:
    """Test suite for RegistrationManager."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.remove(path)
    
    @pytest.fixture
    def reg_manager(self, temp_db):
        """Create RegistrationManager instance."""
        return RegistrationManager(temp_db)
    
    def test_validate_username_valid(self, reg_manager):
        """Test valid username validation."""
        valid, msg = reg_manager.validate_username("john_doe")
        assert valid
        assert "valid" in msg.lower()
    
    def test_validate_username_too_short(self, reg_manager):
        """Test username too short."""
        valid, msg = reg_manager.validate_username("ab")
        assert not valid
        assert "at least" in msg.lower()
    
    def test_validate_username_too_long(self, reg_manager):
        """Test username too long."""
        valid, msg = reg_manager.validate_username("a" * 50)
        assert not valid
        assert "at most" in msg.lower()
    
    def test_validate_username_invalid_characters(self, reg_manager):
        """Test username with invalid characters."""
        valid, msg = reg_manager.validate_username("user@name!")
        assert not valid
        assert "can only contain" in msg.lower()
    
    def test_validate_username_already_exists(self, reg_manager):
        """Test validation fails if username exists."""
        # Register first user
        reg_manager.register("john_doe", "SecurePass123!@#")
        
        # Try to register with same username
        valid, msg = reg_manager.validate_username("john_doe")
        assert not valid
        assert "already exists" in msg.lower()
    
    def test_validate_password_too_short(self, reg_manager):
        """Test password too short."""
        valid, msg = reg_manager.validate_password("Short1!@")
        assert not valid
        assert "at least" in msg.lower()
    
    def test_validate_password_missing_uppercase(self, reg_manager):
        """Test password missing uppercase."""
        valid, msg = reg_manager.validate_password("secure1!@#pass")
        assert not valid
        assert "uppercase" in msg.lower()
    
    def test_validate_password_missing_lowercase(self, reg_manager):
        """Test password missing lowercase."""
        valid, msg = reg_manager.validate_password("SECURE1!@#PASS")
        assert not valid
        assert "lowercase" in msg.lower()
    
    def test_validate_password_missing_digit(self, reg_manager):
        """Test password missing digit."""
        valid, msg = reg_manager.validate_password("SecurePass!@#")
        assert not valid
        assert "digit" in msg.lower()
    
    def test_validate_password_missing_special(self, reg_manager):
        """Test password missing special character."""
        valid, msg = reg_manager.validate_password("SecurePass123")
        assert not valid
        assert "special" in msg.lower()
    
    def test_validate_password_strong(self, reg_manager):
        """Test strong password validation."""
        valid, msg = reg_manager.validate_password("SecurePass123!@#")
        assert valid
        assert "strong" in msg.lower()
    
    def test_register_success(self, reg_manager):
        """Test successful user registration."""
        success, msg = reg_manager.register(
            "john_doe",
            "SecurePass123!@#",
            "john@example.com"
        )
        assert success
        assert "successfully" in msg.lower()
    
    def test_register_weak_password(self, reg_manager):
        """Test registration with weak password."""
        success, msg = reg_manager.register(
            "john_doe",
            "weak"
        )
        assert not success
    
    def test_register_invalid_username(self, reg_manager):
        """Test registration with invalid username."""
        success, msg = reg_manager.register(
            "ab",  # Too short
            "SecurePass123!@#"
        )
        assert not success
    
    def test_delete_account_success(self, reg_manager):
        """Test successful account deletion."""
        # Register user
        reg_manager.register("john_doe", "SecurePass123!@#")
        
        # Delete account
        success, msg = reg_manager.delete_account("john_doe", "SecurePass123!@#")
        assert success
        
        # Verify user is deleted
        assert not reg_manager.login_manager.is_user_registered("john_doe")
    
    def test_delete_account_wrong_password(self, reg_manager):
        """Test account deletion with wrong password."""
        # Register user
        reg_manager.register("john_doe", "SecurePass123!@#")
        
        # Try to delete with wrong password
        success, msg = reg_manager.delete_account("john_doe", "WrongPass123!@#")
        assert not success
        
        # Verify user still exists
        assert reg_manager.login_manager.is_user_registered("john_doe")


class TestTOTPManager:
    """Test suite for TOTPManager."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.remove(path)
    
    @pytest.fixture
    def totp_manager(self, temp_db):
        """Create TOTPManager instance."""
        return TOTPManager(temp_db)
    
    @pytest.fixture
    def setup_user(self, totp_manager):
        """Set up a test user."""
        totp_manager.users['testuser'] = {
            'username': 'testuser',
            'totp_enabled': False,
            'totp_secret': None,
            'backup_codes': []
        }
        totp_manager._save_users()
        return 'testuser'
    
    def test_generate_secret(self, totp_manager):
        """Test TOTP secret generation."""
        secret, uri = totp_manager.generate_secret("testuser")
        
        # Verify secret is base32 encoded
        assert len(secret) > 0
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret)
        
        # Verify provisioning URI
        assert 'otpauth://' in uri
        assert 'testuser' in uri
        assert 'CryptoVault' in uri
    
    def test_get_qr_code(self, totp_manager):
        """Test QR code generation."""
        secret, uri = totp_manager.generate_secret("testuser")
        qr_code = totp_manager.get_qr_code(uri)
        
        # Verify base64 encoded
        assert len(qr_code) > 0
        assert qr_code.startswith(('iVBOR', 'iVBORw')) or len(qr_code) > 100  # PNG magic bytes in base64
    
    def test_enable_totp(self, totp_manager, setup_user):
        """Test enabling TOTP for user."""
        secret, _ = totp_manager.generate_secret(setup_user)
        success, msg = totp_manager.enable_totp(setup_user, secret)
        
        assert success
        assert totp_manager.users[setup_user]['totp_enabled']
        assert totp_manager.users[setup_user]['totp_secret'] == secret
        assert len(totp_manager.users[setup_user]['backup_codes']) == 10
    
    def test_disable_totp(self, totp_manager, setup_user):
        """Test disabling TOTP for user."""
        # Enable first
        secret, _ = totp_manager.generate_secret(setup_user)
        totp_manager.enable_totp(setup_user, secret)
        
        # Disable
        success, msg = totp_manager.disable_totp(setup_user)
        assert success
        assert not totp_manager.users[setup_user]['totp_enabled']
        assert totp_manager.users[setup_user]['totp_secret'] is None
    
    def test_verify_totp_not_enabled(self, totp_manager, setup_user):
        """Test TOTP verification when not enabled."""
        valid, msg = totp_manager.verify_totp(setup_user, "123456")
        assert not valid
        assert "not enabled" in msg.lower()
    
    def test_verify_totp_valid(self, totp_manager, setup_user):
        """Test valid TOTP verification."""
        import pyotp
        
        # Enable TOTP with known secret
        secret = "JBSWY3DPEBLW64TMMQ======"  # Fixed secret for testing
        totp_manager.enable_totp(setup_user, secret)
        
        # Generate valid token
        totp = pyotp.TOTP(secret)
        token = totp.now()
        
        # Verify
        valid, msg = totp_manager.verify_totp(setup_user, token)
        assert valid
        assert "verified" in msg.lower()
    
    def test_verify_totp_invalid(self, totp_manager, setup_user):
        """Test invalid TOTP verification."""
        secret = "JBSWY3DPEBLW64TMMQ======"
        totp_manager.enable_totp(setup_user, secret)
        
        # Invalid token
        valid, msg = totp_manager.verify_totp(setup_user, "000000")
        assert not valid
        assert "invalid" in msg.lower()
    
    def test_backup_codes_generation(self, totp_manager, setup_user):
        """Test backup codes are generated."""
        secret, _ = totp_manager.generate_secret(setup_user)
        totp_manager.enable_totp(setup_user, secret)
        
        codes = totp_manager.users[setup_user]['backup_codes']
        assert len(codes) == 10
        assert all(len(code) == 8 for code in codes)  # 8 character hex codes
    
    def test_verify_backup_code(self, totp_manager, setup_user):
        """Test backup code verification."""
        secret, _ = totp_manager.generate_secret(setup_user)
        totp_manager.enable_totp(setup_user, secret)
        
        backup_codes = totp_manager.users[setup_user]['backup_codes']
        code = backup_codes[0]
        
        # Verify backup code
        valid, msg = totp_manager.verify_backup_code(setup_user, code)
        assert valid
        
        # Verify code is consumed
        assert code not in totp_manager.users[setup_user]['backup_codes']
        assert len(totp_manager.users[setup_user]['backup_codes']) == 9
    
    def test_verify_invalid_backup_code(self, totp_manager, setup_user):
        """Test invalid backup code verification."""
        secret, _ = totp_manager.generate_secret(setup_user)
        totp_manager.enable_totp(setup_user, secret)
        
        valid, msg = totp_manager.verify_backup_code(setup_user, "FFFFFFFF")
        assert not valid
        assert "invalid" in msg.lower()
    
    def test_get_backup_codes(self, totp_manager, setup_user):
        """Test retrieving backup codes."""
        secret, _ = totp_manager.generate_secret(setup_user)
        totp_manager.enable_totp(setup_user, secret)
        
        success, codes = totp_manager.get_backup_codes(setup_user)
        assert success
        assert len(codes) == 10


class TestAuthenticationIntegration:
    """Integration tests for complete authentication flow."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.remove(path)
    
    def test_complete_user_lifecycle(self, temp_db):
        """Test complete user creation, login, and 2FA setup."""
        # Register
        reg = RegistrationManager(temp_db)
        success, msg = reg.register("alice", "SecurePass123!@#", "alice@example.com")
        assert success
        
        # Login without 2FA
        login = LoginManager(temp_db)
        success, msg = login.login("alice", "SecurePass123!@#")
        assert success
        
        # Enable TOTP
        totp = TOTPManager(temp_db)
        secret, uri = totp.generate_secret("alice")
        success, msg = totp.enable_totp("alice", secret)
        assert success
        
        # Verify TOTP works
        import pyotp
        token = pyotp.TOTP(secret).now()
        valid, msg = totp.verify_totp("alice", token)
        assert valid


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])