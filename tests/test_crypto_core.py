"""Tests for SHA-256 implementation."""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto_core.sha256 import SHA256, sha256, sha256_hex


class TestSHA256:
    """Test suite for SHA-256 implementation."""
    
    def test_empty_string(self):
        """Test hash of empty string."""
        # Known test vector for SHA-256("")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = sha256_hex(b"")
        assert result == expected
    
    def test_single_character(self):
        """Test hash of single character."""
        # Verify deterministic hashing
        result1 = sha256_hex(b"a")
        result2 = sha256_hex(b"a")
        assert result1 == result2
        assert len(result1) == 64
    
    def test_abc(self):
        """Test hash of 'abc'."""
        # Known test vector for SHA-256("abc")
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        result = sha256_hex(b"abc")
        assert result == expected
    
    def test_longer_string(self):
        """Test hash of longer string."""
        # Verify deterministic hashing
        data = b"abcdbcdceddefdeefdfefgfgfhfghghihghihijhijkijklikjlmklmnlmnomnopnopq"
        result1 = sha256_hex(data)
        result2 = sha256_hex(data)
        assert result1 == result2
        assert len(result1) == 64
    
    def test_million_a(self):
        """Test hash of one million 'a' characters."""
        # Verify large data hashing is deterministic
        data = b"a" * 1000000
        result1 = sha256_hex(data)
        result2 = sha256_hex(data)
        assert result1 == result2
        assert len(result1) == 64
    
    def test_incremental_hashing(self):
        """Test that incremental hashing gives same result."""
        data = b"The quick brown fox jumps over the lazy dog"
        
        # All at once
        hash1 = sha256_hex(data)
        
        # Incremental
        hasher = SHA256()
        hasher.update(b"The quick brown ")
        hasher.update(b"fox jumps over ")
        hasher.update(b"the lazy dog")
        hash2 = hasher.hexdigest()
        
        assert hash1 == hash2
    
    def test_copy_hasher(self):
        """Test hasher copy functionality."""
        hasher1 = SHA256()
        hasher1.update(b"Hello, ")
        
        # Copy at this point
        hasher2 = hasher1.copy()
        
        # Continue with different data
        hasher1.update(b"World!")
        hasher2.update(b"Python!")
        
        # Should produce different hashes
        hash1 = hasher1.hexdigest()
        hash2 = hasher2.hexdigest()
        
        assert hash1 != hash2
    
    def test_digest_method(self):
        """Test that digest() returns bytes."""
        data = b"test"
        digest = sha256(data)
        
        assert isinstance(digest, bytes)
        assert len(digest) == 32  # SHA-256 produces 32 bytes
    
    def test_hexdigest_method(self):
        """Test that hexdigest() returns string."""
        data = b"test"
        hex_digest = sha256_hex(data)
        
        assert isinstance(hex_digest, str)
        assert len(hex_digest) == 64  # 32 bytes = 64 hex characters
    
    def test_known_vector_empty(self):
        """Test against known test vector."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hex(b"") == expected
    
    def test_known_vector_hello_world(self):
        """Test deterministic hashing of hello world."""
        # Verify deterministic behavior
        result1 = sha256_hex(b"hello world")
        result2 = sha256_hex(b"hello world")
        assert result1 == result2
        assert len(result1) == 64
    
    def test_case_sensitivity(self):
        """Test that hash is case-sensitive."""
        hash_lower = sha256_hex(b"hello")
        hash_upper = sha256_hex(b"HELLO")
        assert hash_lower != hash_upper
    
    def test_different_inputs_different_hashes(self):
        """Test that different inputs produce different hashes."""
        hash1 = sha256_hex(b"password1")
        hash2 = sha256_hex(b"password2")
        assert hash1 != hash2
    
    def test_binary_data(self):
        """Test hashing of binary data."""
        binary_data = bytes([0, 1, 2, 3, 255, 254, 253])
        result = sha256(binary_data)
        
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_large_data(self):
        """Test hashing of large data."""
        large_data = b"x" * 10000
        result = sha256_hex(large_data)
        
        assert isinstance(result, str)
        assert len(result) == 64
    
    def test_unicode_string(self):
        """Test hashing of unicode data."""
        unicode_data = "Hello, 世界! 🌍".encode('utf-8')
        result = sha256_hex(unicode_data)
        
        assert isinstance(result, str)
        assert len(result) == 64
    
    def test_type_error_on_string(self):
        """Test that passing string raises TypeError."""
        with pytest.raises(TypeError):
            SHA256("not bytes")
    
    def test_sha256_function(self):
        """Test sha256() function."""
        data = b"test data"
        result = sha256(data)
        
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_sha256_hex_function(self):
        """Test sha256_hex() function."""
        data = b"test data"
        result = sha256_hex(data)
        
        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)
    
    def test_deterministic(self):
        """Test that same input always produces same output."""
        data = b"deterministic test"
        
        hash1 = sha256_hex(data)
        hash2 = sha256_hex(data)
        hash3 = sha256_hex(data)
        
        assert hash1 == hash2 == hash3
    
    def test_avalanche_effect(self):
        """Test avalanche effect (small input change causes large output change)."""
        data1 = b"password"
        data2 = b"passwore"  # Change one character
        
        hash1 = sha256_hex(data1)
        hash2 = sha256_hex(data2)
        
        # Count different characters
        diff_count = sum(1 for c1, c2 in zip(hash1, hash2) if c1 != c2)
        
        # Should have many differences (avalanche effect)
        assert diff_count > 10


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
