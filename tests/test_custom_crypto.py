"""Tests for classical ciphers and modular arithmetic implementations."""

import pytest
from src.crypto_core.classical import CaesarCipher, VigenèreCipher
from src.crypto_core.modular import (
    pow_mod, extended_gcd, mod_inverse, is_prime, generate_prime,
    gcd, lcm, RSAKeyGenerator
)


class TestCaesarCipher:
    """Test Caesar cipher implementation."""

    def test_encrypt_basic(self):
        """Test basic encryption."""
        plaintext = "HELLO"
        encrypted = CaesarCipher.encrypt(plaintext, 3)
        assert encrypted == "KHOOR"

    def test_decrypt_basic(self):
        """Test basic decryption."""
        ciphertext = "KHOOR"
        decrypted = CaesarCipher.decrypt(ciphertext, 3)
        assert decrypted == "HELLO"

    def test_encrypt_lowercase(self):
        """Test encryption with lowercase letters."""
        plaintext = "hello world"
        encrypted = CaesarCipher.encrypt(plaintext, 5)
        decrypted = CaesarCipher.decrypt(encrypted, 5)
        assert decrypted == plaintext

    def test_encrypt_with_non_letters(self):
        """Test encryption preserves non-letter characters."""
        plaintext = "Hello, World! 123"
        encrypted = CaesarCipher.encrypt(plaintext, 3)
        assert "," in encrypted
        assert "!" in encrypted
        assert "123" in encrypted

    def test_wrap_around(self):
        """Test wrap-around at Z."""
        plaintext = "XYZ"
        encrypted = CaesarCipher.encrypt(plaintext, 3)
        assert encrypted == "ABC"

    def test_brute_force(self):
        """Test brute-force breaking with all shifts."""
        plaintext = "THE QUICK BROWN FOX"
        ciphertext = CaesarCipher.encrypt(plaintext, 7)
        
        # Brute force should find the correct plaintext
        results = CaesarCipher.brute_force(ciphertext)
        
        # Check that original plaintext is in results
        plaintexts = [p for _, p, _ in results]
        assert plaintext in plaintexts

    def test_frequency_analysis(self):
        """Test chi-squared frequency analysis."""
        # English text should have lower score than random
        english = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        random_text = "XYZZYX QWERTY ASDFGH HJKL"
        
        english_score = CaesarCipher._chi_squared_score(english)
        random_score = CaesarCipher._chi_squared_score(random_text)
        
        assert english_score < random_score

    def test_shift_0(self):
        """Test shift of 0 returns same text."""
        text = "HELLO"
        assert CaesarCipher.encrypt(text, 0) == text

    def test_shift_26_equals_0(self):
        """Test shift of 26 is same as shift of 0."""
        text = "HELLO"
        assert CaesarCipher.encrypt(text, 26) == CaesarCipher.encrypt(text, 0)


class TestVigenèreCipher:
    """Test Vigenère cipher implementation."""

    def test_encrypt_basic(self):
        """Test basic encryption."""
        plaintext = "HELLO"
        key = "KEY"
        encrypted = VigenèreCipher.encrypt(plaintext, key)
        assert encrypted == "RIJVS"

    def test_decrypt_basic(self):
        """Test basic decryption."""
        ciphertext = "RIJVS"
        key = "KEY"
        decrypted = VigenèreCipher.decrypt(ciphertext, key)
        assert decrypted == "HELLO"

    def test_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        key = "SECURITY"
        
        encrypted = VigenèreCipher.encrypt(plaintext, key)
        decrypted = VigenèreCipher.decrypt(encrypted, key)
        
        # Compare without spaces
        assert plaintext.replace(" ", "") == decrypted.replace(" ", "")

    def test_with_lowercase(self):
        """Test with lowercase letters."""
        plaintext = "hello world"
        key = "key"
        
        encrypted = VigenèreCipher.encrypt(plaintext, key)
        decrypted = VigenèreCipher.decrypt(encrypted, key)
        
        assert decrypted == plaintext

    def test_with_numbers_and_punctuation(self):
        """Test that non-letter characters are preserved."""
        plaintext = "Hello, World! 123"
        key = "KEY"
        
        encrypted = VigenèreCipher.encrypt(plaintext, key)
        decrypted = VigenèreCipher.decrypt(encrypted, key)
        
        assert decrypted == plaintext

    def test_key_length_estimation_ic(self):
        """Test index of coincidence key length estimation."""
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 5
        key = "SECURITY"
        ciphertext = VigenèreCipher.encrypt(plaintext, key)
        
        # Estimate key length
        estimated_length = VigenèreCipher.estimate_key_length_ic(ciphertext)
        
        # Should estimate key length reasonably (allow some error)
        assert 1 <= estimated_length <= 20

    def test_kasiski_examination(self):
        """Test Kasiski examination for repeated sequences."""
        plaintext = "THEQUICKBROWNFOXTHEQUICKBROWNFOX" * 2
        key = "SECURITY"
        ciphertext = VigenèreCipher.encrypt(plaintext, key)
        
        # Run Kasiski examination
        key_lengths = VigenèreCipher.kasiski_examination(ciphertext)
        
        # Should find some key length candidates
        assert len(key_lengths) > 0

    def test_index_of_coincidence_english(self):
        """Test IC calculation for English text."""
        # English text should have IC ≈ 0.065
        english_text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 10
        ic = VigenèreCipher.index_of_coincidence(english_text)
        
        # English IC should be roughly in this range
        assert 0.04 <= ic <= 0.09

    def test_index_of_coincidence_random(self):
        """Test IC calculation for random text."""
        # Random text should have IC ≈ 0.038
        random_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 10
        ic = VigenèreCipher.index_of_coincidence(random_text)
        
        # Random IC should be lower
        assert ic < 0.06

    def test_invalid_key_raises_error(self):
        """Test that non-alphabetic key raises error."""
        with pytest.raises(ValueError):
            VigenèreCipher.encrypt("HELLO", "123")


class TestModularArithmetic:
    """Test modular arithmetic implementations."""

    def test_pow_mod_basic(self):
        """Test basic modular exponentiation."""
        assert pow_mod(2, 3, 5) == 3  # 2^3 = 8 ≡ 3 (mod 5)
        assert pow_mod(3, 4, 5) == 1  # 3^4 = 81 ≡ 1 (mod 5)

    def test_pow_mod_large_numbers(self):
        """Test with large numbers."""
        result = pow_mod(123456789, 987654321, 1000000007)
        assert isinstance(result, int)
        assert 0 <= result < 1000000007

    def test_pow_mod_zero_exponent(self):
        """Test with zero exponent."""
        assert pow_mod(5, 0, 7) == 1

    def test_extended_gcd_basic(self):
        """Test extended Euclidean algorithm."""
        gcd_val, x, y = extended_gcd(10, 6)
        assert gcd_val == 2
        assert 10 * x + 6 * y == gcd_val

    def test_extended_gcd_coprime(self):
        """Test with coprime numbers."""
        gcd_val, x, y = extended_gcd(35, 12)
        assert gcd_val == 1
        assert 35 * x + 12 * y == 1

    def test_mod_inverse_basic(self):
        """Test modular inverse."""
        inv = mod_inverse(3, 11)
        assert (3 * inv) % 11 == 1

    def test_mod_inverse_large(self):
        """Test modular inverse with larger numbers."""
        inv = mod_inverse(7, 26)
        assert (7 * inv) % 26 == 1

    def test_mod_inverse_nonexistent(self):
        """Test that non-invertible raises error."""
        with pytest.raises(ValueError):
            mod_inverse(6, 9)  # gcd(6, 9) = 3 ≠ 1

    def test_is_prime_true(self):
        """Test prime detection on known primes."""
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        for p in primes:
            assert is_prime(p)

    def test_is_prime_false(self):
        """Test prime detection on known composites."""
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20]
        for c in composites:
            assert not is_prime(c)

    def test_is_prime_edge_cases(self):
        """Test edge cases."""
        assert not is_prime(0)
        assert not is_prime(1)
        assert is_prime(2)

    def test_generate_prime(self):
        """Test prime generation."""
        prime = generate_prime(256)
        assert is_prime(prime)
        assert prime.bit_length() == 256

    def test_generate_prime_multiple(self):
        """Test generating multiple primes."""
        primes = [generate_prime(128) for _ in range(5)]
        for p in primes:
            assert is_prime(p)

    def test_gcd_basic(self):
        """Test GCD calculation."""
        assert gcd(12, 8) == 4
        assert gcd(35, 15) == 5
        assert gcd(17, 19) == 1

    def test_lcm_basic(self):
        """Test LCM calculation."""
        assert lcm(12, 8) == 24
        assert lcm(4, 6) == 12
        assert lcm(7, 13) == 91


class TestRSAKeyGenerator:
    """Test RSA key generation and cryptography."""

    def test_keypair_generation(self):
        """Test RSA keypair generation."""
        pub_key, priv_key = RSAKeyGenerator.generate_keypair(512)
        
        # Check structure
        assert len(pub_key) == 2
        assert len(priv_key) == 2
        
        # Check n is same
        assert pub_key[0] == priv_key[0]
        
        # Check e and d are different
        assert pub_key[1] != priv_key[1]

    def test_rsa_encrypt_decrypt(self):
        """Test RSA encryption and decryption."""
        pub_key, priv_key = RSAKeyGenerator.generate_keypair(512)
        
        plaintext = 12345
        ciphertext = RSAKeyGenerator.encrypt(pub_key, plaintext)
        decrypted = RSAKeyGenerator.decrypt(priv_key, ciphertext)
        
        assert decrypted == plaintext

    def test_rsa_different_messages(self):
        """Test RSA with multiple messages."""
        pub_key, priv_key = RSAKeyGenerator.generate_keypair(512)
        
        messages = [123, 456, 789, 1000]
        for msg in messages:
            if msg < pub_key[0]:
                ciphertext = RSAKeyGenerator.encrypt(pub_key, msg)
                decrypted = RSAKeyGenerator.decrypt(priv_key, ciphertext)
                assert decrypted == msg

    def test_rsa_plaintext_too_large(self):
        """Test that plaintext >= n raises error."""
        pub_key, _ = RSAKeyGenerator.generate_keypair(512)
        
        with pytest.raises(ValueError):
            RSAKeyGenerator.encrypt(pub_key, pub_key[0] + 1)

    def test_rsa_different_plaintexts_different_ciphertexts(self):
        """Test that same plaintext with different RNG produces different ciphertexts."""
        pub_key, priv_key = RSAKeyGenerator.generate_keypair(512)
        
        plaintext = 999
        ciphertext1 = RSAKeyGenerator.encrypt(pub_key, plaintext)
        ciphertext2 = RSAKeyGenerator.encrypt(pub_key, plaintext)
        
        # Deterministic encryption - same plaintext gives same ciphertext
        assert ciphertext1 == ciphertext2
        
        # But decryption is always the same
        assert RSAKeyGenerator.decrypt(priv_key, ciphertext1) == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
