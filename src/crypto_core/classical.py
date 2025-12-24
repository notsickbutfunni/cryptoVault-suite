"""
Classical ciphers implemented from scratch.

Implements:
- Caesar cipher with frequency analysis breaker
- Vigenère cipher with Kasiski examination
"""

import string
from typing import Tuple, List, Dict
from collections import Counter


class CaesarCipher:
    """Caesar cipher with brute-force and frequency analysis breaking."""

    # English letter frequencies (percentage)
    ENGLISH_FREQUENCIES = {
        'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 13.0, 'f': 2.2,
        'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0,
        'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9, 'q': 0.10, 'r': 6.0,
        's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
        'y': 2.0, 'z': 0.07
    }

    @staticmethod
    def encrypt(plaintext: str, shift: int) -> str:
        """
        Encrypt plaintext using Caesar cipher.
        
        Args:
            plaintext: Text to encrypt
            shift: Shift amount (0-25)
        
        Returns:
            Encrypted text
        """
        result = []
        shift = shift % 26
        
        for char in plaintext:
            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            elif char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(char)
        
        return ''.join(result)

    @staticmethod
    def decrypt(ciphertext: str, shift: int) -> str:
        """
        Decrypt ciphertext using Caesar cipher.
        
        Args:
            ciphertext: Text to decrypt
            shift: Shift amount (0-25)
        
        Returns:
            Decrypted text
        """
        return CaesarCipher.encrypt(ciphertext, -shift)

    @staticmethod
    def brute_force(ciphertext: str) -> List[Tuple[int, str, float]]:
        """
        Brute-force all 26 possible Caesar shifts with frequency scoring.
        
        Args:
            ciphertext: Text to decrypt
        
        Returns:
            List of (shift, plaintext, score) tuples, sorted by score (best first)
        """
        results = []
        
        for shift in range(26):
            plaintext = CaesarCipher.decrypt(ciphertext, shift)
            score = CaesarCipher._chi_squared_score(plaintext)
            results.append((shift, plaintext, score))
        
        # Sort by score (lower = better match to English)
        results.sort(key=lambda x: x[2])
        return results

    @staticmethod
    def _chi_squared_score(text: str) -> float:
        """
        Calculate chi-squared statistic for text against English frequency.
        Lower score = better match to English language.
        
        Args:
            text: Text to analyze
        
        Returns:
            Chi-squared score (lower is better)
        """
        # Count letter frequencies in text
        text_clean = text.lower()
        letter_counts = Counter(c for c in text_clean if c.isalpha())
        text_len = sum(letter_counts.values())
        
        if text_len == 0:
            return float('inf')
        
        # Calculate chi-squared statistic
        chi_squared = 0.0
        for letter in string.ascii_lowercase:
            observed_freq = (letter_counts.get(letter, 0) / text_len) * 100
            expected_freq = CaesarCipher.ENGLISH_FREQUENCIES[letter]
            
            if expected_freq > 0:
                chi_squared += ((observed_freq - expected_freq) ** 2) / expected_freq
        
        return chi_squared


class VigenèreCipher:
    """Vigenère cipher with Kasiski examination for key length detection."""

    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt plaintext using Vigenère cipher.
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key (alphabetic)
        
        Returns:
            Encrypted text
        """
        if not key or not any(c.isalpha() for c in key):
            raise ValueError("Key must contain at least one letter")
        
        result = []
        key_upper = key.upper()
        key_index = 0
        
        for char in plaintext:
            if char.isupper():
                shift = ord(key_upper[key_index % len(key_upper)]) - ord('A')
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
                key_index += 1
            elif char.islower():
                shift = ord(key_upper[key_index % len(key_upper)]) - ord('A')
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)

    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        """
        Decrypt ciphertext using Vigenère cipher.
        
        Args:
            ciphertext: Text to decrypt
            key: Decryption key (alphabetic)
        
        Returns:
            Decrypted text
        """
        if not key or not any(c.isalpha() for c in key):
            raise ValueError("Key must contain at least one letter")
        
        result = []
        key_upper = key.upper()
        key_index = 0
        
        for char in ciphertext:
            if char.isupper():
                shift = ord(key_upper[key_index % len(key_upper)]) - ord('A')
                result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                key_index += 1
            elif char.islower():
                shift = ord(key_upper[key_index % len(key_upper)]) - ord('A')
                result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)

    @staticmethod
    def kasiski_examination(ciphertext: str, min_length: int = 3) -> Dict[int, int]:
        """
        Kasiski examination to estimate key length.
        Finds repeated sequences and analyzes spacing.
        
        Args:
            ciphertext: Text to analyze
            min_length: Minimum sequence length to consider
        
        Returns:
            Dictionary mapping possible key length to frequency
        """
        ciphertext_clean = ciphertext.upper()
        sequences: Dict[str, List[int]] = {}
        
        # Find all repeated sequences of length min_length
        for length in range(min_length, min(20, len(ciphertext_clean) // 2)):
            for i in range(len(ciphertext_clean) - length):
                seq = ciphertext_clean[i:i+length]
                if seq not in sequences:
                    sequences[seq] = []
                
                # Find all occurrences
                start = 0
                while True:
                    pos = ciphertext_clean.find(seq, start)
                    if pos == -1:
                        break
                    sequences[seq].append(pos)
                    start = pos + 1
        
        # Analyze spacing between repeated sequences
        key_lengths: Dict[int, int] = {}
        
        for seq, positions in sequences.items():
            if len(positions) >= 2:
                # Calculate differences between positions
                for i in range(len(positions) - 1):
                    spacing = positions[i+1] - positions[i]
                    
                    # Skip invalid spacing
                    if spacing <= 0:
                        continue
                    
                    # Find factors of spacing (likely key length divides spacing)
                    factors = VigenèreCipher._find_factors(spacing)
                    for factor in factors:
                        if 1 <= factor <= 30:  # Reasonable key length range
                            key_lengths[factor] = key_lengths.get(factor, 0) + 1
        
        return key_lengths

    @staticmethod
    def _find_factors(n: int) -> List[int]:
        """Find all factors of n."""
        if n <= 0:
            return []
        
        factors = []
        for i in range(1, int(n**0.5) + 1):
            if n % i == 0:
                factors.append(i)
                if i != n // i:
                    factors.append(n // i)
        return sorted(factors)

    @staticmethod
    def index_of_coincidence(text: str) -> float:
        """
        Calculate index of coincidence (IC).
        IC ≈ 0.065 for English, ≈ 0.038 for random text.
        
        Args:
            text: Text to analyze
        
        Returns:
            Index of coincidence value
        """
        text_clean = text.upper()
        letters_only = [c for c in text_clean if c.isalpha()]
        
        if len(letters_only) < 2:
            return 0.0
        
        # Count letter frequencies
        freq = Counter(letters_only)
        
        # Calculate IC
        ic = 0.0
        for count in freq.values():
            ic += count * (count - 1)
        
        ic /= len(letters_only) * (len(letters_only) - 1)
        return ic

    @staticmethod
    def estimate_key_length_ic(ciphertext: str, max_length: int = 30) -> int:
        """
        Estimate key length using index of coincidence.
        
        Args:
            ciphertext: Text to analyze
            max_length: Maximum key length to check
        
        Returns:
            Estimated key length
        """
        ciphertext_clean = ciphertext.upper()
        best_length = 1
        best_ic = 0.0
        
        for key_len in range(1, min(max_length, len(ciphertext_clean) // 10)):
            # Extract every n-th character
            subtext = ''.join(ciphertext_clean[i] for i in range(len(ciphertext_clean))
                            if i % key_len == 0)
            
            ic = VigenèreCipher.index_of_coincidence(subtext)
            
            # English IC ≈ 0.065, so we want closer to that
            if ic > best_ic:
                best_ic = ic
                best_length = key_len
        
        return best_length
