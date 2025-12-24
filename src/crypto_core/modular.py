"""
Modular arithmetic utilities implemented from scratch.

Implements:
- Modular exponentiation with square-and-multiply algorithm
- Extended Euclidean algorithm for modular inverse
- Prime testing (Miller-Rabin)
- Secure random prime generation
"""

import secrets
from typing import Tuple


def pow_mod(base: int, exp: int, mod: int) -> int:
    """
    Compute (base ^ exp) mod mod using square-and-multiply algorithm.
    
    This is the efficient modular exponentiation method used in RSA.
    Time complexity: O(log exp)
    
    Args:
        base: Base value
        exp: Exponent
        mod: Modulus
    
    Returns:
        (base ^ exp) mod mod
    """
    if mod == 1:
        return 0
    
    result = 1
    base = base % mod
    
    # Binary exponentiation (square-and-multiply)
    while exp > 0:
        # If exponent is odd, multiply result by base
        if exp % 2 == 1:
            result = (result * base) % mod
        
        # Square the base and halve the exponent
        exp = exp >> 1  # Divide by 2
        base = (base * base) % mod
    
    return result


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    
    Args:
        a: First value
        b: Second value
    
    Returns:
        Tuple of (gcd, x, y)
    """
    if b == 0:
        return a, 1, 0
    
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    
    return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse of a modulo m.
    Returns x such that (a * x) mod m = 1
    
    Uses extended Euclidean algorithm.
    
    Args:
        a: Value to invert
        m: Modulus
    
    Returns:
        Modular inverse of a mod m
    
    Raises:
        ValueError: If modular inverse does not exist
    """
    gcd, x, _ = extended_gcd(a, m)
    
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={gcd})")
    
    return x % m


def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    Probabilistic algorithm with error probability ≤ 4^(-k)
    
    Args:
        n: Number to test for primality
        k: Number of rounds (higher = more confidence)
    
    Returns:
        True if probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        # Pick random a in range [2, n-2]
        a = secrets.randbelow(n - 3) + 2
        
        x = pow_mod(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        is_probably_prime = False
        for _ in range(r - 1):
            x = pow_mod(x, 2, n)
            if x == n - 1:
                is_probably_prime = True
                break
        
        if not is_probably_prime:
            return False
    
    return True


def generate_prime(bit_length: int, k: int = 40) -> int:
    """
    Generate a random prime number with specified bit length.
    
    Args:
        bit_length: Desired bit length of prime
        k: Miller-Rabin test rounds (higher = more confidence)
    
    Returns:
        Random prime number with bit_length bits
    """
    while True:
        # Generate random odd number with specified bit length
        candidate = secrets.randbits(bit_length)
        candidate |= (1 << (bit_length - 1))  # Set MSB
        candidate |= 1  # Set LSB (make odd)
        
        if is_prime(candidate, k=k):
            return candidate


def gcd(a: int, b: int) -> int:
    """
    Compute greatest common divisor using Euclidean algorithm.
    
    Args:
        a: First value
        b: Second value
    
    Returns:
        Greatest common divisor of a and b
    """
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """
    Compute least common multiple.
    
    Args:
        a: First value
        b: Second value
    
    Returns:
        Least common multiple of a and b
    """
    return abs(a * b) // gcd(a, b)


class RSAKeyGenerator:
    """
    Generate RSA keypairs using custom modular exponentiation.
    Uses cryptography library only for PEM serialization (not for core algorithm).
    """
    
    @staticmethod
    def generate_keypair(bit_length: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA keypair.
        
        Args:
            bit_length: Key size in bits (e.g., 2048, 4096)
        
        Returns:
            Tuple of ((n, e), (n, d)) where:
            - (n, e) is public key
            - (n, d) is private key
            - n = p * q (modulus)
            - e = public exponent (typically 65537)
            - d = private exponent
        """
        # Generate two large prime numbers
        half_bits = bit_length // 2
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        
        # Ensure p != q
        while p == q:
            q = generate_prime(half_bits)
        
        # Compute modulus
        n = p * q
        
        # Compute Euler's totient function
        phi_n = (p - 1) * (q - 1)
        
        # Choose public exponent e
        e = 65537  # Standard value
        if gcd(e, phi_n) != 1:
            # If e is not coprime with phi(n), find another
            for e in range(3, phi_n):
                if gcd(e, phi_n) == 1:
                    break
        
        # Compute private exponent d
        d = mod_inverse(e, phi_n)
        
        return (n, e), (n, d)
    
    @staticmethod
    def encrypt(public_key: Tuple[int, int], plaintext: int) -> int:
        """
        RSA encryption.
        
        Args:
            public_key: Tuple of (n, e)
            plaintext: Plaintext value (must be < n)
        
        Returns:
            Ciphertext value
        """
        n, e = public_key
        if plaintext >= n:
            raise ValueError(f"Plaintext {plaintext} must be < n {n}")
        return pow_mod(plaintext, e, n)
    
    @staticmethod
    def decrypt(private_key: Tuple[int, int], ciphertext: int) -> int:
        """
        RSA decryption.
        
        Args:
            private_key: Tuple of (n, d)
            ciphertext: Ciphertext value
        
        Returns:
            Plaintext value
        """
        n, d = private_key
        return pow_mod(ciphertext, d, n)
