"""Crypto Core - Core cryptographic implementations

Provides fundamental cryptographic operations:
- SHA-256 hash function (custom implementation)
- Merkle tree with proof generation
- Classical ciphers (Caesar, Vigenère) with cryptanalysis
- Modular exponentiation and RSA (custom implementation)
- AES encryption (CBC/GCM modes)
- RSA asymmetric encryption
- ECDSA digital signatures
- SHA-256/SHA-3 hashing
- HMAC authentication
- Key derivation (PBKDF2, Argon2)
"""

__all__ = [
    "sha256",
    "classical",
    "modular",
    "rsa_utils",
    "hashing",
    "key_derivation",
]
