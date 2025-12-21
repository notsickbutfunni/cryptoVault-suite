"""
AES-GCM encryption helpers for secure messaging.

Provides low-level encrypt/decrypt and a high-level end-to-end function
that uses ECDH-derived session keys.
"""

from typing import Dict
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_exchange import ecdh_session_key_pair


def encrypt_aes_gcm(plaintext: bytes, key: bytes, aad: bytes = b"") -> Dict[str, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns dict containing nonce and ciphertext (includes tag).
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("key must be 32-byte AES-256 key")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt_aes_gcm(
    ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes = b""
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("key must be 32-byte AES-256 key")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext


def encrypt_message_e2e(
    plaintext: bytes,
    sender_private_pem: bytes,
    recipient_public_pem: bytes,
    aad: bytes = b"CryptoVault",
) -> Dict[str, bytes]:
    """
    End-to-end encrypt a message using ECDH-derived session key.

    Returns dict with: nonce, ciphertext, salt used for HKDF.
    Sender must communicate salt; session key can be re-derived by recipient.
    """
    key, salt = ecdh_session_key_pair(sender_private_pem, recipient_public_pem)
    sealed = encrypt_aes_gcm(plaintext, key, aad=aad)
    sealed["salt"] = salt
    return sealed


def decrypt_message_e2e(
    ciphertext: bytes,
    recipient_private_pem: bytes,
    sender_public_pem: bytes,
    nonce: bytes,
    salt: bytes,
    aad: bytes = b"CryptoVault",
) -> bytes:
    """
    Decrypt an end-to-end encrypted message using ECDH-derived session key.
    """
    from .key_exchange import derive_shared_secret, derive_session_key

    shared = derive_shared_secret(recipient_private_pem, sender_public_pem)
    key = derive_session_key(shared, salt=salt)
    return decrypt_aes_gcm(ciphertext, key, nonce, aad=aad)
