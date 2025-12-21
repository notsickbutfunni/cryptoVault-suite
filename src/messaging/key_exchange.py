"""
ECDH key exchange utilities for secure messaging.

Uses secp256r1 curve with HKDF-SHA256 to derive 256-bit session keys.
"""

from typing import Tuple
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


CURVE = ec.SECP256R1()


def generate_ec_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ECDSA/ECDH secp256r1 keypair.

    Returns:
        private_pem, public_pem (bytes)
    """
    private_key = ec.generate_private_key(CURVE, default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def load_private_key(private_pem: bytes):
    return serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )


def load_public_key(public_pem: bytes):
    return serialization.load_pem_public_key(public_pem, backend=default_backend())


def derive_shared_secret(private_pem: bytes, peer_public_pem: bytes) -> bytes:
    """
    Derive raw ECDH shared secret between private and peer public key.
    """
    private_key = load_private_key(private_pem)
    peer_public_key = load_public_key(peer_public_pem)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret


def derive_session_key(
    shared_secret: bytes, salt: bytes = None, info: bytes = b"CryptoVault-Session"
) -> bytes:
    """
    Derive a 32-byte session key from raw shared secret using HKDF-SHA256.
    """
    if salt is None:
        salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    key = hkdf.derive(shared_secret)
    return key


def ecdh_session_key_pair(
    sender_private_pem: bytes, recipient_public_pem: bytes
) -> Tuple[bytes, bytes]:
    """
    Derive session key and return (key, salt) used, suitable for AES-GCM.
    """
    shared = derive_shared_secret(sender_private_pem, recipient_public_pem)
    salt = os.urandom(16)
    key = derive_session_key(shared, salt=salt)
    return key, salt
