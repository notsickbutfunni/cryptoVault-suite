"""
ECDSA signatures for secure messaging integrity.
"""

from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend


CURVE = ec.SECP256R1()


def generate_ec_keypair() -> Tuple[bytes, bytes]:
    """
    Generate secp256r1 keypair for ECDSA.
    Returns (private_pem, public_pem).
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


def sign_message(private_pem: bytes, message: bytes) -> bytes:
    """
    Sign a message using ECDSA with SHA-256.
    Returns DER-encoded signature bytes.
    """
    private_key = load_private_key(private_pem)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an ECDSA signature.
    Returns True if valid, False otherwise.
    """
    public_key = load_public_key(public_pem)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
