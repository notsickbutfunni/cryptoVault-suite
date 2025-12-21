"""
RSA utilities: key generation, encryption, decryption using OAEP with SHA-256.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(bits: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generate an RSA keypair.
    Returns (private_pem, public_pem).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )
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
    return serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())


def load_public_key(public_pem: bytes):
    return serialization.load_pem_public_key(public_pem, backend=default_backend())


def rsa_encrypt(public_pem: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with RSA-OAEP (SHA-256).
    """
    public_key = load_public_key(public_pem)
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(private_pem: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext.
    """
    private_key = load_private_key(private_pem)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext
