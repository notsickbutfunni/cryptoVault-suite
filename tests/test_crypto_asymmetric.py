"""Tests for RSA utilities (keygen, OAEP encrypt/decrypt)."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto_core.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt


def test_rsa_keygen_and_encrypt_decrypt():
    priv, pub = generate_rsa_keypair(2048)
    message = b"RSA test message"
    cipher = rsa_encrypt(pub, message)
    plain = rsa_decrypt(priv, cipher)
    assert plain == message
