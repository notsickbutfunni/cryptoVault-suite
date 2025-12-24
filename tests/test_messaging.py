"""Tests for secure messaging: ECDH, AES-GCM, ECDSA, and E2E flow."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.messaging.key_exchange import generate_ec_keypair, derive_shared_secret, derive_session_key
from src.messaging.encryption import encrypt_aes_gcm, decrypt_aes_gcm, encrypt_message_e2e, decrypt_message_e2e
from src.messaging.signatures import generate_ec_keypair as gen_sig_keys, sign_message, verify_signature
from src.messaging.schema import create_envelope_ephemeral, envelope_to_json, verify_and_decrypt_envelope


def test_ecdh_shared_secret_matches():
    # Alice and Bob keypairs
    alice_priv, alice_pub = generate_ec_keypair()
    bob_priv, bob_pub = generate_ec_keypair()

    # Derive shared secrets both ways
    s1 = derive_shared_secret(alice_priv, bob_pub)
    s2 = derive_shared_secret(bob_priv, alice_pub)

    assert isinstance(s1, bytes) and isinstance(s2, bytes)
    assert s1 == s2


def test_hkdf_session_key_length():
    alice_priv, alice_pub = generate_ec_keypair()
    bob_priv, bob_pub = generate_ec_keypair()
    shared = derive_shared_secret(alice_priv, bob_pub)
    key = derive_session_key(shared)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_aes_gcm_encrypt_decrypt():
    key = os.urandom(32)
    plaintext = b"secret message"
    sealed = encrypt_aes_gcm(plaintext, key)
    recovered = decrypt_aes_gcm(sealed["ciphertext"], key, sealed["nonce"])
    assert recovered == plaintext


def test_ecdsa_sign_verify():
    priv, pub = gen_sig_keys()
    msg = b"verify me"
    sig = sign_message(priv, msg)
    assert verify_signature(pub, msg, sig)
    # Wrong message fails
    assert not verify_signature(pub, b"tampered", sig)


def test_end_to_end_encrypt_decrypt():
    sender_priv, sender_pub = generate_ec_keypair()
    recipient_priv, recipient_pub = generate_ec_keypair()

    message = b"Hello, secure world!"
    sealed = encrypt_message_e2e(message, sender_priv, recipient_pub)
    recovered = decrypt_message_e2e(
        sealed["ciphertext"], recipient_priv, sender_pub, sealed["nonce"], sealed["salt"]
    )
    assert recovered == message


def test_ephemeral_envelope_send_receive():
    # Identity/signing keys
    sender_sign_priv, sender_sign_pub = generate_ec_keypair()
    recipient_priv, recipient_pub = generate_ec_keypair()

    msg = b"Ephemeral ECDH message"
    env = create_envelope_ephemeral(msg, sender_sign_priv, recipient_pub)
    env_json = envelope_to_json(env)
    out = verify_and_decrypt_envelope(env_json, recipient_priv)
    assert out == msg
