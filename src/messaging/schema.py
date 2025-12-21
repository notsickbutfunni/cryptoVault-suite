"""
JSON message schema and signed envelope utilities.

Provides canonical serialization for signing and verification,
and integration with ECDH + AES-GCM for secure messaging.
"""

import json
import base64
from datetime import datetime, timezone
from typing import Dict, Any

from cryptography.hazmat.primitives import serialization

from .key_exchange import (
    ecdh_session_key_pair,
    derive_shared_secret,
    derive_session_key,
    load_private_key as load_ec_priv,
)
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm
from .signatures import sign_message, verify_signature


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _pub_from_private(private_pem: bytes) -> bytes:
    priv = load_ec_priv(private_pem)
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return text.encode("utf-8")


def create_envelope(
    plaintext: bytes,
    sender_private_pem: bytes,
    recipient_public_pem: bytes,
    aad: bytes = b"CryptoVault",
) -> Dict[str, Any]:
    """
    Create a signed JSON envelope for secure messaging.

    Fields:
      - version: "1.0"
      - sender_pub, recipient_pub: base64-encoded PEM
      - nonce, salt, ciphertext: base64-encoded bytes
      - timestamp: ISO-8601 UTC with 'Z'
      - signature: base64-encoded DER signature over canonical payload
      - signature_alg: "ECDSA-SHA256"
    """
    key, salt = ecdh_session_key_pair(sender_private_pem, recipient_public_pem)
    sealed = encrypt_aes_gcm(plaintext, key, aad=aad)

    sender_pub_pem = _pub_from_private(sender_private_pem)

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    payload = {
        "version": "1.0",
        "sender_pub": _b64e(sender_pub_pem),
        "recipient_pub": _b64e(recipient_public_pem),
        "nonce": _b64e(sealed["nonce"]),
        "salt": _b64e(salt),
        "ciphertext": _b64e(sealed["ciphertext"]),
        "timestamp": timestamp,
    }

    canon = _canonical_bytes(payload)
    sig = sign_message(sender_private_pem, canon)

    envelope = dict(payload)
    envelope["signature"] = _b64e(sig)
    envelope["signature_alg"] = "ECDSA-SHA256"
    return envelope


def envelope_to_json(envelope: Dict[str, Any]) -> str:
    return json.dumps(envelope, indent=2)


def verify_and_decrypt_envelope(
    envelope_json: str,
    recipient_private_pem: bytes,
    aad: bytes = b"CryptoVault",
) -> bytes:
    """
    Verify signature and decrypt envelope for the recipient.
    Raises ValueError if signature is invalid.
    Returns plaintext bytes if verification and decryption succeed.
    """
    env = json.loads(envelope_json)
    payload = {
        "version": env["version"],
        "sender_pub": env["sender_pub"],
        "recipient_pub": env["recipient_pub"],
        "nonce": env["nonce"],
        "salt": env["salt"],
        "ciphertext": env["ciphertext"],
        "timestamp": env["timestamp"],
    }

    canon = _canonical_bytes(payload)
    sender_pub_pem = _b64d(env["sender_pub"])
    signature = _b64d(env["signature"])

    if not verify_signature(sender_pub_pem, canon, signature):
        raise ValueError("Invalid signature")

    nonce = _b64d(env["nonce"])
    salt = _b64d(env["salt"])
    ciphertext = _b64d(env["ciphertext"])
    peer_pub = _b64d(env["sender_pub"])  # sender public key

    shared = derive_shared_secret(recipient_private_pem, peer_pub)
    key = derive_session_key(shared, salt=salt)
    return decrypt_aes_gcm(ciphertext, key, nonce, aad=aad)
