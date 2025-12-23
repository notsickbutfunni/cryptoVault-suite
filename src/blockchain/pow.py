"""Proof-of-work helpers."""

import hashlib
from typing import Tuple


def difficulty_to_target(bits: int) -> int:
    """Convert leading-zero bit difficulty into integer target."""

    if bits < 0 or bits > 256:
        raise ValueError("bits must be between 0 and 256")
    return (1 << (256 - bits)) - 1


def hash_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def meets_difficulty(hash_hex: str, bits: int) -> bool:
    target = difficulty_to_target(bits)
    value = int(hash_hex, 16)
    return value <= target


def mine(data: bytes, bits: int, start_nonce: int = 0) -> Tuple[int, str]:
    """
    Brute-force a nonce so that sha256(data || nonce) meets difficulty.
    Returns (nonce, hash_hex).
    """

    nonce = start_nonce
    target = difficulty_to_target(bits)
    while True:
        digest = hash_bytes(data + nonce.to_bytes(8, "big"))
        value = int.from_bytes(digest, "big")
        if value <= target:
            return nonce, digest.hex()
        nonce += 1
