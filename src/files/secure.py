"""
Password-based secure file encryption with FEK wrapping and HMAC.

Format (version 2):
  Header (struct >4sB H I I 12s 12s 12s):
    magic: b"CVF2"
    version: 2
    salt_len: uint16
    meta_len: uint32 (length of encrypted meta)
    pbkdf2_iters: uint32
    file_nonce: 12 bytes (GCM for file)
    meta_nonce: 12 bytes (GCM for meta)
    fek_nonce: 12 bytes (GCM for FEK wrap)
  salt: salt_len bytes
  meta_cipher: meta_len bytes (AESGCM(master_key) over meta JSON, aad=b"meta2")
  ciphertext: streaming AES-GCM with FEK, aad=b"file2"
  tag: 16 bytes (file GCM tag)
  hmac: 32 bytes (HMAC-SHA256(master_key, ciphertext||tag))

Meta JSON (encrypted):
  {
    "original_sha256": hex,
    "kdf": "pbkdf2",
    "kdf_iters": int,
    "fek_wrapped": hex,
  }

This module is self-contained and does not change the existing v1 format used by src/files/encrypt.py.
"""

import json
import os
import struct
import hashlib
import hmac
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_CHUNK_SIZE = 64 * 1024
TAG_SIZE = 16
HMAC_SIZE = 32

MAGIC2 = b"CVF2"
VERSION2 = 2
# >4s B H I I 12s 12s 12s
HEADER2_STRUCT = struct.Struct(
    ">4sB H I I 12s 12s 12s"
)


def _pack_header2(
    salt_len: int,
    meta_len: int,
    pbkdf2_iters: int,
    file_nonce: bytes,
    meta_nonce: bytes,
    fek_nonce: bytes,
) -> bytes:
    return HEADER2_STRUCT.pack(
        MAGIC2, VERSION2, salt_len, meta_len, pbkdf2_iters, file_nonce, meta_nonce, fek_nonce
    )


def _unpack_header2(data: bytes):
    if len(data) != HEADER2_STRUCT.size:
        raise ValueError("Invalid header2 length")
    magic, version, salt_len, meta_len, iters, file_nonce, meta_nonce, fek_nonce = HEADER2_STRUCT.unpack(data)
    if magic != MAGIC2 or version != VERSION2:
        raise ValueError("Unsupported format (magic/version)")
    return salt_len, meta_len, iters, file_nonce, meta_nonce, fek_nonce


def _derive_master_key_pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    iterations = max(100_000, int(iterations))
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)


def encrypt_file_pw(
    input_path: str,
    output_path: str,
    password: str,
    pbkdf2_iters: int = 200_000,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict:
    src = Path(input_path)
    dst = Path(output_path)

    # Precompute original file hash
    h_plain = hashlib.sha256()
    total_bytes = src.stat().st_size
    with src.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h_plain.update(b)
    original_sha256 = h_plain.hexdigest()

    # Derive master key (PBKDF2)
    salt = os.urandom(32)
    master_key = _derive_master_key_pbkdf2(password, salt, pbkdf2_iters)

    # Generate FEK and wrap
    fek = os.urandom(32)
    fek_nonce = os.urandom(12)
    fek_wrapped = AESGCM(master_key).encrypt(fek_nonce, fek, associated_data=b"fek")

    # Prepare encrypted metadata
    meta = {
        "original_sha256": original_sha256,
        "kdf": "pbkdf2",
        "kdf_iters": int(pbkdf2_iters),
        "fek_wrapped": fek_wrapped.hex(),
    }
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    meta_nonce = os.urandom(12)
    meta_cipher = AESGCM(master_key).encrypt(meta_nonce, meta_bytes, associated_data=b"meta2")

    # File encryption
    file_nonce = os.urandom(12)
    header = _pack_header2(len(salt), len(meta_cipher), int(pbkdf2_iters), file_nonce, meta_nonce, fek_nonce)

    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(header)
        fout.write(salt)
        fout.write(meta_cipher)

        encryptor = Cipher(
            algorithms.AES(fek), modes.GCM(file_nonce), backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(b"file2")

        h = hmac.new(master_key, digestmod=hashlib.sha256)

        processed = 0
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            processed += len(chunk)
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)
                h.update(ct)
            if progress_cb:
                progress_cb(processed, total_bytes)
        final = encryptor.finalize()
        if final:
            fout.write(final)
            h.update(final)
        fout.write(encryptor.tag)
        h.update(encryptor.tag)
        fout.write(h.digest())

    return meta


def decrypt_file_pw(
    input_path: str,
    output_path: str,
    password: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict:
    src = Path(input_path)
    dst = Path(output_path)

    total_size = src.stat().st_size
    header_size = HEADER2_STRUCT.size

    with src.open("rb") as fin:
        header = fin.read(header_size)
        salt_len, meta_len, pbkdf2_iters, file_nonce, meta_nonce, fek_nonce = _unpack_header2(header)

        salt = fin.read(salt_len)
        if len(salt) != salt_len:
            raise ValueError("Unexpected EOF reading salt")

        meta_cipher = fin.read(meta_len)
        if len(meta_cipher) != meta_len:
            raise ValueError("Unexpected EOF reading meta")

        # Remaining layout sizes
        remaining = total_size - header_size - salt_len - meta_len
        if remaining < TAG_SIZE + HMAC_SIZE:
            raise ValueError("File too short for ciphertext/tag/hmac")
        cipher_and_tag_len = remaining - HMAC_SIZE
        cipher_len = cipher_and_tag_len - TAG_SIZE

        # Read stored HMAC
        fin.seek(header_size + salt_len + meta_len + cipher_and_tag_len)
        stored_hmac = fin.read(HMAC_SIZE)

        # Read tag
        fin.seek(header_size + salt_len + meta_len + cipher_len)
        tag = fin.read(TAG_SIZE)

        # Derive master key
        master_key = _derive_master_key_pbkdf2(password, salt, pbkdf2_iters)

        # Verify HMAC before any decryption
        h = hmac.new(master_key, digestmod=hashlib.sha256)
        fin.seek(header_size + salt_len + meta_len)
        remaining_cipher = cipher_len
        while remaining_cipher > 0:
            to_read = min(chunk_size, remaining_cipher)
            chunk = fin.read(to_read)
            if not chunk:
                raise ValueError("Unexpected EOF in ciphertext for HMAC")
            remaining_cipher -= len(chunk)
            h.update(chunk)
        h.update(tag)
        if not hmac.compare_digest(h.digest(), stored_hmac):
            raise ValueError("HMAC verification failed; file may be tampered")

        # Decrypt meta to obtain wrapped FEK
        meta_plain = AESGCM(master_key).decrypt(meta_nonce, meta_cipher, associated_data=b"meta2")
        meta = json.loads(meta_plain.decode("utf-8"))
        fek_wrapped = bytes.fromhex(meta["fek_wrapped"])  # type: ignore

        # Unwrap FEK
        fek = AESGCM(master_key).decrypt(fek_nonce, fek_wrapped, associated_data=b"fek")

        # Decrypt file
        fin.seek(header_size + salt_len + meta_len)
        decryptor = Cipher(
            algorithms.AES(fek), modes.GCM(file_nonce, tag), backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(b"file2")

        processed = 0
        with dst.open("wb") as fout:
            remaining_cipher = cipher_len
            while remaining_cipher > 0:
                to_read = min(chunk_size, remaining_cipher)
                chunk = fin.read(to_read)
                if not chunk:
                    raise ValueError("Unexpected EOF in ciphertext")
                remaining_cipher -= len(chunk)
                processed += len(chunk)
                fout.write(decryptor.update(chunk))
                if progress_cb:
                    progress_cb(processed, cipher_len)
            decryptor.finalize()

    return meta
