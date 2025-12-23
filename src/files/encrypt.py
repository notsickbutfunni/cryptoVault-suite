"""Streaming AES-256-GCM file encryption with metadata protection."""

import json
import os
import struct
from pathlib import Path
from typing import Callable, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CVF1"
VERSION = 1
TAG_SIZE = 16
HEADER_STRUCT = struct.Struct(
    ">4sB I 12s 12s"
)
# fields: magic, version, meta_len, meta_nonce, file_nonce
DEFAULT_CHUNK_SIZE = 64 * 1024


def _default_metadata(path: Path) -> Dict[str, int]:
    stat = path.stat()
    return {
        "name": path.name,
        "size": stat.st_size,
        "mtime": int(stat.st_mtime),
    }


def _pack_header(meta_len: int, meta_nonce: bytes, file_nonce: bytes) -> bytes:
    return HEADER_STRUCT.pack(MAGIC, VERSION, meta_len, meta_nonce, file_nonce)


def _unpack_header(data: bytes):
    if len(data) != HEADER_STRUCT.size:
        raise ValueError("Invalid header length")
    magic, version, meta_len, meta_nonce, file_nonce = HEADER_STRUCT.unpack(
        data
    )
    if magic != MAGIC:
        raise ValueError("Invalid file magic")
    if version != VERSION:
        raise ValueError("Unsupported version")
    return meta_len, meta_nonce, file_nonce


def encrypt_file(
    input_path: str,
    output_path: str,
    key: bytes,
    metadata: Optional[Dict] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict:
    src = Path(input_path)
    dst = Path(output_path)

    meta = _default_metadata(src)
    if metadata:
        meta.update(metadata)

    meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    meta_nonce = os.urandom(12)
    meta_cipher = AESGCM(key).encrypt(
        meta_nonce, meta_bytes, associated_data=b"meta"
    )

    file_nonce = os.urandom(12)
    header = _pack_header(len(meta_cipher), meta_nonce, file_nonce)

    total_bytes = meta["size"]

    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(header)
        fout.write(meta_cipher)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(file_nonce),
            backend=default_backend(),
        ).encryptor()
        encryptor.authenticate_additional_data(b"file")

        processed = 0
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            processed += len(chunk)
            fout.write(encryptor.update(chunk))
            if progress_cb:
                progress_cb(processed, total_bytes)
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)

    return meta


def decrypt_file(
    input_path: str,
    output_path: str,
    key: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict:
    src = Path(input_path)
    dst = Path(output_path)

    total_size = src.stat().st_size
    header_size = HEADER_STRUCT.size

    with src.open("rb") as fin:
        header_bytes = fin.read(header_size)
        meta_len, meta_nonce, file_nonce = _unpack_header(header_bytes)

        meta_cipher = fin.read(meta_len)
        if len(meta_cipher) != meta_len:
            raise ValueError("Unexpected EOF reading metadata")

        remaining = total_size - header_size - meta_len
        if remaining < TAG_SIZE:
            raise ValueError("File too short for ciphertext and tag")
        cipher_len = remaining - TAG_SIZE

        fin.seek(header_size + meta_len + cipher_len)
        tag = fin.read(TAG_SIZE)
        fin.seek(header_size + meta_len)

        meta_plain = AESGCM(key).decrypt(
            meta_nonce, meta_cipher, associated_data=b"meta"
        )
        meta = json.loads(meta_plain.decode("utf-8"))
        expected_total = int(meta.get("size", 0)) if meta.get("size") else None

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(file_nonce, tag),
            backend=default_backend(),
        ).decryptor()
        decryptor.authenticate_additional_data(b"file")

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
                if progress_cb and expected_total:
                    progress_cb(min(processed, expected_total), expected_total)
            decryptor.finalize()

    return meta


def encrypt_directory(
    source_dir: str,
    target_dir: str,
    key: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> None:
    src_root = Path(source_dir)
    dst_root = Path(target_dir)
    for root, _, files in os.walk(src_root):
        for name in files:
            in_path = Path(root) / name
            rel = in_path.relative_to(src_root)
            out_path = dst_root / f"{rel}.enc"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            encrypt_file(
                str(in_path),
                str(out_path),
                key,
                metadata={"relative": str(rel)},
                chunk_size=chunk_size,
                progress_cb=progress_cb,
            )


def decrypt_directory(
    source_dir: str,
    target_dir: str,
    key: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> None:
    src_root = Path(source_dir)
    dst_root = Path(target_dir)
    for root, _, files in os.walk(src_root):
        for name in files:
            in_path = Path(root) / name
            rel = in_path.relative_to(src_root)
            if rel.suffix == ".enc":
                rel_out = rel.with_suffix("")
            else:
                rel_out = rel
            out_path = dst_root / rel_out
            out_path.parent.mkdir(parents=True, exist_ok=True)
            meta = decrypt_file(
                str(in_path),
                str(out_path),
                key,
                chunk_size=chunk_size,
                progress_cb=progress_cb,
            )
            if "relative" in meta:
                desired = dst_root / meta["relative"]
                desired.parent.mkdir(parents=True, exist_ok=True)
                out_path.rename(desired)
