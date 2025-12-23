import os
import tempfile
from pathlib import Path

from src.files.encrypt import (
    encrypt_file,
    decrypt_file,
    encrypt_directory,
    decrypt_directory,
)


def test_encrypt_decrypt_file_roundtrip():
    key = os.urandom(32)
    data = os.urandom(256 * 1024)

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "plain.bin"
        enc = Path(tmp) / "plain.bin.enc"
        dec = Path(tmp) / "plain.dec.bin"
        src.write_bytes(data)

        encrypt_file(str(src), str(enc), key)
        meta = decrypt_file(str(enc), str(dec), key)

        assert dec.read_bytes() == data
        assert meta["size"] == len(data)


def test_encrypt_decrypt_directory_roundtrip():
    key = os.urandom(32)

    with tempfile.TemporaryDirectory() as tmp:
        src_dir = Path(tmp) / "src"
        enc_dir = Path(tmp) / "enc"
        dec_dir = Path(tmp) / "dec"
        (src_dir / "nested").mkdir(parents=True)

        files = {
            src_dir / "a.txt": b"hello",
            src_dir / "nested" / "b.bin": os.urandom(8192),
        }

        for path, content in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        encrypt_directory(str(src_dir), str(enc_dir), key)
        decrypt_directory(str(enc_dir), str(dec_dir), key)

        for path, content in files.items():
            out_path = dec_dir / path.relative_to(src_dir)
            assert out_path.read_bytes() == content
