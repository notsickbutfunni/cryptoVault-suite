import os
import tempfile
from pathlib import Path

from src.files.secure import encrypt_file_pw, decrypt_file_pw


def test_password_encrypt_decrypt_roundtrip():
    data = os.urandom(300_000)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "plain.bin"
        enc = Path(tmp) / "plain.bin.sec"
        dec = Path(tmp) / "plain.dec.bin"
        src.write_bytes(data)

        meta = encrypt_file_pw(str(src), str(enc), password="P@ssw0rd!", pbkdf2_iters=150_000)
        assert meta["kdf"] == "pbkdf2"
        assert int(meta["kdf_iters"]) >= 100_000
        assert len(meta["original_sha256"]) == 64

        out_meta = decrypt_file_pw(str(enc), str(dec), password="P@ssw0rd!")
        assert dec.read_bytes() == data
        assert out_meta["original_sha256"] == meta["original_sha256"]


def test_password_decrypt_tamper_detection():
    data = b"A" * (256 * 1024)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "data.bin"
        enc = Path(tmp) / "data.bin.sec"
        dec = Path(tmp) / "data.out.bin"
        src.write_bytes(data)

        encrypt_file_pw(str(src), str(enc), password="S3cret!!", pbkdf2_iters=120_000)
        # flip a byte in ciphertext area (skip header+salt+meta)
        b = bytearray(enc.read_bytes())
        # last 48 bytes are tag(16)+hmac(32); modify before that
        if len(b) > 64:
            b[len(b) - 64] ^= 0xFF
        enc.write_bytes(bytes(b))

        try:
            decrypt_file_pw(str(enc), str(dec), password="S3cret!!")
        except Exception as e:
            assert "HMAC" in str(e)
        else:
            raise AssertionError("Tamper not detected")
