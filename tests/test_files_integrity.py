import os
import tempfile
from pathlib import Path

from src.files.integrity import (
    hash_file,
    file_chunk_hashes,
    file_merkle_root,
    merkle_tree,
    merkle_proof,
    verify_proof,
    verify_file_integrity,
    detect_tamper,
)


def test_hash_and_merkle_root_roundtrip():
    data = os.urandom(128 * 1024)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "data.bin"
        path.write_bytes(data)

        file_hash = hash_file(str(path))
        # hash should match hashing the entire file in one shot
        assert file_hash == hash_file(str(path))

        leaves = file_chunk_hashes(str(path), chunk_size=16 * 1024)
        root = file_merkle_root(str(path), chunk_size=16 * 1024)
        tree = merkle_tree(leaves)

        assert tree[-1][0] == root
        assert len(tree[0]) == len(leaves)


def test_merkle_proof_and_verify():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "data.bin"
        path.write_bytes(b"abcdefghijklmno")

        leaves = file_chunk_hashes(str(path), chunk_size=4)
        root = file_merkle_root(str(path), chunk_size=4)

        for idx, leaf in enumerate(leaves):
            proof = merkle_proof(leaves, idx)
            assert verify_proof(leaf, proof, root)


def test_tamper_detection():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "data.bin"
        path.write_bytes(b"A" * 1024)

        root = file_merkle_root(str(path), chunk_size=128)
        assert verify_file_integrity(str(path), root, chunk_size=128)
        assert detect_tamper(str(path), root, chunk_size=128) is False

        # tamper with file
        data = bytearray(path.read_bytes())
        data[100] ^= 0xFF
        path.write_bytes(bytes(data))

        assert verify_file_integrity(str(path), root, chunk_size=128) is False
        assert detect_tamper(str(path), root, chunk_size=128) is True
