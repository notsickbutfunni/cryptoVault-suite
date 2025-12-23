"""File integrity helpers: SHA-256 hashing and Merkle trees."""

import hashlib
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def hash_file(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """
    Compute SHA-256 digest of a file using streaming reads.
    Returns raw bytes digest.
    """

    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def file_chunk_hashes(
    path: str, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> List[bytes]:
    """Return list of SHA-256 digests for each chunk of the file."""

    hashes: List[bytes] = []
    with Path(path).open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hashes.append(_sha256(chunk))
    if not hashes:
        hashes.append(_sha256(b""))
    return hashes


def _next_level(nodes: Sequence[bytes]) -> List[bytes]:
    out: List[bytes] = []
    n = len(nodes)
    i = 0
    while i < n:
        left = nodes[i]
        if i + 1 < n:
            right = nodes[i + 1]
        else:
            right = left  # duplicate last for odd count
        out.append(_sha256(left + right))
        i += 2
    return out


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Compute Merkle root from leaf hashes (SHA-256)."""

    if not leaves:
        raise ValueError("No leaves provided")
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_tree(leaves: Sequence[bytes]) -> List[List[bytes]]:
    """Return full Merkle tree levels (level 0 = leaves)."""

    if not leaves:
        raise ValueError("No leaves provided")
    levels: List[List[bytes]] = [list(leaves)]
    while len(levels[-1]) > 1:
        levels.append(_next_level(levels[-1]))
    return levels


def merkle_proof(
    leaves: Sequence[bytes], index: int
) -> List[Tuple[bytes, str]]:
    """
    Produce a Merkle inclusion proof for leaf at index.
    Returns list of (sibling_hash, position), where position is 'left' or
    'right' indicating sibling placement relative to the running hash during
    verification.
    """

    if not leaves:
        raise ValueError("No leaves provided")
    if index < 0 or index >= len(leaves):
        raise IndexError("Leaf index out of range")

    proof: List[Tuple[bytes, str]] = []
    idx = index
    level = list(leaves)
    while len(level) > 1:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1
        if sibling_idx >= len(level):
            sibling_hash = level[idx]
        else:
            sibling_hash = level[sibling_idx]
        position = "left" if is_right else "right"
        proof.append((sibling_hash, position))
        idx //= 2
        level = _next_level(level)
    return proof


def verify_proof(
    leaf_hash: bytes, proof: Iterable[Tuple[bytes, str]], root: bytes
) -> bool:
    """Verify a Merkle inclusion proof."""

    h = leaf_hash
    for sibling, position in proof:
        if position == "left":
            h = _sha256(sibling + h)
        else:
            h = _sha256(h + sibling)
    return h == root


def file_merkle_root(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """Compute Merkle root of file chunk hashes."""

    leaves = file_chunk_hashes(path, chunk_size=chunk_size)
    return merkle_root(leaves)


def verify_file_integrity(
    path: str, expected_root: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> bool:
    """Return True if computed Merkle root matches expected_root."""

    return file_merkle_root(path, chunk_size=chunk_size) == expected_root


def detect_tamper(
    path: str, expected_root: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> bool:
    """Return True if tampering is detected (root mismatch)."""

    return not verify_file_integrity(
        path, expected_root, chunk_size=chunk_size
    )
