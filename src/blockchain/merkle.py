"""Merkle tree utilities for blockchain transactions."""

import hashlib
from typing import Iterable, List, Sequence, Tuple


def _to_bytes(item) -> bytes:
    if isinstance(item, bytes):
        return item
    if isinstance(item, str):
        return item.encode("utf-8")
    return str(item).encode("utf-8")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_leaves(items: Iterable) -> List[bytes]:
    return [_sha256(_to_bytes(x)) for x in items]


def _next_level(nodes: Sequence[bytes]) -> List[bytes]:
    out: List[bytes] = []
    n = len(nodes)
    i = 0
    while i < n:
        left = nodes[i]
        if i + 1 < n:
            right = nodes[i + 1]
        else:
            right = left
        out.append(_sha256(left + right))
        i += 2
    return out


def merkle_root(items: Iterable) -> bytes:
    leaves = merkle_leaves(items)
    if not leaves:
        raise ValueError("No leaves provided")
    level = leaves
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_tree(items: Iterable) -> List[List[bytes]]:
    leaves = merkle_leaves(items)
    if not leaves:
        raise ValueError("No leaves provided")
    levels: List[List[bytes]] = [leaves]
    while len(levels[-1]) > 1:
        levels.append(_next_level(levels[-1]))
    return levels


def merkle_proof(items: Sequence, index: int) -> List[Tuple[bytes, str]]:
    leaves = merkle_leaves(items)
    if not leaves:
        raise ValueError("No leaves provided")
    if index < 0 or index >= len(leaves):
        raise IndexError("Leaf index out of range")

    proof: List[Tuple[bytes, str]] = []
    idx = index
    level = leaves
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
    leaf_item, proof: Iterable[Tuple[bytes, str]], root: bytes
) -> bool:
    h = _sha256(_to_bytes(leaf_item))
    for sibling, position in proof:
        if position == "left":
            h = _sha256(sibling + h)
        else:
            h = _sha256(h + sibling)
    return h == root
