"""Simple blockchain block model with PoW and Merkle root."""

import hashlib
import json
import time
from dataclasses import dataclass, asdict, field
from typing import Any, List, Optional

from .merkle import merkle_root
from .pow import mine, meets_difficulty, hash_bytes


def _canonical_data(data: Any) -> Any:
    if data is None:
        return []
    return data


@dataclass
class Block:
    index: int
    prev_hash: str
    timestamp: float
    data: List[Any]
    merkle_root: str
    nonce: int
    difficulty: int
    hash: str = field(default="")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict) -> "Block":
        return cls(**payload)

    @staticmethod
    def compute_merkle(data: List[Any]) -> str:
        payload = _canonical_data(data)
        if not payload:
            return hashlib.sha256(b"").hexdigest()
        root = merkle_root(payload)
        return root.hex()

    def _base_blob(self) -> bytes:
        body = {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "data": self.data,
            "merkle_root": self.merkle_root,
            "difficulty": self.difficulty,
        }
        return json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def compute_hash(self) -> str:
        base = self._base_blob()
        digest = hash_bytes(base + self.nonce.to_bytes(8, "big"))
        return digest.hex()

    def is_valid_hash(self) -> bool:
        computed = self.compute_hash()
        return self.hash == computed and meets_difficulty(
            computed, self.difficulty
        )

    def mine(self) -> None:
        blob = self._base_blob()
        nonce, h = mine(blob, self.difficulty)
        self.nonce = nonce
        self.hash = h


def create_block(
    index: int, prev_hash: str, data: Optional[List[Any]], difficulty: int
) -> Block:
    payload = _canonical_data(data)
    root_hex = Block.compute_merkle(payload)
    blk = Block(
        index=index,
        prev_hash=prev_hash,
        timestamp=time.time(),
        data=payload,
        merkle_root=root_hex,
        nonce=0,
        difficulty=difficulty,
    )
    blk.mine()
    return blk


def genesis_block(
    data: Optional[List[Any]] = None, difficulty: int = 4
) -> Block:
    return create_block(0, "0" * 64, data or [], difficulty)


def validate_block(prev_block: Optional[Block], block: Block) -> bool:
    """
    Validate a block against its predecessor and proof-of-work.
    Checks: index sequencing, prev_hash match, merkle root matches data,
    hash correctness and difficulty.
    """

    if prev_block is None:
        expected_prev = "0" * 64
        expected_index = 0
    else:
        expected_prev = prev_block.hash
        expected_index = prev_block.index + 1

    if block.prev_hash != expected_prev:
        return False
    if block.index != expected_index:
        return False

    # recompute merkle and hash
    expected_merkle = Block.compute_merkle(block.data)
    if block.merkle_root != expected_merkle:
        return False

    return block.is_valid_hash()
