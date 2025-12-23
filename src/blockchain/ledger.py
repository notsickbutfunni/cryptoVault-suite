"""Blockchain ledger with basic chain management and persistence."""

import json
import time
from pathlib import Path
from typing import List, Optional

from .block import (
    Block,
    create_block,
    genesis_block,
    validate_block,
)
from .pow import hash_bytes


def _work_for_bits(bits: int) -> int:
    # cumulative work metric: higher bits => more work
    return 1 << bits


class Blockchain:
    def __init__(
        self,
        blocks: Optional[List[Block]] = None,
        default_difficulty: int = 12,
    ):
        self.blocks: List[Block] = blocks or [
            genesis_block(difficulty=default_difficulty)
        ]
        self.default_difficulty = default_difficulty
        self.audit_log: List[dict] = []

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    def add_block(
        self, data: Optional[List] = None, difficulty: Optional[int] = None
    ) -> Block:
        diff = difficulty or self.default_difficulty
        blk = create_block(
            index=self.head.index + 1,
            prev_hash=self.head.hash,
            data=data or [],
            difficulty=diff,
        )
        self.blocks.append(blk)
        return blk

    def is_valid(self) -> bool:
        prev = None
        for blk in self.blocks:
            if not validate_block(prev, blk):
                return False
            prev = blk
        return True

    def cumulative_work(self) -> int:
        return sum(_work_for_bits(b.difficulty) for b in self.blocks)

    def to_dict(self) -> dict:
        return {
            "default_difficulty": self.default_difficulty,
            "blocks": [b.to_dict() for b in self.blocks],
            "audit_log": self.audit_log,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "Blockchain":
        blocks = [Block.from_dict(b) for b in payload["blocks"]]
        chain = cls(
            blocks=blocks,
            default_difficulty=payload.get("default_difficulty", 12),
        )
        chain.audit_log = payload.get("audit_log", [])
        if not chain.is_valid():
            raise ValueError("Invalid chain data")
        return chain

    def save(self, path: str) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), sort_keys=True, indent=2)
        )

    @classmethod
    def load(cls, path: str) -> "Blockchain":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)

    def resolve_fork(self, other: "Blockchain") -> "Blockchain":
        if not other.is_valid():
            return self
        if other.cumulative_work() > self.cumulative_work():
            return other
        return self

    def append_audit(self, action: str, user: str = "system") -> None:
        entry = {"ts": time.time(), "user": user, "action": action}
        self.audit_log.append(entry)

    def audit_proof(self) -> str:
        blob = json.dumps(
            self.audit_log,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hash_bytes(blob).hex()


__all__ = ["Blockchain"]
