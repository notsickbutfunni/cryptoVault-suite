from src.blockchain.pow import (
    difficulty_to_target,
    meets_difficulty,
    mine,
    hash_bytes,
)


def test_difficulty_to_target_bounds():
    # 0 bits => max target
    assert difficulty_to_target(0) == (1 << 256) - 1
    # 256 bits => smallest target
    assert difficulty_to_target(256) == 0


def test_meets_difficulty_and_mine_small_bits():
    data = b"hello"
    bits = 8  # easy target for test
    nonce, h = mine(data, bits)
    assert meets_difficulty(h, bits)
    # recompute hash and check
    digest = hash_bytes(data + nonce.to_bytes(8, "big")).hex()
    assert digest == h
    assert meets_difficulty(digest, bits)
