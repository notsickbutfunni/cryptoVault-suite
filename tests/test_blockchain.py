import hashlib

from src.blockchain.block import create_block, genesis_block, validate_block
from src.blockchain.merkle import merkle_root, merkle_proof, verify_proof


def test_merkle_root_and_proof():
    txs = ["tx1", "tx2", "tx3", "tx4"]
    root = merkle_root(txs)
    for idx, tx in enumerate(txs):
        proof = merkle_proof(txs, idx)
        assert verify_proof(tx, proof, root)


def test_block_mining_and_validation():
    data = ["txA", "txB"]
    blk = create_block(index=1, prev_hash="0" * 64, data=data, difficulty=12)
    assert blk.hash
    assert blk.is_valid_hash()

    # validate against prev hash
    prev = genesis_block([], difficulty=12)
    chained = create_block(
        index=prev.index + 1,
        prev_hash=prev.hash,
        data=data,
        difficulty=12,
    )
    assert validate_block(prev, chained)

    # recomputed hash should be consistent
    assert blk.hash == blk.compute_hash()


def test_genesis_merkle_for_empty_data():
    blk = genesis_block([], difficulty=8)
    assert blk.index == 0
    assert blk.prev_hash == "0" * 64
    assert blk.is_valid_hash()
    assert blk.merkle_root == hashlib.sha256(b"").hexdigest()
