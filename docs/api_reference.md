# API Reference

Minimal signatures for quick lookup. All functions live under `src/` and mirror the CLI.

## Authentication
- `RegistrationManager.register(username, password, email="") -> (bool, msg)`
- `RegistrationManager.validate_username/password(...) -> (bool, msg)`
- `LoginManager.login(username, password) -> (bool, msg)`
- `LoginManager.verify_password(password, stored_hash, stored_salt) -> bool`
- `TOTPManager.generate_secret(username) -> (secret, uri)`
- `TOTPManager.enable_totp(username, secret) -> (bool, msg)`
- `TOTPManager.verify_totp(username, token, window=1) -> (bool, msg)`
- `TOTPManager.verify_backup_code(username, code) -> (bool, msg)`

## Messaging
- `generate_ec_keypair() -> (priv_pem, pub_pem)`
- `ecdh_session_key_pair(sender_priv_pem, recipient_pub_pem) -> (key, salt)`
- `create_envelope(plaintext, sender_private_pem, recipient_public_pem, aad=b"CryptoVault") -> dict`
- `envelope_to_json(envelope: dict) -> str`
- `verify_and_decrypt_envelope(envelope_json: str, recipient_private_pem: bytes, aad=b"CryptoVault") -> bytes`

## Files — Encryption
- `encrypt_file(input_path, output_path, key, metadata=None, chunk_size=64*1024, progress_cb=None) -> dict`
- `decrypt_file(input_path, output_path, key, chunk_size=64*1024, progress_cb=None) -> dict`
- `encrypt_directory(source_dir, target_dir, key, chunk_size=64*1024, progress_cb=None) -> None`
- `decrypt_directory(source_dir, target_dir, key, chunk_size=64*1024, progress_cb=None) -> None`

## Files — Integrity
- `hash_file(path, chunk_size=1_048_576) -> bytes`
- `file_chunk_hashes(path, chunk_size=1_048_576) -> List[bytes]`
- `merkle_root(leaves) -> bytes`
- `merkle_tree(leaves) -> List[List[bytes]]`
- `merkle_proof(leaves, index) -> List[(bytes, str)]`
- `verify_proof(leaf_hash, proof, root) -> bool`
- `file_merkle_root(path, chunk_size=1_048_576) -> bytes`
- `verify_file_integrity(path, expected_root, chunk_size=1_048_576) -> bool`
- `detect_tamper(path, expected_root, chunk_size=1_048_576) -> bool`

## Blockchain
- `Block.compute_merkle(data) -> str`
- `create_block(index, prev_hash, data, difficulty) -> Block`
- `genesis_block(data=None, difficulty=4) -> Block`
- `validate_block(prev_block, block) -> bool`
- `Blockchain.add_block(data=None, difficulty=None) -> Block`
- `Blockchain.is_valid() -> bool`
- `Blockchain.cumulative_work() -> int`
- `Blockchain.save(path) -> None`
- `Blockchain.load(path) -> Blockchain`
- `Blockchain.resolve_fork(other_chain) -> Blockchain`
- `Blockchain.append_audit(action, user="system") -> None`
- `Blockchain.audit_proof() -> str`

## PoW Utilities
- `hash_bytes(data: bytes) -> bytes`
- `difficulty_to_target(bits: int) -> int`
- `meets_difficulty(hex_hash: str, bits: int) -> bool`
- `mine(blob: bytes, bits: int) -> (nonce: int, hex_hash: str)`
