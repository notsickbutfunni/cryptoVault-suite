# API Reference

Minimal signatures for quick lookup. All functions live under `src/` and mirror the CLI.

## Custom Crypto (From-Scratch Implementations)

### SHA-256 Hash Function
- `SHA256(data=b"") -> SHA256` — Streaming SHA-256 object (FIPS 180-4)
- `SHA256.update(data: bytes) -> None` — Add data to hash
- `SHA256.digest() -> bytes` — Get 32-byte hash
- `SHA256.hexdigest() -> str` — Get 64-char hex hash
- `SHA256.copy() -> SHA256` — Clone hash state
- `sha256(data: bytes) -> bytes` — One-shot hashing
- `sha256_hex(data: bytes) -> str` — One-shot hex hashing

### Caesar Cipher
- `CaesarCipher.encrypt(plaintext: str, shift: int) -> str`
- `CaesarCipher.decrypt(ciphertext: str, shift: int) -> str`
- `CaesarCipher.brute_force(ciphertext: str) -> List[(shift, plaintext, score)]`
- `CaesarCipher._chi_squared_score(text: str) -> float` — Frequency analysis scoring

### Vigenère Cipher
- `VigenèreCipher.encrypt(plaintext: str, key: str) -> str`
- `VigenèreCipher.decrypt(ciphertext: str, key: str) -> str`
- `VigenèreCipher.kasiski_examination(ciphertext: str) -> Dict[int, int]` — Key length detection
- `VigenèreCipher.index_of_coincidence(text: str) -> float` — IC calculation
- `VigenèreCipher.estimate_key_length_ic(ciphertext: str) -> int` — IC-based key length

### Modular Arithmetic
- `pow_mod(base: int, exp: int, mod: int) -> int` — Square-and-multiply exponentiation
- `extended_gcd(a: int, b: int) -> (gcd, x, y)` — Extended Euclidean algorithm
- `mod_inverse(a: int, m: int) -> int` — Modular multiplicative inverse
- `is_prime(n: int, k=40) -> bool` — Miller-Rabin primality test
- `generate_prime(bit_length: int) -> int` — Secure random prime generation
- `gcd(a: int, b: int) -> int` — Euclidean algorithm
- `lcm(a: int, b: int) -> int` — Least common multiple

### RSA Key Generation & Encryption
- `RSAKeyGenerator.generate_keypair(bit_length=2048) -> ((n, e), (n, d))` — RSA keypair
- `RSAKeyGenerator.encrypt(public_key: (n, e), plaintext: int) -> int`
- `RSAKeyGenerator.decrypt(private_key: (n, d), ciphertext: int) -> int`

### Merkle Tree
- `merkle_leaves(items) -> List[bytes]` — Hash transaction items
- `merkle_root(items) -> bytes` — Single Merkle root
- `merkle_tree(items) -> List[List[bytes]]` — Full tree levels
- `merkle_proof(items, index: int) -> List[(bytes, str)]` — Inclusion proof
- `verify_proof(leaf_hash, proof, root) -> bool` — Proof verification

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
