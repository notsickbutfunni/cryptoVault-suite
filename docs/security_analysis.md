# Security Analysis

Compact threat model, crypto rationale, and operational guardrails.

## Threat Model
- Attacker can read/write local files (non-admin) and aims to steal keys or tamper with data/ledger.
- CLI is local-first; network interception is out of scope. Messaging assumes key exchange + signature verification.
- DoS not covered (heavy PoW, very large files).

## Cryptography
- Symmetric: AES-256-GCM for confidentiality + integrity.
- KDF: PBKDF2-HMAC-SHA256 (100k iterations); SHA-256 for hashing.
- Asymmetric: ECDH (secp256r1) for session keys; ECDSA (secp256r1) for signatures.
- Integrity: Merkle trees over file chunks; SHA-256 for block/tx roots.
- Ledger: PoW with configurable difficulty; longest cumulative work wins.

## Key Handling
- Keys and user DB stay local and are git-ignored; no cloud persistence.
- CLI accepts passphrase, hex, or file-based keys; passphrase route depends on PBKDF2 strength.
- TOTP secrets + backup codes stored in `users.json`; rotate by re-enrolling.

## Known Limitations
- No account lockout/rate limiting; local DB only.
- Static PoW difficulty; no dynamic adjustment.
- Fork resolution is longest-work only; no peer networking/consensus.
- Plaintext/temp files not securely wiped; relies on OS semantics.
- No HSM/secure enclave; keys live in files.

## Future Improvements
- Add lockout/rate limiting and audit triggers on auth failures.
- Move password hashing to Argon2id or tunable KDF with stronger defaults.
- Wrap private keys with a KEK and optionally hardware-backed storage.
- Add authenticated peer sync and richer fork detection/checkpoints.
- Provide secure wipe routines and streaming in-place verification.
- TOTP drift detection and optional WebAuthn/FIDO2 second factor.

## Operational Guidance
- Keep system time synced for TOTP and signatures.
- Restrict filesystem permissions on `users.json`, `chain.json`, `keys/`, and encrypted outputs.
- Prefer explicit 32-byte keys or high-entropy passphrases for encryption.
- Verify integrity before consumption (`file-verify` or directory hash comparison).
