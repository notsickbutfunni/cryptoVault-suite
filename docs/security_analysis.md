# Security Analysis

Compact threat model, crypto rationale, and operational guardrails.

## Threat Model
- Attacker can read/write local files (non-admin) and aims to steal keys or tamper with data/ledger.
- CLI is local-first; network interception is out of scope. Messaging assumes key exchange + signature verification.
- DoS not covered (heavy PoW, very large files).

## Cryptography

### Core Algorithms
- **Symmetric**: AES-256-GCM for confidentiality + integrity (cryptography library)
- **KDF**: Argon2id (primary) + PBKDF2-HMAC-SHA256 (≥100k iterations)
- **Hashing**: SHA-256 (custom FIPS 180-4 implementation + library fallback)
- **Asymmetric**: ECDH (P-256/secp256r1) for key exchange; ECDSA (P-256) for signatures
- **Integrity**: Merkle trees (custom implementation) over file chunks; SHA-256 block/tx roots
- **Ledger**: PoW (SHA-256) with configurable difficulty; longest cumulative work wins
- **Session tokens**: HMAC-SHA256 with hashed storage; expiry-based revocation
- **Backup codes**: SHA-256 hashed; single-use enforcement

### Custom Implementations (Educational & Cryptanalysis)
1. **SHA-256**: Complete FIPS 180-4 implementation (~200 lines); used in file integrity checks
2. **Merkle Tree**: Binary tree with sibling-based inclusion proofs; transaction verification
3. **Caesar Cipher**: Shift cipher with chi-squared frequency analysis breaker
4. **Vigenère Cipher**: Polyalphabetic cipher with Kasiski examination & IC-based key length detection
5. **Modular Exponentiation**: Square-and-multiply algorithm (O(log exp)); RSA foundation
6. **RSA**: Complete key generation with Miller-Rabin prime testing; secure random initialization

## Key Handling
- Keys and user DB stay local and are git-ignored; no cloud persistence.
- CLI accepts passphrase, hex, or file-based keys; passphrase route depends on PBKDF2 strength.
- TOTP secrets + backup codes stored in `users.json`; rotate by re-enrolling.

## Implemented Security Features
- ✅ **Rate limiting + account lockout**: 5-attempt lockout with 15-min expiry
- ✅ **Argon2id password hashing**: Memory-hard KDF (primary); PBKDF2 fallback
- ✅ **Session tokens**: HMAC-SHA256 with expiry and revocation
- ✅ **Hashed backup codes**: SHA-256 hashed with atomic single-use enforcement
- ✅ **Ephemeral ECDH**: Per-message keypair for perfect forward secrecy (PFS)
- ✅ **FEK wrapping**: File encryption key wrapped with AES-256-GCM
- ✅ **HMAC verification**: HMAC-SHA256 over ciphertext before decryption (tamper detection)
- ✅ **Constant-time comparisons**: `hmac.compare_digest()` for sensitive data
- ✅ **CSPRNG**: `secrets` module for all randomness
- ✅ **Custom crypto**: 6 implementations for educational cryptanalysis

## Known Limitations
- **Local-first**: No network encryption; messaging assumes pre-shared keys
- **PoW**: Static difficulty; no dynamic adjustment
- **Fork resolution**: Longest-work only; no peer networking/consensus
- **Memory**: Python garbage collection only (no explicit mlock); use `cryptography` library for sensitive ops
- **Storage**: Plaintext/temp files not securely wiped; relies on OS semantics
- **Hardware**: No HSM/secure enclave; keys live in files (can be wrapped with KEK in production)
- **Textbook RSA**: No OAEP padding in custom RSA (educational only; use library for production)

## Future Improvements
- Add WebAuthn/FIDO2 as optional second factor
- Wrap private keys with KEK and optional hardware-backed storage
- Add authenticated peer sync and richer fork detection/checkpoints
- Provide secure wipe routines and in-place streaming verification
- Implement password reset with signed recovery tokens
- Support RSA-OAEP for production-grade encryption

## Operational Guidance
- Keep system time synced for TOTP and signatures.
- Restrict filesystem permissions on `users.json`, `chain.json`, `keys/`, and encrypted outputs.
- Prefer explicit 32-byte keys or high-entropy passphrases for encryption.
- Verify integrity before consumption (`file-verify` or directory hash comparison).
