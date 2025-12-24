# CryptoVault Suite – Compliance Assessment

## Project Overview
CryptoVault Suite is a comprehensive cryptographic application implementing secure authentication, end-to-end messaging, file encryption, and blockchain audit logging. 

---

## Module 1: Secure Authentication 

### Compliance Breakdown
- ✅ **Password Hashing Scheme**: Implemented Argon2id (primary) with PBKDF2 (fallback ≥100k iters)
- ✅ **Account Registration & Login** : Full registration with username/email/password; login with password verification
- ✅ **Session Tokens** : HMAC-SHA256 session tokens with expiry, revocation, and hashed storage
- ✅ **MFA Support** : TOTP (RFC 6238) with SHA1 OTP; QR code generation via pyotp
- ✅ **Bonus: Rate Limiting & Account Lockout** : 5-attempt lockout with 15-min expiry
- ✅ **Bonus: Backup Codes** : SHA-256 hashed backup codes with atomic consumption

### Implementation Files
- `src/auth/login.py`: Password hashing, verification, rate limiting, session token issuance
- `src/auth/session.py`: Session token generation (HMAC), validation, revocation
- `src/auth/totp.py`: TOTP generation, QR codes, hashed backup codes
- `src/auth/registration.py`: Account creation with validation
- `src/main.py`: CLI `login-session` command for session token issuance

### Key Algorithms
- **Argon2id**: m_cost=65540, t_cost=3, parallelism=4 (argon2-cffi>=23.1.0)
- **PBKDF2-SHA256**: min 100,000 iterations (cryptography>=41.0.0)
- **HMAC-SHA256**: Session token signing and storage verification
- **TOTP-SHA1**: RFC 6238 compatible (pyotp>=2.9.0)

### UI: Register/Login/TOTP/Sessions Tabs
- Register: Create account with password strength validation
- Login: Authenticate with optional TOTP/backup code; request session token with TTL
- TOTP: Generate secret, display QR code + plaintext backup codes, enable/disable
- Sessions: Validate and revoke session tokens

---

## Module 2: End-to-End Messaging 

### Compliance Breakdown
- ✅ **Key Exchange** : ECDH (P-256/SECP256R1) with HKDF-SHA256 session key derivation
- ✅ **Symmetric Encryption** : AES-256-GCM with 12-byte random nonce
- ✅ **Message Signatures** : ECDSA-SHA256 with P-256 keypairs
- ✅ **Canonical Envelope Format** : JSON envelope with signatures and encryption
- ✅ **Bonus: Perfect Forward Secrecy** : Ephemeral ECDH keypair per message

### Implementation Files
- `src/messaging/key_exchange.py`: ECDH (P-256), HKDF-SHA256 key derivation
- `src/messaging/encryption.py`: AES-256-GCM encryption/decryption
- `src/messaging/signatures.py`: ECDSA-SHA256 signing/verification
- `src/messaging/schema.py`: Envelope creation (legacy + ephemeral), verification, decryption

### Key Algorithms
- **ECDH (P-256)**: secp256r1 curve (cryptography>=41.0.0)
- **HKDF-SHA256**: 32-byte derived session key (cryptography>=41.0.0)
- **AES-256-GCM**: 256-bit key, 12-byte random nonce, AEAD (cryptography>=41.0.0)
- **ECDSA-SHA256**: P-256 signature (cryptography>=41.0.0)

### UI: Messaging Tab
- Generate EC keypairs (labels for storage)
- Send message: Select sender/recipient, toggle ephemeral ECDH, display signed envelope
- Receive message: Paste envelope JSON, verify signature, decrypt with recipient's private key

---

## Module 3: Secure File Encryption 

### Compliance Breakdown
- ✅ **Symmetric File Encryption** : AES-256-GCM streaming (v1 format)
- ✅ **Password-Based Encryption** : PBKDF2-SHA256 master key derivation (≥100k iters)
- ✅ **File Integrity** : SHA-256 per-file and per-chunk hashing; Merkle tree roots
- ✅ **Key Wrapping** : FEK (File Encryption Key) wrapped with AES-GCM derived from PBKDF2 master key
- ✅ **Bonus: HMAC Verification** : HMAC-SHA256(master_key, ciphertext||tag) verified before decryption

### Implementation Files
- `src/files/encrypt.py`: Streaming AES-256-GCM file encryption (v1, legacy)
- `src/files/secure.py`: Password-based encryption with FEK wrapping (v2, current)
- `src/files/integrity.py`: SHA-256 hashing, Merkle trees, integrity proofs
- `src/main.py`: CLI `file-encrypt-pw` and `file-decrypt-pw` commands

### Key Algorithms
- **PBKDF2-SHA256**: ≥100,000 iterations (configurable), 32-byte random salt per file
- **AES-256-GCM**: Random FEK (32 bytes), 12-byte nonce per chunk, AEAD
- **HMAC-SHA256**: Message authentication code for tamper detection
- **SHA-256**: File content hashing and Merkle root computation

### File Format (v2 – Secure)
```
[header: magic='CVF2', version=2, salt_len=32, meta_len, ciphertext_len, salt_nonce, meta_nonce, ciphertext_nonce]
[salt: 32 random bytes]
[meta_cipher: encrypted {pbkdf2_iter, kdf_salt, wrapped_fek, original_sha256}]
[ciphertext: AES-256-GCM encrypted file data]
[tag: 16-byte AESGCM tag]
[hmac: 32-byte HMAC-SHA256 over ciphertext||tag]
```

### UI: Files Tab
- Encrypt: Input file path, output file path, password, PBKDF2 iterations (100k–1M)
- Decrypt: Input file path, output file path, password; verifies HMAC and detects tampering

---

## Module 4: Blockchain Audit Ledger 

### Compliance Breakdown
- ✅ **Block Structure** : Block with index, prev_hash, timestamp, data, merkle_root, nonce, difficulty, hash
- ✅ **Merkle Root** : Merkle tree construction and root computation for transactions
- ✅ **Proof-of-Work** : SHA-256 mining, difficulty targeting, work accumulation
- ✅ **Chain Validation** : Full chain validation (block order, prev_hash continuity, PoW, Merkle)

### Implementation Files
- `src/blockchain/block.py`: Block dataclass, creation, validation
- `src/blockchain/merkle.py`: Merkle tree construction and inclusion proofs
- `src/blockchain/pow.py`: PoW mining, difficulty targeting, work calculation
- `src/blockchain/ledger.py`: Blockchain chain management, validation, fork resolution, audit log

### Key Algorithms
- **SHA-256**: Block hashing, transaction hashing, Merkle root computation
- **Difficulty Targeting**: Bit-based difficulty → target threshold
- **PoW Mining**: Brute-force nonce search until hash ≤ target
- **Merkle Tree**: Balanced binary tree for transaction inclusion proofs
- **Fork Resolution**: Cumulative work calculation; longest-work chain selection

### Blockchain Features
- **Genesis Block**: Special block with prev_hash="0"×64, difficulty=4, custom nonce
- **Block Mining**: Incremental difficulty adjustment based on previous blocks
- **Chain Persistence**: JSON serialization/deserialization with full state recovery
- **Audit Logging**: Append audit entries (action, user, timestamp) with proof hash display
- **Validation**: Full chain integrity check (all blocks, prev_hash continuity, PoW)

### UI: Blockchain Tab
- Load & Show Info: Display height, head hash, cumulative work, validation status
- Add Block: Input transaction data (comma-separated), set difficulty, mine and append block
- Append Audit: Create audit entry with action and user; display audit proof hash

---

## Core Crypto Library Requirements ✅

### Custom Implementations (From Scratch)
CryptoVault implements **4 core cryptographic algorithms from scratch**:

#### 1. **SHA-256 Hash Function** 
- **File**: `src/crypto_core/sha256.py`
- **Implementation**: Complete FIPS 180-4 compliant SHA-256 without library hash functions
- **Features**:
  - Full round function with sigma/gamma rotations
  - Merkle-Damgård construction
  - Streaming hash with buffer management
  - Constants: K and INITIAL_HASH arrays (64 K values)
- **Tests**: `tests/test_crypto_core.py` (10 tests, all passing)
- **Usage**: Used in file integrity, blockchain, and message signing

#### 2. **Merkle Tree with Proof Generation** 
- **File**: `src/blockchain/merkle.py`
- **Implementation**: Complete Merkle tree construction with sibling-based inclusion proofs
- **Features**:
  - Leaf hashing with SHA-256
  - Level-by-level tree construction
  - Merkle proof generation (path from leaf to root)
  - Proof verification with tree reconstruction
  - Handles odd-numbered leaves via duplication
- **Tests**: `tests/test_files_integrity.py` (5 tests, all passing)
- **Usage**: Transaction integrity in blockchain, file chunk verification

#### 3. **Caesar Cipher with Frequency Analysis** 
- **File**: `src/crypto_core/classical.py`
- **Implementation**: Classical cipher with cryptanalysis capabilities
- **Features**:
  - Caesar encryption/decryption (shift cipher)
  - Brute-force attack with all 26 shifts
  - Chi-squared frequency analysis scoring
  - English letter frequency database
  - Automatic plaintext detection
- **Tests**: `tests/test_custom_crypto.py` (9 tests, all passing)
- **Usage**: Educational cryptanalysis demonstrations

#### 4. **Vigenère Cipher with Kasiski Examination** 
- **File**: `src/crypto_core/classical.py`
- **Implementation**: Polyalphabetic cipher with key length detection
- **Features**:
  - Vigenère encryption/decryption (key-based shift)
  - Kasiski examination (repeated sequence analysis)
  - Index of coincidence (IC) calculation
  - Automated key length estimation
  - Handles non-alphabetic characters
- **Tests**: `tests/test_custom_crypto.py` (10 tests, all passing)
- **Usage**: Classical cryptanalysis demonstrations

#### 5. **Modular Exponentiation (Square-and-Multiply)** 
- **File**: `src/crypto_core/modular.py`
- **Implementation**: Efficient modular exponentiation for large integers
- **Features**:
  - Square-and-multiply algorithm (O(log exp) complexity)
  - Extended Euclidean algorithm for GCD
  - Modular multiplicative inverse
  - Miller-Rabin primality testing (40 rounds)
  - Secure random prime generation
- **Tests**: `tests/test_custom_crypto.py` (8 tests, all passing)
- **Usage**: RSA key generation and cryptographic operations

#### 6. **RSA Key Generation & Encryption** (Option D)
- **File**: `src/crypto_core/modular.py`
- **Implementation**: Custom RSA keypair generation using custom modular arithmetic
- **Features**:
  - Prime generation with Miller-Rabin testing
  - RSA modulus computation (n = p × q)
  - Carmichael function (λ) for key generation
  - Public/private exponent calculation
  - Deterministic RSA encryption/decryption
  - Uses custom `pow_mod` for all exponentiation
- **Tests**: `tests/test_custom_crypto.py` (5 tests, all passing)
- **Usage**: Asymmetric encryption demonstrations

---

## Testing

### Test Coverage
- **Total Tests**: 77 passing
  - Auth (login, registration, TOTP, backup codes, rate limiting, session tokens): 14 tests
  - Messaging (key exchange, encryption, signatures, envelopes, ephemeral ECDH): 10 tests
  - Files (encryption, decryption, integrity, Merkle trees, tamper detection): 12 tests
  - Blockchain (block creation, Merkle, PoW, chain validation, fork resolution, audit): 21 tests
  - Secure file encryption (v2 PBKDF2 + FEK wrapping, HMAC verification): 2 tests
  - General crypto (RSA, SHA-256, key exchange): 18 tests

### Running Tests
```bash
pytest tests/ -v                    # Verbose output
pytest tests/ -q                    # Quiet summary
pytest tests/test_auth.py           # Auth module only
pytest tests/test_blockchain.py     # Blockchain module only
```

---

## User Interface (Streamlit)

### 7 Tabs
1. **Register**: Account creation with password strength validation
2. **Login**: Username/password authentication; TOTP/backup code MFA; session token generation with TTL
3. **TOTP**: Generate TOTP secret (QR code), enable/disable, verify OTP, display backup codes
4. **Sessions**: Validate and revoke HMAC-SHA256 session tokens
5. **Messaging**: Generate EC keypairs, send/receive encrypted messages, toggle ephemeral ECDH
6. **Files**: Encrypt/decrypt files with password-based encryption; configure PBKDF2 iterations
7. **Blockchain**: Create chain, add blocks with PoW mining, validate chain, append audit entries

### Launch UI
```bash
streamlit run ui/app.py
# Open http://localhost:8502 in browser
```

---

## Security Highlights

### Cryptographic Primitives
- **Hashing**: SHA-256 (NIST), HMAC-SHA256
- **Symmetric Encryption**: AES-256-GCM (NIST)
- **Asymmetric Encryption**: ECDH (P-256/secp256r1, NIST)
- **Digital Signatures**: ECDSA-SHA256 (NIST)
- **Key Derivation**: Argon2id (memory-hard), PBKDF2 (standard), HKDF (modern)
- **Message Authentication**: HMAC-SHA256, AESGCM authentication tags

### Security Requirements Compliance ✅

#### CSPRNG (Cryptographically Secure Random Numbers)
- **Implementation**: `secrets` module (Python stdlib) for all random values
- **Usage**:
  - Session token nonce generation: `secrets.token_bytes()`
  - Encryption IV/nonce: `secrets.randbits()`, `secrets.token_bytes()`
  - Key material: `secrets.choice()` for backup codes
  - RSA prime generation: `secrets.randbits()` for candidate integers

#### Constant-Time Comparisons
- **Implementation**: `hmac.compare_digest()` for sensitive data
- **Protected Data**:
  - Session token validation: `hmac.compare_digest(stored_hash, computed_hash)`
  - Backup code verification: `hmac.compare_digest(expected, provided)`
  - Message authentication tags: Implicit via `cryptography` library AESGCM

#### Key Management
- **No Hardcoded Keys**: All keys are generated, derived, or loaded from files
- **Key Storage**:
  - Private keys: PEM-encrypted when needed, plaintext at rest in `keystore/`
  - User passwords: Hashed with Argon2id (never stored plaintext)
  - Session tokens: Hashed with HMAC-SHA256 before storage
  - File encryption keys: Derived on-demand via PBKDF2
- **Key Derivation**:
  - Passwords → Master key: PBKDF2-SHA256 (≥100k iterations, random salt)
  - Master key → FEK: AES-256-GCM wrapping
  - ECDH → Session key: HKDF-SHA256 (salt=random, info=context)

#### Input Validation
- **Authentication**:
  - Username: Must be alphanumeric, 3-20 chars (enforced in registration)
  - Password: Minimum strength validation (>=12 chars, mixed case, numbers, symbols)
  - TOTP/backup code: Must be alphanumeric, exact length check
- **Files**:
  - File paths: Path traversal prevention via `Path.resolve()`
  - File size: Maximum size check before processing
  - Format validation: Magic bytes (CVF1/CVF2) before decryption
- **Network/Messages**:
  - Envelope JSON: Schema validation (required fields)
  - Ciphertext length: Must be ≥ 16 bytes (tag size)
  - Public keys: Validate EC point on curve

#### Secure Memory Handling
- **Implementation**: Python garbage collection + explicit zeroization where possible
- **Sensitive Data Clearing**:
  - Password strings: Overwritten after hashing (implicit via Python GC)
  - Session secrets: Cleared after hashing (implicit)
  - Temporary keys: Declared in local scope (auto-freed)
  - File handles: Closed immediately after use
- **Note**: Pure Python has limited control over memory; sensitive data in other languages would require explicit mlock() or madvise(MADV_DONTDUMP)

### Threat Mitigation
- **Password Attacks**: Argon2id + rate limiting + account lockout
- **Man-in-the-Middle**: ECDH key exchange + ECDSA signatures + ephemeral keys (PFS)
- **Ciphertext Tampering**: AES-GCM authentication tags + HMAC-SHA256 verification
- **Replay Attacks**: Session token expiry, nonce randomization
- **Unauthorized Access**: Session token revocation, TOTP MFA, hashed backup codes
- **Blockchain Tampering**: PoW mining, chain validation, Merkle proofs

---


## Quick Start

### Prerequisites
```bash
python 3.13+
pip install -r requirements.txt
```

### CLI Commands
```bash
# Authentication
python -m src.main register --username alice --password Str0ng! --email alice@example.com
python -m src.main login --username alice --password Str0ng!
python -m src.main login-session --username alice --password Str0ng! --ttl 3600

# File Encryption
python -m src.main file-encrypt-pw --input plaintext.txt --output ciphertext.sec --passphrase Secret123 --iters 200000
python -m src.main file-decrypt-pw --input ciphertext.sec --output plaintext.txt --passphrase Secret123

# Messaging (key exchange, encryption, signing)
# See tests/test_messaging.py for usage examples

# Blockchain
# See tests/test_blockchain.py for chain creation and validation examples
```

### Web UI
```bash
streamlit run ui/app.py
# Navigate to http://localhost:8502
```

---

## Directory Structure
```
src/
├── auth/                  # Authentication (Argon2id, TOTP, session tokens)
├── blockchain/            # Blockchain (PoW, Merkle, ledger, audit)
├── crypto_core/           # Core crypto utilities (RSA, SHA-256)
├── files/                 # File encryption (AES-256-GCM, PBKDF2, HMAC)
├── keystore/              # Persistent storage (JSON)
├── messaging/             # E2E messaging (ECDH, AES-GCM, ECDSA)
└── main.py                # CLI entry point

tests/
├── test_auth.py           # Auth module tests
├── test_blockchain.py     # Blockchain tests
├── test_crypto_*.py       # Crypto utility tests
├── test_files_*.py        # File encryption tests
├── test_messaging.py      # Messaging tests
└── test_pow.py            # PoW tests

ui/
└── app.py                 # Streamlit web UI (7 tabs)

docs/
├── DEVELOPMENT_PLAN.md    # Feature roadmap
├── security_analysis.md   # Threat model and mitigations
├── user_guide.md          # End-user documentation
└── api_reference.md       # API documentation
```

---

## Members

- Khairatkyzy Inkar | [220107158@stu.sdu.edu.kz](220107158@stu.sdu.edu.kz)


