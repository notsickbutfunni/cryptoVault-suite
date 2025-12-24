# CryptoVault User Guide

Your fast lane to the CLI: flows, flags, and gotchas in one place.

## Setup (2 steps)
- Python 3.13+ (tested on 3.13.5)
- `pip install -r requirements.txt` inside an activated virtualenv
  - Windows PowerShell: `./venv/Scripts/Activate.ps1`
  - Unix/macOS bash: `source venv/bin/activate`

Global flags go **before** the subcommand: `python -m src.main --user-db users.json register ...`

## Web UI (Streamlit)
```bash
streamlit run ui/app.py
# Open http://localhost:8502 in browser
```

7 tabs: Register, Login, TOTP, Sessions, Messaging, Files, Blockchain

## Core Flows

### Register + Login (TOTP + Backup Codes)
1) Register: `python -m src.main register --username alice --password "Str0ng!Password228" --email alice@example.com`
2) Enable TOTP: `python -m src.main enable-totp --username alice`
   - Save displayed QR code + plaintext backup codes to secure location
3) Login: `python -m src.main login --username alice --password "Str0ng!Password228"`
   - Verify with TOTP: `--totp <6-digit-code>`
   - Or backup code: `--backup-code <code>`
4) Session token (optional): `python -m src.main login-session --username alice --password "Str0ng!Password228" --ttl 3600`
   - Returns HMAC-SHA256 token (expires in 1 hour)
   - Validate: `python -m src.main validate-session --token <token>`

### Secure Messaging (Alice → Bob)
1) Keys: `python -m src.main gen-keys --label alice` and `--label bob`
2) Send: `python -m src.main send-message --from-label alice --to-label bob --message "hello" --out msg.json`
3) Receive: `python -m src.main receive-message --for-label bob --infile msg.json`

### File Encryption + Integrity
**Password-Based Encryption (v2 Secure Format)**:
- Encrypt: `python -m src.main file-encrypt-pw --input plain.txt --output plain.sec --passphrase "secret" --iters 200000`
  - PBKDF2-SHA256 master key derivation (≥100k iterations, random salt)
  - Random FEK wrapped with AES-256-GCM
  - HMAC-SHA256 verification before decryption (tamper detection)
- Decrypt: `python -m src.main file-decrypt-pw --input plain.sec --output plain.txt --passphrase "secret"`
  - Verifies HMAC; fails if tampering detected

**Legacy Encryption (v1)**:
- Encrypt: `python -m src.main file-encrypt --input plain.txt --output plain.txt.enc --key <32-hex-bytes>`
- Decrypt: `python -m src.main file-decrypt --input plain.txt.enc --output plain.dec.txt --key <32-hex-bytes>`

**Integrity Verification**:
- Hash: `python -m src.main file-hash --input plain.txt`
  - Returns SHA-256 hash + Merkle root (1MB chunks)
- Verify: `python -m src.main file-verify --input plain.txt --expected-root <hexroot>`
  - Confirms file integrity against expected hash

### Directory Encryption
- Encrypt: `python -m src.main dir-encrypt --source mydir --target mydir.enc --key <32-hex-bytes>`
- Decrypt: `python -m src.main dir-decrypt --source mydir.enc --target mydir.dec --key <32-hex-bytes>`
  - Recursively encrypts all files in directory

### Blockchain Ledger & Audit
- Add block: `python -m src.main chain-add --data "tx1,tx2" --difficulty 12`
  - Parses comma-separated transactions; mines block with PoW
- Validate chain: `python -m src.main chain-validate`
  - Checks full chain integrity (prev_hash, Merkle root, PoW)
- Audit entry: `python -m src.main chain-audit --action "e2e_test" --user alice`
  - Appends audit log with timestamp
- Audit proof: `python -m src.main chain-proof`
  - Generates hash-based audit trail proof
- Resolve fork: `python -m src.main chain-resolve --peer-chain other_chain.json`
  - Selects chain with highest cumulative work

## Global Flags
- `--store` → key store directory (default `keys`)
- `--user-db` → user database file (default `users.json`)
- `--chain` → blockchain file (default `chain.json`)
- `--default-difficulty` → PoW bits for new chains (default `12`)

## Pro Tips
- **TOTP Timing**: Sync system clock; TOTP windows are strict (±30 seconds)
- **Passphrases**: High-entropy recommended; e.g., 4+ random words or 16+ mixed-case alphanumeric
- **PBKDF2 Iterations**: Use ≥100k; 200k-400k recommended for password-based file encryption
- **File Encryption**: v2 format (secure.py) preferred over v1 for new files; includes HMAC verification
- **Backup Codes**: Save backup codes to secure offline location immediately after TOTP enrollment
- **Session Tokens**: Default TTL is 3600 seconds (1 hour); revoke before expiry if needed
- **Git**: Exclude `users.json`, `chain.json`, `keys/`, `*.sec`, `*.enc` from version control
- **Key Management**: Use `--key-hex <32-byte-hex>` for deterministic encryption; otherwise passphrase route via PBKDF2
- **Sample Data**: Test with `sample.txt` and `sample_dir/` for quick CLI dry-runs
- **Blockchain Difficulty**: Start with `--difficulty 8` for testing; production use 12-16 (PoW scales linearly with difficulty)

## Security Notes
- **Rate Limiting**: 5 failed login attempts lock account for 15 minutes
- **Session Tokens**: HMAC-SHA256 hashed in storage; compared via constant-time function
- **Ephemeral ECDH**: Messaging uses per-message ephemeral key for perfect forward secrecy (default)
- **FEK Wrapping**: File encryption keys wrapped with AES-256-GCM; random per file
- **HMAC Verification**: File decryption verifies HMAC before any decryption (tamper detection)
- **Constant-Time Comparisons**: All sensitive comparisons use `hmac.compare_digest()`
- **CSPRNG**: All randomness via `secrets` module (cryptographically secure)
