# CryptoVault User Guide

Your fast lane to the CLI: flows, flags, and gotchas in one place.

## Setup (2 steps)
- Python 3.10+
- `pip install -e .` inside an activated virtualenv (`./venv/Scripts/Activate.ps1` on PowerShell)

Global flags go **before** the subcommand: `python -m src.main --user-db users.json register ...`

## Core Flows

### Register + Login (TOTP ready)
1) Register: `python -m src.main --user-db users.json register --username alice --password "Str0ng!Password228"`
2) Enable TOTP: `python -m src.main --user-db users.json enable-totp --username alice` (save secret URI + backup codes)
3) Login: `python -m src.main --user-db users.json login --username alice --password "Str0ng!Password228" --totp <code>`
   - Fallback: `--backup-code <code>`

### Secure Messaging (Alice → Bob)
1) Keys: `python -m src.main gen-keys --label alice` and `--label bob`
2) Send: `python -m src.main send-message --from-label alice --to-label bob --message "hello" --out msg.json`
3) Receive: `python -m src.main receive-message --for-label bob --infile msg.json`

### File Encryption + Integrity
- Encrypt: `python -m src.main file-encrypt --input plain.txt --output plain.txt.enc --passphrase "secret"`
- Decrypt: `python -m src.main file-decrypt --input plain.txt.enc --output plain.dec.txt --passphrase "secret"`
- Hash/Merkle: `python -m src.main file-hash --input plain.txt`
- Verify: `python -m src.main file-verify --input plain.txt --expected-root <hexroot>`

### Directory Encryption
- Encrypt: `python -m src.main dir-encrypt --source mydir --target mydir.enc --passphrase "secret"`
- Decrypt: `python -m src.main dir-decrypt --source mydir.enc --target mydir.dec --passphrase "secret"`

### Blockchain Ledger & Audit
- Add data: `python -m src.main chain-add --data "tx1" --user cli`
- Validate: `python -m src.main chain-validate`
- Audit entry: `python -m src.main chain-audit --action "e2e_test" --user cli`
- Generate proof: `python -m src.main chain-proof`
- Resolve fork: `python -m src.main chain-resolve --peer-chain other_chain.json`

## Global Flags
- `--store` → key store directory (default `keys`)
- `--user-db` → user database file (default `users.json`)
- `--chain` → blockchain file (default `chain.json`)
- `--default-difficulty` → PoW bits for new chains (default `12`)

## Pro Tips
- Keep secrets and artifacts out of git (`users.json`, `chain.json`, `keys/`, `*.enc`).
- For deterministic keys use `--key-hex` or `--key-file`; otherwise pick high-entropy passphrases.
- TOTP needs accurate system time; sync your clock to avoid rejects.
- Sample data lives in `sample.txt*` and `sample_dir*` for quick dry-runs.
