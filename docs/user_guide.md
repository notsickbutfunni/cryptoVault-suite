# CryptoVault User Guide

## Setup
- Requires Python 3.10+.
- Create and activate a virtualenv, then install: `pip install -e .`
- Global CLI flags go **before** the subcommand: `python -m src.main --user-db users.json register ...`
- Default local artifacts (ignored): `users.json`, `chain.json`, `keys/`, `*.enc`, sample files.

## Quickstart Flows

### Register + Login (with TOTP or backup code)
1. Register: `python -m src.main --user-db users.json register --username alice --password "Str0ng!Password228"`
2. Enable TOTP: `python -m src.main --user-db users.json enable-totp --username alice` (record secret/URI and backup codes).
3. Login with TOTP: `python -m src.main --user-db users.json login --username alice --password "Str0ng!Password228" --totp <code>`
   - Or use a backup code: `--backup-code <code>`.

### Secure Messaging
1. Generate keys: `python -m src.main gen-keys --label alice` and `--label bob`.
2. Send: `python -m src.main send-message --from-label alice --to-label bob --message "hello" --out msg.json`
3. Receive: `python -m src.main receive-message --for-label bob --infile msg.json`

### File Encryption & Integrity
- Encrypt file: `python -m src.main file-encrypt --input plain.txt --output plain.txt.enc --passphrase "secret"`
- Decrypt file: `python -m src.main file-decrypt --input plain.txt.enc --output plain.dec.txt --passphrase "secret"`
- Hash + Merkle root: `python -m src.main file-hash --input plain.txt`
- Verify Merkle root: `python -m src.main file-verify --input plain.txt --expected-root <hexroot>`

### Directory Encryption
- Encrypt: `python -m src.main dir-encrypt --source mydir --target mydir.enc --passphrase "secret"`
- Decrypt: `python -m src.main dir-decrypt --source mydir.enc --target mydir.dec --passphrase "secret"`

### Blockchain Ledger & Audit
- Add blocks: `python -m src.main chain-add --data "tx1" --user cli`
- Validate chain: `python -m src.main chain-validate`
- Audit entry: `python -m src.main chain-audit --action "e2e_test" --user cli`
- Audit proof: `python -m src.main chain-proof`
- Fork resolve (against peer file): `python -m src.main chain-resolve --peer-chain other_chain.json`

## Flag Reference (global)
- `--store`: key store directory (default `keys`)
- `--user-db`: user database file (default `users.json`)
- `--chain`: blockchain file (default `chain.json`)
- `--default-difficulty`: mining difficulty for new chains (default `12`)

## Tips
- Keep secrets out of git; keys, user DB, and chain files are ignored by default.
- For passphrase-derived keys, use strong entropy; `--key-hex` and `--key-file` are supported for exact key control.
- TOTP is time-based; ensure system clock is accurate.
