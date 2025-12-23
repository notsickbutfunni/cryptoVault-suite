# CryptoVault Suite

Command-line vault for MFA auth, end-to-end messaging, encrypted files/dirs, and a PoW-backed audit ledger.

## Why CryptoVault
- One CLI for auth + messaging + storage + audit
- AES-GCM, PBKDF2, ECDH/ECDSA, Merkle roots, PoW ledger
- Ships with realistic samples (`sample.txt*`, `sample_dir*`)

## Install (Python 3.10+)
1) `python -m venv venv`
2) Activate: `./venv/Scripts/Activate.ps1` (PowerShell) or `source venv/bin/activate`
3) `pip install -e .`

## 60s CLI Tour
Global flags go **before** the subcommand.

| Flow | Command | Notes |
| --- | --- | --- |
| Register | `python -m src.main --user-db users.json register --username alice --password "Str0ng!Password228"` | Creates local user DB row |
| Enable TOTP | `... enable-totp --username alice` | Saves secret/backup codes |
| Login | `... login --username alice --password "Str0ng!Password228" --totp <code>` | Use `--backup-code` as fallback |
| Messaging | `gen-keys`, `send-message`, `receive-message` | EC keys + envelope encryption/signatures |
| Files | `file-encrypt`, `file-decrypt`, `file-hash`, `file-verify` | AES-GCM + Merkle integrity |
| Directories | `dir-encrypt`, `dir-decrypt` | Streaming encryption per file |
| Blockchain | `chain-add`, `chain-validate`, `chain-audit`, `chain-proof`, `chain-resolve` | PoW, longest-work fork |

## Run & Test
- Tests: `pytest -q`
- Lint: `flake8 src tests`

## Docs
- User guide with end-to-end flows: [docs/user_guide.md](docs/user_guide.md)
- API surface (concise): [docs/api_reference.md](docs/api_reference.md)
- Troubleshooting cheatsheet: [docs/troubleshooting.md](docs/troubleshooting.md)
- Threat model and crypto picks: [docs/security_analysis.md](docs/security_analysis.md)

## Security Posture
- Git-ignored local artifacts: `users.json`, `chain.json`, `keys/`, `*.enc`
- Use strong passphrases or explicit 32-byte keys; prefer synced system clock for TOTP
- PoW-backed audit for tamper evidence; verify integrity before use (`file-verify`)