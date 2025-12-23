# Troubleshooting

Grab-and-go fixes by topic. Global flags always come **before** subcommands.

## CLI Arguments
- "unrecognized arguments" with `--user-db`/`--chain`/`--store`: run `python -m src.main --user-db users.json register ...`
- Subcommand typo: `python -m src.main -h`

## Files & Paths
- `FileNotFoundError`: check `--input`/`--source` exists.
- Permission denied: avoid protected folders; adjust OS permissions.

## TOTP / Login
- Invalid TOTP: sync system clock; confirm current secret.
- Lost TOTP: use `--backup-code`, then re-enroll.
- Password rejected: enforce 12+ chars with mixed classes.

## Messaging
- Decrypt fails: ensure correct recipient private key and envelope path.
- Signature invalid: verify sender/recipient keys are not swapped.

## File Encryption & Integrity
- Decrypt fails: match the original passphrase/key; confirm `.enc` file is intact.
- Integrity mismatch: recompute `file-hash`; confirm expected root.

## Blockchain
- Validation fails: confirm correct `chain.json`; avoid manual edits.
- Fork surprise: longer cumulative work wins—check both chains.

## Reset Local State (dev/testing)
- Remove git-ignored artifacts: `users.json`, `chain.json`, `keys/`, `*.enc`, `sample_dir*`, `msg.json`
- Regenerate keys and rerun flows.

## Need Help Fast
- List commands: `python -m src.main -h`
- Command help: `python -m src.main <subcommand> -h`
- Tests: `pytest -q`; lint: `flake8 src tests`
