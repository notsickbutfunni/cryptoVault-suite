# Troubleshooting

## CLI Argument Errors
- "unrecognized arguments" when using `--user-db`/`--chain`/`--store`: place global flags **before** the subcommand, e.g. `python -m src.main --user-db users.json register ...`.
- Wrong subcommand spelling: run `python -m src.main -h` to list commands.

## File/Path Errors
- `FileNotFoundError` during encrypt/decrypt: ensure `--input`/`--source` paths exist.
- Permission denied: check OS permissions; avoid writing into protected locations.

## TOTP / Login Issues
- Invalid TOTP: ensure clock is in sync; verify the account uses the current secret.
- Lost TOTP: use a backup code (`--backup-code`), then re-enroll TOTP.
- Password rejected: remember minimum length (12+) and character-class requirements.

## Messaging Issues
- Envelope decrypt fails: verify correct recipient private key; confirm envelope file path.
- Signature invalid: ensure sender/recipient keys are not swapped.

## File Encryption/Integrity
- Decrypt fails: confirm passphrase/key matches original; verify `.enc` file is intact.
- Integrity check fails: recompute `file-hash` on the original; ensure the expected root matches.

## Blockchain
- Chain validation fails: confirm you are using the correct `chain.json`; avoid manual edits.
- Fork resolution unexpected: check both chain files for validity; only longer cumulative work wins.

## Resetting Local State (dev/testing)
- Remove local artifacts: `users.json`, `chain.json`, `keys/`, `*.enc`, `sample_dir*`, `msg.json` (these are git-ignored).
- Regenerate keys and rerun flows as needed.

## Getting Help
- List commands: `python -m src.main -h`
- Command help: `python -m src.main <subcommand> -h`
- Run tests: `pytest -q`; lint: `flake8 src tests`
