"""CLI entrypoint for CryptoVault: auth, messaging, files, and blockchain."""

import argparse
import hashlib
import sys
from pathlib import Path
from typing import List, Optional

from src.auth.login import LoginManager
from src.auth.registration import RegistrationManager
from src.auth.totp import TOTPManager
from src.blockchain.ledger import Blockchain
from src.files.encrypt import (
    decrypt_directory,
    decrypt_file,
    encrypt_directory,
    encrypt_file,
)
from src.files.integrity import (
    file_merkle_root,
    hash_file,
    verify_file_integrity,
)
from src.messaging.key_exchange import generate_ec_keypair
from src.messaging.schema import (
    create_envelope,
    envelope_to_json,
    verify_and_decrypt_envelope,
)
from src.keystore.fs_store import (
    ensure_store,
    list_keys,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)


def cmd_gen_keys(args: argparse.Namespace) -> None:
    ensure_store(args.store)
    priv, pub = generate_ec_keypair()
    p1 = save_private_key(args.label, priv, base_dir=args.store)
    p2 = save_public_key(args.label, pub, base_dir=args.store)
    print(f"Generated EC keys: {p1}, {p2}")


def _read_message(args: argparse.Namespace) -> bytes:
    if args.message is not None:
        return args.message.encode("utf-8")
    if args.infile is not None:
        with open(args.infile, "rb") as f:
            return f.read()
    raise SystemExit("Provide --message or --infile")


def cmd_send(args: argparse.Namespace) -> None:
    priv = load_private_key(args.from_label, base_dir=args.store)
    pub = load_public_key(args.to_label, base_dir=args.store)
    plaintext = _read_message(args)
    env = create_envelope(plaintext, priv, pub)
    json_text = envelope_to_json(env)
    if args.out is None:
        print(json_text)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(json_text)
        print(f"Wrote envelope: {args.out}")


def cmd_receive(args: argparse.Namespace) -> None:
    priv = load_private_key(args.for_label, base_dir=args.store)
    with open(args.infile, "r", encoding="utf-8") as f:
        env_json = f.read()
    plaintext = verify_and_decrypt_envelope(env_json, priv)
    if args.out is None:
        sys.stdout.buffer.write(plaintext + b"\n")
    else:
        with open(args.out, "wb") as f:
            f.write(plaintext)
        print(f"Wrote decrypted: {args.out}")


def cmd_list(args: argparse.Namespace) -> None:
    ensure_store(args.store)
    for name in list_keys(base_dir=args.store):
        print(name)


def _key_from_args(args: argparse.Namespace) -> bytes:
    """Derive a 32-byte key from hex, passphrase, or file contents."""
    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
    elif args.passphrase:
        key = hashlib.sha256(args.passphrase.encode("utf-8")).digest()
    elif args.key_file:
        key = Path(args.key_file).read_bytes()
    else:
        raise SystemExit("Provide --key-hex, --passphrase, or --key-file")

    if len(key) != 32:
        raise SystemExit("Key must be 32 bytes (256-bit)")
    return key


def cmd_encrypt_file(args: argparse.Namespace) -> None:
    key = _key_from_args(args)
    encrypt_file(
        args.input,
        args.output,
        key,
        chunk_size=args.chunk_size,
    )
    print(f"Encrypted {args.input} -> {args.output}")


def cmd_decrypt_file(args: argparse.Namespace) -> None:
    key = _key_from_args(args)
    meta = decrypt_file(
        args.input,
        args.output,
        key,
        chunk_size=args.chunk_size,
    )
    print(f"Decrypted {args.input} -> {args.output}")
    print(f"Metadata: {meta}")


def cmd_encrypt_dir(args: argparse.Namespace) -> None:
    key = _key_from_args(args)
    encrypt_directory(
        args.source,
        args.target,
        key,
        chunk_size=args.chunk_size,
    )
    print(f"Encrypted directory {args.source} -> {args.target}")


def cmd_decrypt_dir(args: argparse.Namespace) -> None:
    key = _key_from_args(args)
    decrypt_directory(
        args.source,
        args.target,
        key,
        chunk_size=args.chunk_size,
    )
    print(f"Decrypted directory {args.source} -> {args.target}")


def cmd_file_hash(args: argparse.Namespace) -> None:
    file_hash = hash_file(args.input)
    root = file_merkle_root(args.input)
    print(f"SHA-256: {file_hash.hex()}")
    print(f"Merkle root: {root.hex()}")


def cmd_file_verify(args: argparse.Namespace) -> None:
    expected_root = bytes.fromhex(args.expected_root)
    ok = verify_file_integrity(args.input, expected_root)
    if not ok:
        raise SystemExit("Integrity check failed")
    print("Integrity verified")


def cmd_register(args: argparse.Namespace) -> None:
    reg = RegistrationManager(args.user_db)
    ok, msg = reg.register(
        args.username, args.password, email=args.email or ""
    )
    if not ok:
        raise SystemExit(msg)
    print(msg)


def cmd_login(args: argparse.Namespace) -> None:
    login_mgr = LoginManager(args.user_db)
    ok, msg = login_mgr.login(args.username, args.password)
    if not ok:
        raise SystemExit(msg)

    totp_mgr = TOTPManager(args.user_db)
    user = totp_mgr.users.get(args.username, {})
    if user.get("totp_enabled"):
        if args.totp:
            ok, msg = totp_mgr.verify_totp(args.username, args.totp)
        elif args.backup_code:
            ok, msg = totp_mgr.verify_backup_code(
                args.username, args.backup_code
            )
        else:
            raise SystemExit("TOTP token or --backup-code required")
        if not ok:
            raise SystemExit(msg)

    login_mgr.update_last_login(args.username)
    print(f"Authenticated {args.username}")


def cmd_enable_totp(args: argparse.Namespace) -> None:
    totp_mgr = TOTPManager(args.user_db)
    if args.username not in totp_mgr.users:
        raise SystemExit("User not found; register first")

    secret, uri = totp_mgr.generate_secret(args.username)
    ok, msg = totp_mgr.enable_totp(args.username, secret)
    if not ok:
        raise SystemExit(msg)

    ok, codes = totp_mgr.get_backup_codes(args.username)
    print("TOTP enabled. Add this account to your authenticator:")
    print(f"Secret: {secret}")
    print(f"URI: {uri}")
    if ok:
        print("Backup codes:")
        for code in codes:
            print(f"  {code}")


def cmd_backup_codes(args: argparse.Namespace) -> None:
    totp_mgr = TOTPManager(args.user_db)
    ok, codes = totp_mgr.get_backup_codes(args.username)
    if not ok:
        raise SystemExit("User not found")
    print("Backup codes:")
    for code in codes:
        print(code)


def _load_chain(path: str, default_difficulty: int) -> Blockchain:
    if Path(path).exists():
        return Blockchain.load(path)
    return Blockchain(default_difficulty=default_difficulty)


def cmd_chain_add(args: argparse.Namespace) -> None:
    chain = _load_chain(args.chain, args.default_difficulty)
    payload: List[str] = []
    if args.data:
        payload.extend(args.data)
    if args.data_file:
        text = Path(args.data_file).read_text(encoding="utf-8")
        payload.extend([line for line in text.splitlines() if line.strip()])
    blk = chain.add_block(payload)
    chain.append_audit(f"add_block:{blk.index}", user=args.user)
    chain.save(args.chain)
    print(f"Added block {blk.index} (difficulty {blk.difficulty})")


def cmd_chain_info(args: argparse.Namespace) -> None:
    chain = _load_chain(args.chain, args.default_difficulty)
    head = chain.head
    print(f"Height: {chain.height}")
    print(f"Head hash: {head.hash}")
    print(f"Cumulative work: {chain.cumulative_work()}")


def cmd_chain_validate(args: argparse.Namespace) -> None:
    chain = _load_chain(args.chain, args.default_difficulty)
    if not chain.is_valid():
        raise SystemExit("Chain validation failed")
    print("Chain is valid")


def cmd_chain_audit(args: argparse.Namespace) -> None:
    chain = _load_chain(args.chain, args.default_difficulty)
    chain.append_audit(args.action, user=args.user)
    chain.save(args.chain)
    print("Audit entry appended")
    print(f"Proof: {chain.audit_proof()}")


def cmd_chain_proof(args: argparse.Namespace) -> None:
    chain = _load_chain(args.chain, args.default_difficulty)
    print(chain.audit_proof())


def cmd_chain_resolve(args: argparse.Namespace) -> None:
    local = _load_chain(args.chain, args.default_difficulty)
    peer = Blockchain.load(args.peer_chain)
    chosen = local.resolve_fork(peer)
    chosen.save(args.chain)
    print(f"Selected chain with height {chosen.height}")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser; global flags must precede subcommands."""
    p = argparse.ArgumentParser(prog="cryptovault")
    p.add_argument("--store", default="keys", help="Key store directory")
    p.add_argument(
        "--user-db", default="users.json", help="User database path"
    )
    p.add_argument(
        "--chain", default="chain.json", help="Blockchain file path"
    )
    p.add_argument(
        "--default-difficulty",
        type=int,
        default=12,
        help="Default difficulty for new chains",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-keys", help="Generate EC keypair")
    g.add_argument("--label", required=True)
    g.set_defaults(func=cmd_gen_keys)

    s = sub.add_parser(
        "send-message",
        help="Encrypt and sign a message to recipient",
    )
    s.add_argument("--from-label", required=True)
    s.add_argument("--to-label", required=True)
    s.add_argument("--message")
    s.add_argument("--infile")
    s.add_argument("--out")
    s.set_defaults(func=cmd_send)

    r = sub.add_parser(
        "receive-message",
        help="Verify and decrypt an envelope",
    )
    r.add_argument("--for-label", required=True)
    r.add_argument("--infile", required=True)
    r.add_argument("--out")
    r.set_defaults(func=cmd_receive)

    ls = sub.add_parser("list-keys", help="List keys in store")
    ls.set_defaults(func=cmd_list)

    reg = sub.add_parser("register", help="Register a new user")
    reg.add_argument("--username", required=True)
    reg.add_argument("--password", required=True)
    reg.add_argument("--email", default="")
    reg.set_defaults(func=cmd_register)

    log = sub.add_parser("login", help="Login a user")
    log.add_argument("--username", required=True)
    log.add_argument("--password", required=True)
    log.add_argument("--totp")
    log.add_argument("--backup-code")
    log.set_defaults(func=cmd_login)

    et = sub.add_parser("enable-totp", help="Enable TOTP for a user")
    et.add_argument("--username", required=True)
    et.set_defaults(func=cmd_enable_totp)

    bc = sub.add_parser("backup-codes", help="Show backup codes for a user")
    bc.add_argument("--username", required=True)
    bc.set_defaults(func=cmd_backup_codes)

    fe = sub.add_parser("file-encrypt", help="Encrypt a file with AES-256-GCM")
    fe.add_argument("--input", required=True)
    fe.add_argument("--output", required=True)
    fe.add_argument("--chunk-size", type=int, default=64 * 1024)
    group_fe = fe.add_mutually_exclusive_group(required=True)
    group_fe.add_argument("--key-hex")
    group_fe.add_argument("--passphrase")
    group_fe.add_argument("--key-file")
    fe.set_defaults(func=cmd_encrypt_file)

    fd = sub.add_parser("file-decrypt", help="Decrypt a file with AES-256-GCM")
    fd.add_argument("--input", required=True)
    fd.add_argument("--output", required=True)
    fd.add_argument("--chunk-size", type=int, default=64 * 1024)
    group_fd = fd.add_mutually_exclusive_group(required=True)
    group_fd.add_argument("--key-hex")
    group_fd.add_argument("--passphrase")
    group_fd.add_argument("--key-file")
    fd.set_defaults(func=cmd_decrypt_file)

    de = sub.add_parser("dir-encrypt", help="Encrypt a directory recursively")
    de.add_argument("--source", required=True)
    de.add_argument("--target", required=True)
    de.add_argument("--chunk-size", type=int, default=64 * 1024)
    group_de = de.add_mutually_exclusive_group(required=True)
    group_de.add_argument("--key-hex")
    group_de.add_argument("--passphrase")
    group_de.add_argument("--key-file")
    de.set_defaults(func=cmd_encrypt_dir)

    dd = sub.add_parser("dir-decrypt", help="Decrypt a directory recursively")
    dd.add_argument("--source", required=True)
    dd.add_argument("--target", required=True)
    dd.add_argument("--chunk-size", type=int, default=64 * 1024)
    group_dd = dd.add_mutually_exclusive_group(required=True)
    group_dd.add_argument("--key-hex")
    group_dd.add_argument("--passphrase")
    group_dd.add_argument("--key-file")
    dd.set_defaults(func=cmd_decrypt_dir)

    fh = sub.add_parser("file-hash", help="Show SHA-256 and Merkle root")
    fh.add_argument("--input", required=True)
    fh.set_defaults(func=cmd_file_hash)

    fv = sub.add_parser(
        "file-verify", help="Verify file integrity by Merkle root"
    )
    fv.add_argument("--input", required=True)
    fv.add_argument(
        "--expected-root", required=True, help="Hex-encoded Merkle root"
    )
    fv.set_defaults(func=cmd_file_verify)

    ca = sub.add_parser("chain-add", help="Add a block to the blockchain")
    ca.add_argument("--data", action="append", help="Transaction payloads")
    ca.add_argument("--data-file", help="File with one transaction per line")
    ca.add_argument("--user", default="cli")
    ca.set_defaults(func=cmd_chain_add)

    ci = sub.add_parser("chain-info", help="Show chain head and metrics")
    ci.set_defaults(func=cmd_chain_info)

    cv = sub.add_parser("chain-validate", help="Validate the current chain")
    cv.set_defaults(func=cmd_chain_validate)

    au = sub.add_parser("chain-audit", help="Append an audit log entry")
    au.add_argument("--action", required=True)
    au.add_argument("--user", default="cli")
    au.set_defaults(func=cmd_chain_audit)

    cp = sub.add_parser("chain-proof", help="Show current audit proof hash")
    cp.set_defaults(func=cmd_chain_proof)

    cr = sub.add_parser(
        "chain-resolve", help="Resolve fork against another chain file"
    )
    cr.add_argument("--peer-chain", required=True)
    cr.set_defaults(func=cmd_chain_resolve)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
