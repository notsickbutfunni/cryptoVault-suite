import argparse
import sys
from typing import Optional

from src.messaging.key_exchange import generate_ec_keypair
from src.messaging.schema import (
    create_envelope,
    envelope_to_json,
    verify_and_decrypt_envelope,
)
from src.keystore.fs_store import (
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    list_keys,
    ensure_store,
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cryptovault")
    p.add_argument("--store", default="keys", help="Key store directory")
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

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
