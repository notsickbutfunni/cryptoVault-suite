import os
from typing import List


def ensure_store(base_dir: str = "keys") -> str:
    if not os.path.isdir(base_dir):
        os.makedirs(base_dir, exist_ok=True)
    return base_dir


def _path(base_dir: str, filename: str) -> str:
    return os.path.join(base_dir, filename)


def save_private_key(label: str, pem_bytes: bytes, base_dir: str = "keys") -> str:
    ensure_store(base_dir)
    path = _path(base_dir, f"{label}_private.pem")
    with open(path, "wb") as f:
        f.write(pem_bytes)
    return path


def save_public_key(label: str, pem_bytes: bytes, base_dir: str = "keys") -> str:
    ensure_store(base_dir)
    path = _path(base_dir, f"{label}_public.pem")
    with open(path, "wb") as f:
        f.write(pem_bytes)
    return path


def load_private_key(label: str, base_dir: str = "keys") -> bytes:
    path = _path(base_dir, f"{label}_private.pem")
    with open(path, "rb") as f:
        return f.read()


def load_public_key(label: str, base_dir: str = "keys") -> bytes:
    path = _path(base_dir, f"{label}_public.pem")
    with open(path, "rb") as f:
        return f.read()


def list_keys(base_dir: str = "keys") -> List[str]:
    ensure_store(base_dir)
    names = [name for name in os.listdir(base_dir) if name.endswith(".pem")]
    return sorted(names)
