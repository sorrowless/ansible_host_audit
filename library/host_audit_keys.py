#!/usr/bin/python3
"""Find private SSH keys and tell whether they are encrypted.

The scan reads only a short header. It never prints key material and never
tries a real passphrase.
"""

from __future__ import annotations

import base64
import os
import stat
import struct

try:
    from ansible.module_utils.basic import AnsibleModule
except ImportError:
    AnsibleModule = None  # type: ignore[misc, assignment]


SKIP_DIRS = {
    ".cache",
    ".git",
    ".npm",
    ".cargo",
    ".venv",
    "venv",
    "node_modules",
    "snap",
    "Library",
    "__pycache__",
    "vendor",
    "target",
}

SKIP_NAMES = {
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "config",
}


def _read_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buf):
        raise ValueError("truncated")
    (length,) = struct.unpack(">I", buf[offset : offset + 4])
    offset += 4
    if length < 0 or offset + length > len(buf):
        raise ValueError("truncated")
    return buf[offset : offset + length], offset + length


def _openssh_state(blob: bytes) -> str:
    text = blob.decode("ascii", errors="replace")
    start = text.find("-----BEGIN OPENSSH PRIVATE KEY-----")
    end = text.find("-----END OPENSSH PRIVATE KEY-----")
    if start < 0 or end < 0:
        return "unknown"
    body = "".join(text[start:end].splitlines()[1:])
    try:
        raw = base64.b64decode(body, validate=False)
    except (ValueError, TypeError):
        return "unknown"
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        return "unknown"
    try:
        cipher, offset = _read_string(raw, len(magic))
        kdf, _offset = _read_string(raw, offset)
    except ValueError:
        return "unknown"
    if cipher == b"none" and kdf == b"none":
        return "unencrypted"
    return "encrypted"


def classify_private_key(blob: bytes) -> str | None:
    """Return unencrypted, encrypted, unknown, or None when the file is not a private key."""
    if not blob:
        return None
    head = blob[:800]
    if b"BEGIN OPENSSH PRIVATE KEY" in head:
        return _openssh_state(blob)
    if head.startswith(b"PuTTY-User-Key-File-"):
        for line in blob.splitlines():
            if line.lower().startswith(b"encryption:"):
                value = line.split(b":", 1)[1].strip().lower()
                return "unencrypted" if value == b"none" else "encrypted"
        return "unknown"
    if b"BEGIN ENCRYPTED PRIVATE KEY" in head:
        return "encrypted"
    pem_markers = (
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN DSA PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"BEGIN PRIVATE KEY",
    )
    if any(marker in head for marker in pem_markers):
        if b"Proc-Type: 4,ENCRYPTED" in blob[:1200]:
            return "encrypted"
        return "unencrypted"
    return None


def _depth(root: str, path: str) -> int:
    rel = os.path.relpath(path, root)
    if rel == ".":
        return 0
    return rel.count(os.sep)


def scan_keys(paths: list[str], max_depth: int, max_files: int) -> dict:
    keys: list[dict] = []
    errors: list[str] = []
    examined = 0
    for root in paths:
        if not root or not os.path.isabs(root):
            errors.append(f"путь должен быть абсолютным: {root}")
            continue
        if not os.path.isdir(root):
            errors.append(f"каталог не найден: {root}")
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
            if _depth(root, dirpath) >= max_depth:
                dirnames[:] = []
            for name in filenames:
                examined += 1
                if examined > max_files:
                    errors.append(f"достигнут лимит просмотра файлов ({max_files})")
                    return {"keys": keys, "errors": errors, "error": ""}
                if name.endswith(".pub") or name in SKIP_NAMES:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    info = os.lstat(path)
                except OSError as exc:
                    errors.append(f"{path}: {exc.strerror or exc}")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size <= 0 or info.st_size > 65536:
                    continue
                try:
                    with open(path, "rb") as handle:
                        blob = handle.read(4096)
                except OSError as exc:
                    errors.append(f"{path}: {exc.strerror or exc}")
                    continue
                state = classify_private_key(blob)
                if state is None:
                    continue
                mode = stat.S_IMODE(info.st_mode)
                keys.append(
                    {
                        "path": path,
                        "state": state,
                        "mode": f"{mode:04o}",
                        "exposed": bool(mode & 0o077),
                    }
                )
                if len(keys) >= 100:
                    errors.append("достигнут лимит найденных ключей (100)")
                    return {"keys": keys, "errors": errors, "error": ""}
    return {"keys": keys, "errors": errors, "error": ""}


def main() -> None:
    if AnsibleModule is None:
        raise SystemExit("ansible is required to execute host_audit_keys")
    module = AnsibleModule(
        argument_spec={
            "paths": {"type": "list", "elements": "str", "required": True},
            "max_depth": {"type": "int", "default": 6},
            "max_files": {"type": "int", "default": 8000},
        },
        supports_check_mode=True,
    )
    try:
        result = scan_keys(
            module.params["paths"],
            int(module.params["max_depth"]),
            int(module.params["max_files"]),
        )
    except Exception as exc:  # noqa: BLE001 - keep the audit running
        module.exit_json(changed=False, keys=[], errors=[], error=f"{type(exc).__name__}: {exc}")
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()


DOCUMENTATION = r"""
---
module: host_audit_keys
short_description: Find private SSH keys and report whether a passphrase protects them
description:
  - Walks the given directories and classifies private key headers.
  - Does not print key material and does not attempt passphrases.
options:
  paths:
    description: Absolute directories to scan.
    type: list
    elements: str
    required: true
  max_depth:
    description: Maximum directory depth below each root.
    type: int
    default: 6
  max_files:
    description: Maximum number of regular files to inspect.
    type: int
    default: 8000
author:
  - sorrowless
"""

EXAMPLES = r"""
- name: Scan home directories
  host_audit_keys:
    paths:
      - /home
      - /root
"""

RETURN = r"""
keys:
  description: Private keys that were recognized.
  type: list
  returned: always
errors:
  description: Paths that could not be read, missing directories, or scan limits.
  type: list
  returned: always
"""
