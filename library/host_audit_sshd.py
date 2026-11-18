#!/usr/bin/python3
"""Read-only inspection of the effective sshd configuration.

The parser follows OpenSSH rules: Include is expanded when it is encountered,
globs are sorted, and for ordinary keywords the first obtained value wins.
sshd -T is collected separately so the role can compare the real daemon parser
with the file parser.
"""

from __future__ import annotations

import glob
import os

try:
    from ansible.module_utils.basic import AnsibleModule
except ImportError:  # unit tests load this file without Ansible installed
    AnsibleModule = None  # type: ignore[misc, assignment]


ENUM_LOWER = {
    "passwordauthentication",
    "permitrootlogin",
    "usepam",
    "kbdinteractiveauthentication",
    "challengeresponseauthentication",
    "pubkeyauthentication",
}

ACCUMULATE = {
    "authenticationmethods",
    "listenaddress",
    "port",
    "hostkey",
    "acceptenv",
}

INTERESTING = ENUM_LOWER | ACCUMULATE | {
    "allowusers",
    "allowgroups",
}

RELATIVE_INCLUDE_DIR = "/etc/ssh"


def strip_comment(line: str) -> str:
    """Drop an unquoted ``#`` comment."""
    out: list[str] = []
    quote = ""
    for char in line:
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out).strip()


def tokenize(line: str) -> list[str]:
    """Split an sshd config line, honoring single and double quotes."""
    tokens: list[str] = []
    buf: list[str] = []
    quote = ""
    for char in line:
        if quote:
            if char == quote:
                quote = ""
            else:
                buf.append(char)
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(char)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _normalize(key: str, value: str) -> str:
    if key in ENUM_LOWER:
        return value.lower()
    return value


def expand_include(token: str, list_glob, base_dir: str = RELATIVE_INCLUDE_DIR) -> list[str]:
    """Resolve one Include token the way sshd does."""
    pattern = token if token.startswith("/") else os.path.join(base_dir, token)
    matched = list(list_glob(pattern))
    if matched:
        return sorted(matched)
    if any(char in pattern for char in "*?["):
        return []
    return []


def parse_sshd_tree(main_path: str, read_text, list_glob) -> dict:
    """Parse ``main_path`` and every Include it pulls in.

    ``read_text(path) -> str`` and ``list_glob(pattern) -> list[str]`` are
    injected so the same function runs in unit tests and on the target.
    """
    globals_map: dict[str, str] = {}
    multi: dict[str, list[str]] = {}
    sources: dict[str, str] = {}
    matches: list[dict] = []
    files_read: list[str] = []
    warnings: list[str] = []

    def parse_file(path: str, stack: list[str], match: dict | None) -> dict | None:
        if path in stack:
            warnings.append(f"цикл Include: {path}")
            return match
        try:
            text = read_text(path)
        except OSError as exc:
            warnings.append(f"{path}: {exc}")
            return match
        files_read.append(path)
        current = match
        pending = ""
        logical: list[str] = []
        for raw_line in text.splitlines():
            if raw_line.endswith("\\") and not raw_line.endswith("\\\\"):
                pending += raw_line[:-1] + " "
                continue
            logical.append(pending + raw_line)
            pending = ""
        if pending:
            logical.append(pending)

        for raw_line in logical:
            line = strip_comment(raw_line).strip()
            if not line:
                continue
            tokens = tokenize(line)
            if not tokens:
                continue
            key = tokens[0].lower()
            if key == "include":
                for token in tokens[1:]:
                    for included in expand_include(token, list_glob):
                        current = parse_file(included, stack + [path], current)
                continue
            if key == "match":
                current = {
                    "criteria": " ".join(tokens[1:]),
                    "source": path,
                    "settings": {},
                    "sources": {},
                }
                matches.append(current)
                continue
            if key not in INTERESTING:
                continue
            value = _normalize(key, " ".join(tokens[1:]))
            if current is None:
                if key in ACCUMULATE:
                    multi.setdefault(key, []).append(value)
                    if key not in globals_map:
                        globals_map[key] = value
                        sources[key] = path
                elif key not in globals_map:
                    globals_map[key] = value
                    sources[key] = path
                continue
            if key in ACCUMULATE:
                current.setdefault("multi", {}).setdefault(key, []).append(value)
                if key not in current["settings"]:
                    current["settings"][key] = value
                    current["sources"][key] = path
            elif key not in current["settings"]:
                current["settings"][key] = value
                current["sources"][key] = path
        return current

    parse_file(main_path, [], None)
    risks = []
    for block in matches:
        for kind in ("passwordauthentication", "permitrootlogin"):
            value = str(block["settings"].get(kind, "")).lower()
            if not value:
                continue
            if kind == "passwordauthentication" and value != "yes":
                continue
            if kind == "permitrootlogin" and value == "no":
                continue
            risks.append(
                {
                    "kind": kind,
                    "value": value,
                    "match": block["criteria"],
                    "source": block["sources"].get(kind, block["source"]),
                }
            )
    return {
        "globals": globals_map,
        "multi": multi,
        "sources": sources,
        "matches": [
            {
                "criteria": block["criteria"],
                "source": block["source"],
                "settings": block["settings"],
            }
            for block in matches
        ],
        "risks": risks,
        "files_read": files_read,
        "warnings": warnings,
    }


def parse_sshd_t(text: str) -> dict[str, list[str]]:
    """Parse ``sshd -T`` output. Repeated keywords keep every value."""
    parsed: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" ")
        if not separator:
            continue
        parsed.setdefault(key.lower(), []).append(value.strip())
    return parsed


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _sshd_pids() -> list[int]:
    proc = "/proc"
    if not os.path.isdir(proc):
        return []
    pids = []
    for name in os.listdir(proc):
        if not name.isdigit():
            continue
        comm_path = os.path.join(proc, name, "comm")
        try:
            with open(comm_path, encoding="ascii", errors="replace") as handle:
                comm = handle.read().strip()
        except OSError:
            continue
        if comm == "sshd":
            pids.append(int(name))
    return pids


def _daemon_state(files_read: list[str]) -> dict:
    pids = _sshd_pids()
    if not pids:
        return {"running": False, "drift": False, "pid": 0}
    starts = []
    for pid in pids:
        try:
            starts.append((os.stat(f"/proc/{pid}").st_mtime, pid))
        except OSError:
            continue
    if not starts:
        return {"running": False, "drift": False, "pid": 0}
    start, pid = min(starts)
    mtimes = []
    for path in files_read:
        try:
            mtimes.append(os.path.getmtime(path))
        except OSError:
            continue
    newest = max(mtimes) if mtimes else 0
    # One second of slack covers timestamp resolution on the config write.
    drift = bool(newest and start + 1 < newest)
    return {"running": True, "drift": drift, "pid": pid}


def _run_sshd_t(module, path: str, binary: str) -> tuple[int, str, str]:
    candidates = [binary] if binary else []
    candidates.extend(["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"])
    last_err = "sshd не найден"
    for candidate in candidates:
        if candidate.startswith("/") and not os.path.isfile(candidate):
            continue
        rc, out, err = module.run_command([candidate, "-T", "-f", path], check_rc=False)
        if os.path.isfile(candidate) or rc == 0:
            return rc, out or "", err or ""
        last_err = err or out or last_err
    return 127, "", last_err


def inspect_sshd(module, path: str, binary: str) -> dict:
    if not os.path.isfile(path):
        empty = {
            "globals": {},
            "multi": {},
            "sources": {},
            "matches": [],
            "risks": [],
            "files_read": [],
            "warnings": [],
            "sshd_t": {},
            "sshd_t_rc": 127,
            "sshd_t_stderr": "",
            "daemon": {"running": False, "drift": False, "pid": 0},
            "error": f"нет файла {path}",
        }
        return empty
    parsed = parse_sshd_tree(path, _read_text, glob.glob)
    rc, out, err = _run_sshd_t(module, path, binary)
    parsed["sshd_t"] = parse_sshd_t(out) if rc == 0 else {}
    parsed["sshd_t_rc"] = rc
    parsed["sshd_t_stderr"] = (err or "")[:500]
    parsed["daemon"] = _daemon_state(parsed["files_read"])
    parsed["error"] = ""
    return parsed


def main() -> None:
    if AnsibleModule is None:
        raise SystemExit("ansible is required to execute host_audit_sshd")
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "str", "default": "/etc/ssh/sshd_config"},
            "sshd_binary": {"type": "str", "default": ""},
        },
        supports_check_mode=True,
    )
    try:
        result = inspect_sshd(
            module,
            module.params["path"],
            module.params["sshd_binary"],
        )
    except Exception as exc:  # noqa: BLE001 - report and continue the audit
        module.exit_json(changed=False, error=f"{type(exc).__name__}: {exc}")
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()


DOCUMENTATION = r"""
---
module: host_audit_sshd
short_description: Read the effective sshd configuration
description:
  - Parses sshd_config together with Include files.
  - Runs sshd -T and reports whether the running daemon is older than the files.
  - Does not modify the host.
options:
  path:
    description: Path to the main sshd_config.
    type: str
    default: /etc/ssh/sshd_config
  sshd_binary:
    description: Explicit path to sshd. Empty uses the usual locations.
    type: str
    default: ""
author:
  - sorrowless
"""

EXAMPLES = r"""
- name: Inspect sshd
  host_audit_sshd:
    path: /etc/ssh/sshd_config
  register: sshd_audit
"""

RETURN = r"""
globals:
  description: First-wins keyword values outside Match blocks.
  type: dict
  returned: always
sources:
  description: File that supplied each global keyword.
  type: dict
  returned: always
risks:
  description: Match blocks that weaken PasswordAuthentication or PermitRootLogin.
  type: list
  returned: always
sshd_t:
  description: Keywords from sshd -T. Values are lists because some keywords repeat.
  type: dict
  returned: when sshd -T succeeds
daemon:
  description: Whether sshd is running and whether config files are newer than the process.
  type: dict
  returned: always
"""
