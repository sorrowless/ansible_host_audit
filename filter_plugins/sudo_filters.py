"""Find sudoers rules that grant every command."""

from __future__ import annotations

import re


_TAGS = re.compile(
    r"(?i)\b(NOEXEC|EXEC|NOPASSWD|PASSWD|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|"
    r"LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW)\s*:"
)
_RUNAS = re.compile(r"\([^)]*\)")
_ALIAS = re.compile(r"(?i)^cmnd_alias\s+(\S+)\s*=\s*(.+)$")
_SKIP = ("defaults", "user_alias", "host_alias", "runas_alias")


def _strip_comment(line: str) -> str:
    out = []
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


def _is_root_only(left: str) -> bool:
    """Left side of a sudoers rule is ``users hosts``, not only the user list."""
    chunks = left.split()
    if not chunks:
        return False
    users = [part.strip() for part in chunks[0].split(",") if part.strip()]
    return users == ["root"]


def _commands_are_all(command: str, aliases: dict[str, list[str]]) -> bool:
    token = command.strip().strip('"').strip("'")
    if not token:
        return False
    upper = token.upper()
    if upper == "ALL" or upper.startswith("ALL ") or upper.startswith("ALL!"):
        return True
    expanded = aliases.get(token) or aliases.get(token.upper()) or []
    return any(item.upper() == "ALL" or item.upper().startswith("ALL ") for item in expanded)


def sudo_includes(content: str) -> list[dict]:
    """Return ``#include`` / ``#includedir`` targets. In sudoers a leading # is not a comment."""
    found = []
    for raw in (content or "").splitlines():
        stripped = raw.strip()
        kind = ""
        if stripped.startswith(("#includedir ", "@includedir ")):
            kind = "dir"
        elif stripped.startswith(("#include ", "@include ")):
            kind = "file"
        if not kind:
            continue
        target = stripped.split(None, 1)[1].strip().strip('"')
        if target:
            found.append({"kind": kind, "path": target})
    return found


def parse_sudoers(content: str, path: str) -> list[dict]:
    aliases: dict[str, list[str]] = {}
    findings = []
    for number, raw in enumerate((content or "").splitlines(), start=1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(_SKIP) or lowered.startswith(("include", "@include", "#include")):
            continue
        alias = _ALIAS.match(line)
        if alias:
            name = alias.group(1)
            commands = [part.strip() for part in alias.group(2).split(",") if part.strip()]
            aliases[name] = commands
            aliases[name.upper()] = commands
            continue
        if "=" not in line:
            continue
        users, spec = line.split("=", 1)
        if _is_root_only(users):
            continue
        nopasswd = bool(re.search(r"(?i)(?<!!)\bNOPASSWD\s*:", spec))
        commands = _TAGS.sub(" ", spec)
        commands = _RUNAS.sub(" ", commands)
        for command in [part.strip() for part in commands.split(",")]:
            if not _commands_are_all(command, aliases):
                continue
            findings.append(
                {
                    "path": path,
                    "line": number,
                    "nopasswd": nopasswd,
                    "text": raw.strip(),
                }
            )
            break
    return findings


def host_audit_sudo_checks(files, modes):
    """``files`` is a list of ``{path, content}``. ``modes`` maps path to an octal string."""
    if not files:
        return [{"name": "sudoers", "status": "fail", "evidence": "/etc/sudoers не прочитан"}]
    findings = []
    for item in files or []:
        findings.extend(parse_sudoers(item.get("content") or "", item.get("path") or ""))
    nopasswd = [item for item in findings if item["nopasswd"]]
    broad = [item for item in findings if not item["nopasswd"]]

    def _fmt(rows) -> str:
        return "; ".join(f"{row['path']}:{row['line']}: {row['text']}" for row in rows[:8])

    checks = []
    if nopasswd:
        checks.append(
            {
                "name": "nopasswd_all",
                "status": "fail",
                "severity": "critical",
                "evidence": "NOPASSWD: ALL: " + _fmt(nopasswd),
            }
        )
    else:
        checks.append(
            {
                "name": "nopasswd_all",
                "status": "pass",
                "evidence": "правил NOPASSWD: ALL нет",
            }
        )
    if broad:
        checks.append(
            {
                "name": "command_all",
                "status": "fail",
                "severity": "medium",
                "evidence": "правила на все команды: " + _fmt(broad),
            }
        )
    else:
        checks.append(
            {
                "name": "command_all",
                "status": "pass",
                "evidence": "нет правил, которые выдают ALL не-root пользователям",
            }
        )

    loose = []
    for path, mode in (modes or {}).items():
        try:
            value = int(str(mode), 8)
        except (TypeError, ValueError):
            loose.append(f"{path}: режим не прочитан")
            continue
        if value & ~0o440 & 0o777:
            loose.append(f"{path}: режим {mode}, ожидается не шире 0440")
    checks.append(
        {
            "name": "mode",
            "status": "fail" if loose else "pass",
            "severity": "high",
            "evidence": "; ".join(loose) if loose else "файлы sudoers не доступны группе и остальным на запись",
        }
    )
    return checks


class FilterModule:
    def filters(self):
        return {
            "host_audit_sudo_checks": host_audit_sudo_checks,
            "host_audit_parse_sudoers": parse_sudoers,
            "host_audit_sudo_includes": sudo_includes,
        }
