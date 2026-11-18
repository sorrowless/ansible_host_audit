"""Turn parsed sshd and key scans into audit checks."""

from __future__ import annotations


def _first(values) -> str:
    if not values:
        return ""
    return str(values[0]).strip()


def _effective(result: dict, key: str) -> tuple[str, str]:
    """Prefer sshd -T. Fall back to the file parser when the daemon parser is absent."""
    sshd_t = result.get("sshd_t") or {}
    if key in sshd_t and sshd_t[key]:
        return _first(sshd_t[key]).lower(), "sshd -T"
    value = str((result.get("globals") or {}).get(key, "")).strip()
    source = str((result.get("sources") or {}).get(key, "")).strip()
    return value.lower(), source


def _source_label(result: dict, key: str, origin: str) -> str:
    if origin == "sshd -T":
        file_source = str((result.get("sources") or {}).get(key, "")).strip()
        if file_source:
            return f"sshd -T, файл {file_source}"
        return "sshd -T"
    return origin or "разбор файлов"


def _agreement(result: dict, key: str) -> dict | None:
    if int(result.get("sshd_t_rc") or 0) != 0:
        return None
    parsed = str((result.get("globals") or {}).get(key, "")).strip().lower()
    reported = _first((result.get("sshd_t") or {}).get(key)).lower()
    if not parsed or not reported:
        return None
    if parsed == reported:
        return {
            "name": f"{key}_agrees",
            "status": "pass",
            "evidence": f"{key}: sshd -T и разбор файлов совпадают ({reported})",
        }
    return {
        "name": f"{key}_agrees",
        "status": "fail",
        "evidence": f"{key}: sshd -T говорит {reported}, разбор файлов — {parsed}",
    }


def _daemon_checks(result: dict) -> list[dict]:
    checks = []
    if int(result.get("sshd_t_rc") or 0) != 0:
        err = (result.get("sshd_t_stderr") or "").strip() or "ненулевой код"
        checks.append(
            {
                "name": "sshd_t",
                "status": "warn",
                "evidence": f"sshd -T не выполнен ({err}). Оценка построена по файлам конфигурации.",
            }
        )
    daemon = result.get("daemon") or {}
    if daemon.get("drift"):
        checks.append(
            {
                "name": "reload",
                "status": "fail",
                "evidence": "файлы sshd новее процесса демона: загруженная конфигурация может отличаться от диска",
            }
        )
    elif daemon.get("running"):
        checks.append(
            {
                "name": "reload",
                "status": "pass",
                "evidence": f"sshd запущен (pid {daemon.get('pid')}) и не старше файлов конфигурации",
            }
        )
    else:
        checks.append(
            {
                "name": "reload",
                "status": "warn",
                "evidence": "sshd не запущен, оценена конфигурация, которую демон прочитает при старте",
            }
        )
    return checks


def _match_risks(result: dict, kind: str) -> list[dict]:
    return [risk for risk in (result.get("risks") or []) if risk.get("kind") == kind]


def _config_error(result: dict) -> list[dict] | None:
    if result.get("error") and not result.get("globals") and not result.get("sshd_t"):
        return [{"name": "config", "status": "fail", "evidence": str(result["error"])}]
    return None


def host_audit_ssh_password_checks(result):
    broken = _config_error(result or {})
    if broken:
        return broken
    result = result or {}
    value, origin = _effective(result, "passwordauthentication")
    source = _source_label(result, "passwordauthentication", origin)
    risks = _match_risks(result, "passwordauthentication")
    if value == "no" and not risks:
        evidence = f"PasswordAuthentication no ({source})"
        status = "pass"
    else:
        shown = value or "не задано, для OpenSSH это yes"
        evidence = f"PasswordAuthentication {shown} ({source})"
        if risks:
            details = ", ".join(
                f"{risk.get('match')} → {risk.get('value')} в {risk.get('source')}" for risk in risks
            )
            evidence += f"; Match включает парольный вход: {details}"
        status = "fail"
    checks = [{"name": "effective_value", "status": status, "evidence": evidence}]
    agreement = _agreement(result, "passwordauthentication")
    if agreement:
        checks.append(agreement)
    checks.extend(_daemon_checks(result))
    for warning in result.get("warnings") or []:
        checks.append({"name": "parse_warning", "status": "warn", "evidence": str(warning)})
    return checks


def host_audit_ssh_root_checks(result):
    broken = _config_error(result or {})
    if broken:
        return broken
    result = result or {}
    value, origin = _effective(result, "permitrootlogin")
    source = _source_label(result, "permitrootlogin", origin)
    risks = _match_risks(result, "permitrootlogin")
    if value == "no" and not risks:
        evidence = f"PermitRootLogin no ({source})"
        status = "pass"
    else:
        shown = value or "не задано"
        evidence = f"PermitRootLogin {shown} ({source})"
        if value in {"prohibit-password", "without-password"}:
            evidence += "; вход root по ключу всё ещё разрешён"
        if risks:
            details = ", ".join(
                f"{risk.get('match')} → {risk.get('value')} в {risk.get('source')}" for risk in risks
            )
            evidence += f"; Match ослабляет запрет: {details}"
        status = "fail"
    checks = [{"name": "effective_value", "status": status, "evidence": evidence}]
    agreement = _agreement(result, "permitrootlogin")
    if agreement:
        checks.append(agreement)
    checks.extend(_daemon_checks(result))
    return checks


_OPEN_ALLOW = {"", "*", "*@*", "*@*:*"}


def _restricts(value: str) -> bool:
    tokens = [token for token in value.split() if token]
    if not tokens:
        return False
    return any(token not in _OPEN_ALLOW for token in tokens)


def host_audit_ssh_access_checks(result):
    broken = _config_error(result or {})
    if broken:
        return broken
    result = result or {}
    users, users_origin = _effective(result, "allowusers")
    groups, groups_origin = _effective(result, "allowgroups")
    # sshd -T omits the keyword when it is unset; the parser then leaves it empty.
    user_source = _source_label(result, "allowusers", users_origin) if users else ""
    group_source = _source_label(result, "allowgroups", groups_origin) if groups else ""
    if _restricts(users) or _restricts(groups):
        parts = []
        if _restricts(users):
            parts.append(f"AllowUsers {users} ({user_source})")
        if _restricts(groups):
            parts.append(f"AllowGroups {groups} ({group_source})")
        checks = [{"name": "allowlist", "status": "pass", "evidence": "; ".join(parts)}]
    else:
        checks = [
            {
                "name": "allowlist",
                "status": "fail",
                "evidence": "в эффективной конфигурации нет AllowUsers и AllowGroups. Match Address сам по себе никого не запрещает",
            }
        ]
    checks.extend(_daemon_checks(result))
    return checks


def _join_paths(rows, limit=12) -> str:
    paths = [row.get("path", "") for row in rows]
    shown = ", ".join(paths[:limit])
    if len(paths) > limit:
        shown += f" и ещё {len(paths) - limit}"
    return shown


def host_audit_key_checks(result, placement="target"):
    result = result or {}
    if result.get("error"):
        return [{"name": "scan", "status": "fail", "evidence": str(result["error"])}]
    if result.get("failed") and result.get("msg"):
        return [{"name": "scan", "status": "fail", "evidence": str(result["msg"])}]

    keys = result.get("keys") or []
    errors = [str(item) for item in (result.get("errors") or [])]
    missing = [item for item in errors if item.startswith("каталог не найден")]
    other_errors = [item for item in errors if item not in missing]
    unencrypted = [item for item in keys if item.get("state") == "unencrypted"]
    unknown = [item for item in keys if item.get("state") == "unknown"]
    exposed = [item for item in keys if item.get("exposed") and item.get("state") != "unencrypted"]
    encrypted = [item for item in keys if item.get("state") == "encrypted" and not item.get("exposed")]

    checks = []
    if placement == "controller":
        if unencrypted:
            checks.append(
                {
                    "name": "passphrase",
                    "status": "fail",
                    "evidence": "приватные ключи без парольной фразы: " + _join_paths(unencrypted),
                }
            )
        elif unknown:
            checks.append(
                {
                    "name": "passphrase",
                    "status": "warn",
                    "evidence": "формат ключа не распознан, фразу подтвердить нельзя: " + _join_paths(unknown),
                }
            )
        elif not keys and missing and not other_errors:
            checks.append(
                {
                    "name": "passphrase",
                    "status": "warn",
                    "evidence": "каталоги ключей управляющей машины не найдены: " + "; ".join(missing),
                }
            )
        else:
            checks.append(
                {
                    "name": "passphrase",
                    "status": "pass",
                    "evidence": "все найденные приватные ключи зашифрованы"
                    if keys
                    else "приватные ключи в заданных каталогах не найдены",
                }
            )
        if exposed:
            checks.append(
                {
                    "name": "mode",
                    "status": "fail",
                    "evidence": "ключ доступен группе или остальным: " + _join_paths(exposed),
                }
            )
    else:
        if unencrypted or exposed:
            parts = []
            if unencrypted:
                parts.append("без парольной фразы: " + _join_paths(unencrypted))
            if exposed:
                parts.append("режим доступен не только владельцу: " + _join_paths(exposed))
            checks.append(
                {
                    "name": "cleartext",
                    "status": "fail",
                    "evidence": "приватные ключи лежат в открытом виде (" + "; ".join(parts) + ")",
                }
            )
        elif unknown:
            checks.append(
                {
                    "name": "cleartext",
                    "status": "warn",
                    "evidence": "формат ключа на хосте не распознан: " + _join_paths(unknown),
                }
            )
        elif encrypted:
            checks.append(
                {
                    "name": "cleartext",
                    "status": "warn",
                    "evidence": "зашифрованные приватные ключи лежат на хосте: " + _join_paths(encrypted),
                }
            )
        else:
            checks.append(
                {
                    "name": "cleartext",
                    "status": "pass",
                    "evidence": "в /home и /root нет приватных ключей",
                }
            )
    if other_errors:
        checks.append(
            {
                "name": "scan_errors",
                "status": "warn",
                "evidence": "; ".join(other_errors[:8]),
            }
        )
    return checks


class FilterModule:
    def filters(self):
        return {
            "host_audit_ssh_password_checks": host_audit_ssh_password_checks,
            "host_audit_ssh_root_checks": host_audit_ssh_root_checks,
            "host_audit_ssh_access_checks": host_audit_ssh_access_checks,
            "host_audit_key_checks": host_audit_key_checks,
        }
