"""fail2ban, MFA, auditd, remote logs, and time sync."""

from __future__ import annotations

import re


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _info(services: dict, name: str) -> dict:
    for key in (name, f"{name}.service"):
        info = (services or {}).get(key)
        if info:
            return info
    return {}


def _active(services: dict, name: str) -> bool:
    return str(_info(services, name).get("state", "")).lower() == "running"


def _enabled(services: dict, name: str) -> bool:
    return str(_info(services, name).get("status", "")).lower() in {"enabled", "enabled-runtime"}


def host_audit_bruteforce_checks(services, fail2ban_rc):
    services = services or {}
    try:
        rc = int(fail2ban_rc)
    except (TypeError, ValueError):
        rc = 127
    if _active(services, "fail2ban") and rc == 0:
        return [{"name": "jail", "status": "pass", "evidence": "fail2ban запущен, jail sshd отвечает"}]
    bouncers = (
        "crowdsec-firewall-bouncer",
        "crowdsec-nftables-bouncer",
        "crowdsec-custom-bouncer",
    )
    if _active(services, "crowdsec") and any(_active(services, name) for name in bouncers):
        return [{"name": "jail", "status": "pass", "evidence": "crowdsec и firewall bouncer запущены"}]
    if _active(services, "sshguard"):
        return [{"name": "jail", "status": "pass", "evidence": "sshguard запущен"}]
    if _active(services, "fail2ban"):
        return [
            {
                "name": "jail",
                "status": "fail",
                "evidence": "fail2ban запущен, но jail sshd не активен (fail2ban-client status sshd)",
            }
        ]
    return [
        {
            "name": "jail",
            "status": "fail",
            "evidence": "не найден активный fail2ban с jail sshd, sshguard или crowdsec с bouncer",
        }
    ]


def pam_includes(text: str) -> list[str]:
    found = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts and parts[0] in {"@include", "include"} and len(parts) >= 2:
            found.append(parts[1])
        elif len(parts) >= 3 and parts[1] == "include":
            found.append(parts[2])
    return found


def _mfa_lines(text: str, modules: list[str]) -> list[tuple[str, str]]:
    found = []
    names = set(modules or [])
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        module = parts[2]
        if module not in names and not any(module.endswith("/" + name) for name in names):
            continue
        found.append((module, parts[1]))
    return found


def _method_lists(sshd: dict) -> list[str]:
    values = (sshd.get("sshd_t") or {}).get("authenticationmethods") or []
    if not values:
        values = (sshd.get("multi") or {}).get("authenticationmethods") or []
        if not values and (sshd.get("globals") or {}).get("authenticationmethods"):
            values = [sshd["globals"]["authenticationmethods"]]
    return [str(item).strip().lower() for item in values if str(item).strip()]


def _effective_flag(sshd: dict, key: str) -> str:
    values = (sshd.get("sshd_t") or {}).get(key) or []
    if values:
        return str(values[0]).strip().lower()
    return str((sshd.get("globals") or {}).get(key, "")).strip().lower()


def host_audit_mfa_checks(sshd, pam_text, modules_found, management, required_modules):
    if not _as_bool(management):
        return [
            {
                "name": "scope",
                "status": "skip",
                "evidence": "хост не отмечен как управляющий контур (host_audit_management_host=false)",
            }
        ]
    sshd = sshd or {}
    lists = _method_lists(sshd)
    strong = []
    weak = []
    for item in lists:
        factors = [part.strip() for part in item.split(",") if part.strip()]
        if len(factors) >= 2 and "publickey" in factors:
            strong.append(item)
        else:
            weak.append(item)
    methods_ok = bool(lists) and not weak and bool(strong)
    methods_evidence = (
        "AuthenticationMethods " + " или ".join(lists)
        if lists
        else "AuthenticationMethods не задан"
    )
    if not methods_ok:
        methods_evidence += "; каждый вариант должен содержать publickey и второй фактор"

    usepam = _effective_flag(sshd, "usepam")
    kbd = _effective_flag(sshd, "kbdinteractiveauthentication")
    needs_kbd = any("keyboard-interactive" in item for item in lists)
    lines = _mfa_lines(pam_text or "", list(required_modules or []))
    strong_pam = [module for module, control in lines if control in {"required", "requisite"}]
    present = set(modules_found or [])
    missing_so = [module for module in strong_pam if module not in present and module.split("/")[-1] not in present]

    checks = [
        {
            "name": "authentication_methods",
            "status": "pass" if methods_ok else "fail",
            "evidence": methods_evidence,
        },
        {
            "name": "usepam",
            "status": "pass" if usepam == "yes" else "fail",
            "evidence": f"UsePAM {usepam or 'не задан'}",
        },
        {
            "name": "pam_module",
            "status": "pass" if strong_pam else "fail",
            "evidence": "PAM required: " + ", ".join(strong_pam)
            if strong_pam
            else "в стеке sshd нет required/requisite модуля MFA",
        },
        {
            "name": "module_file",
            "status": "pass" if strong_pam and not missing_so else "fail",
            "evidence": "файл модуля найден"
            if strong_pam and not missing_so
            else "файл модуля не найден: " + (", ".join(missing_so) if missing_so else "модуль MFA не подключён"),
        },
    ]
    if needs_kbd:
        checks.append(
            {
                "name": "kbdinteractive",
                "status": "pass" if kbd == "yes" else "fail",
                "evidence": f"KbdInteractiveAuthentication {kbd or 'не задан'}",
            }
        )
    return checks


def _uncommented(text: str, pattern: str) -> bool:
    regex = re.compile(pattern, re.I)
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if regex.search(line):
            return True
    return False


def host_audit_audit_checks(services, rules_text, auditctl_rc, auditctl_err, enabled_text=""):
    text = rules_text or ""
    err = (auditctl_err or "").lower()
    identity = "/etc/passwd" in text and "/etc/shadow" in text
    sudo = "/etc/sudoers" in text
    time_change = bool(re.search(r"adjtimex|settimeofday|clock_settime|time-change", text))
    unsupported = any(
        token in err
        for token in (
            "not supported",
            "operation not permitted",
            "permission denied",
            "function not implemented",
            "address family not supported",
            "no such file",
        )
    )
    enabled_word = str(enabled_text or "").strip().lower()
    enabled = _enabled(services, "auditd") or enabled_word in {"enabled", "enabled-runtime", "alias", "indirect"}
    active = _active(services, "auditd")
    if active:
        service_check = {"name": "service_active", "status": "pass", "evidence": "auditd запущен"}
    elif unsupported and enabled and identity and sudo and time_change:
        service_check = {
            "name": "service_active",
            "status": "warn",
            "evidence": "ядро не даёт включить audit; правила и unit на месте, демон не запущен",
        }
    else:
        detail = (auditctl_err or "").strip()
        service_check = {
            "name": "service_active",
            "status": "fail",
            "evidence": "auditd не запущен" + (f" ({detail})" if detail else ""),
        }
    return [
        {
            "name": "rules_identity",
            "status": "pass" if identity else "fail",
            "evidence": "есть watch на /etc/passwd и /etc/shadow" if identity else "нет правил на /etc/passwd и /etc/shadow",
        },
        {
            "name": "rules_sudo",
            "status": "pass" if sudo else "fail",
            "evidence": "есть watch на /etc/sudoers" if sudo else "нет правила на /etc/sudoers",
        },
        {
            "name": "rules_time",
            "status": "pass" if time_change else "fail",
            "evidence": "есть правило смены времени" if time_change else "нет правила на adjtimex/settimeofday/clock_settime",
        },
        {
            "name": "service_enabled",
            "status": "pass" if enabled else "fail",
            "evidence": "auditd enabled" if enabled else "auditd не enabled",
        },
        service_check,
    ]


def host_audit_log_checks(files, services):
    """``files`` is a list of ``{path, content}``."""
    shippers = []
    for item in files or []:
        path = item.get("path") or ""
        content = item.get("content") or ""
        if "rsyslog" in path and _uncommented(content, r"(@@?\s*\S+|omfwd|target\s*=)"):
            shippers.append(("rsyslog", path))
        elif "journal-upload" in path and _uncommented(content, r"^URL="):
            shippers.append(("systemd-journal-upload", path))
        elif "filebeat" in path and _uncommented(content, r"output\.(logstash|elasticsearch|kafka)\s*:"):
            shippers.append(("filebeat", path))
        elif "vector" in path and _uncommented(content, r"\btype\s*=\s*\"?(elasticsearch|kafka|socket|http)"):
            shippers.append(("vector", path))
    if not shippers:
        return [
            {
                "name": "forwarding",
                "status": "fail",
                "evidence": "не найдена отправка логов: rsyslog @/@@, journal-upload, filebeat или vector",
            }
        ]
    problems = []
    running = []
    for service, path in shippers:
        if _active(services, service):
            running.append(f"{service} ({path})")
        else:
            problems.append(f"{service} не запущен, хотя настроен в {path}")
    if problems and not running:
        return [{"name": "forwarding", "status": "fail", "evidence": "; ".join(problems)}]
    evidence = "централизованная отправка настроена: " + ", ".join(running or [item[0] for item in shippers])
    if problems:
        evidence += "; " + "; ".join(problems)
        return [{"name": "forwarding", "status": "warn", "evidence": evidence}]
    return [{"name": "forwarding", "status": "pass", "evidence": evidence}]


def _has_time_source(chrony_text: str, timesyncd_text: str) -> bool:
    if _uncommented(chrony_text, r"^(server|pool)\s+\S+"):
        return True
    if _uncommented(timesyncd_text, r"^(NTP|FallbackNTP)\s*=\s*\S+"):
        return True
    for raw in (timesyncd_text or "").splitlines():
        if raw.startswith("FallbackNTP=") or raw.startswith("SystemNTPServers=") or raw.startswith("ServerName="):
            value = raw.split("=", 1)[1].strip()
            if value and value not in {"n/a", "none"}:
                return True
    return False


def host_audit_time_checks(services, chrony_text, timesyncd_text, synchronized, require_sync):
    services = services or {}
    names = ("chrony", "chronyd", "systemd-timesyncd", "ntp", "ntpd", "ntpsec")
    active = [name for name in names if _active(services, name)]
    configured = _has_time_source(chrony_text or "", timesyncd_text or "")
    checks = [
        {
            "name": "service",
            "status": "pass" if active else "fail",
            "evidence": "служба времени запущена: " + ", ".join(active) if active else "chrony/systemd-timesyncd/ntp не запущены",
        },
        {
            "name": "sources",
            "status": "pass" if configured else "fail",
            "evidence": "в конфигурации или timedatectl есть серверы времени"
            if configured
            else "не найдены server/pool, NTP= или FallbackNTP",
        },
    ]
    if not _as_bool(require_sync):
        checks.append(
            {
                "name": "synchronized",
                "status": "skip",
                "evidence": "проверка NTPSynchronized отключена (host_audit_time_require_synchronized=false)",
            }
        )
    else:
        synced = str(synchronized or "").strip().lower() in {"yes", "true", "1"}
        checks.append(
            {
                "name": "synchronized",
                "status": "pass" if synced else "fail",
                "evidence": f"NTPSynchronized={synchronized or 'нет'}",
            }
        )
    return checks


class FilterModule:
    def filters(self):
        return {
            "host_audit_bruteforce_checks": host_audit_bruteforce_checks,
            "host_audit_pam_includes": pam_includes,
            "host_audit_mfa_checks": host_audit_mfa_checks,
            "host_audit_audit_checks": host_audit_audit_checks,
            "host_audit_log_checks": host_audit_log_checks,
            "host_audit_time_checks": host_audit_time_checks,
        }
