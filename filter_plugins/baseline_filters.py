"""Sysctl, file modes, password policy, packages, and accounts."""

from __future__ import annotations

import re


def _mode_int(mode) -> int:
    if isinstance(mode, int):
        return mode & 0o777
    return int(str(mode), 8)


def _compare(actual: str, op: str, expected: str) -> bool:
    if op == "eq":
        return actual == expected
    try:
        left = int(actual)
        right = int(expected)
    except ValueError:
        return False
    if op == "ge":
        return left >= right
    if op == "le":
        return left <= right
    return False


def host_audit_sysctl_checks(loop_results, expectations, skip=None):
    skipped = set(skip or [])
    by_key = {}
    for row in loop_results or []:
        if not isinstance(row, dict) or row.get("skipped"):
            continue
        item = row.get("item") or {}
        by_key[item.get("key")] = row
    checks = []
    for exp in expectations or []:
        key = exp.get("key")
        if key in skipped:
            checks.append({"name": key, "status": "skip", "evidence": f"{key} исключён host_audit_sysctl_skip"})
            continue
        row = by_key.get(key) or {}
        optional = bool(exp.get("optional"))
        rc = row.get("rc")
        actual = str(row.get("stdout") or "").strip()
        if rc not in (0, "0") or actual == "":
            err = str(row.get("stderr") or row.get("msg") or "нет значения").strip()
            checks.append(
                {
                    "name": key,
                    "status": "skip" if optional else "fail",
                    "evidence": f"{key}: не прочитан ({err})",
                }
            )
            continue
        op = exp.get("op", "eq")
        expected = str(exp.get("value"))
        ok = _compare(actual, op, expected)
        checks.append(
            {
                "name": key,
                "status": "pass" if ok else "fail",
                "evidence": f"{key}={actual}, ожидается {op} {expected}",
            }
        )
    return checks


def host_audit_perm_checks(rows):
    checks = []
    for row in rows or []:
        if not isinstance(row, dict) or row.get("skipped"):
            continue
        item = row.get("item") or {}
        path = item.get("path", "")
        stat_result = row.get("stat") or {}
        if not stat_result.get("exists"):
            checks.append(
                {
                    "name": path,
                    "status": "skip" if item.get("optional") else "fail",
                    "evidence": f"{path} отсутствует",
                }
            )
            continue
        mode = stat_result.get("mode")
        owner = stat_result.get("pw_name")
        group = stat_result.get("gr_name")
        problems = []
        try:
            if _mode_int(mode) & ~_mode_int(item.get("mode_max", "0777")) & 0o777:
                problems.append(f"режим {mode}, допустимо не шире {item.get('mode_max')}")
        except (TypeError, ValueError):
            problems.append(f"режим {mode} не разобран")
        if item.get("owner") and owner != item.get("owner"):
            problems.append(f"владелец {owner}, ожидается {item.get('owner')}")
        groups = item.get("group_any") or []
        if groups and group not in groups:
            problems.append(f"группа {group}, ожидается одна из {', '.join(groups)}")
        checks.append(
            {
                "name": path,
                "status": "fail" if problems else "pass",
                "evidence": "; ".join(problems) if problems else f"{path} {mode} {owner}:{group}",
            }
        )
    return checks


def host_audit_dropin_rows(stat_rows):
    """Adapt a stat loop over sshd drop-ins to the permission checker."""
    rows = []
    for row in stat_rows or []:
        if not isinstance(row, dict):
            continue
        path = (row.get("stat") or {}).get("path") or (row.get("item") or {}).get("path")
        rows.append(
            {
                "item": {
                    "path": path,
                    "mode_max": "0600",
                    "owner": "root",
                    "group_any": ["root"],
                    "optional": False,
                },
                "stat": row.get("stat") or {},
                "skipped": row.get("skipped", False),
            }
        )
    return rows


def _strip(line: str) -> str:
    out = []
    quote = ""
    for char in line:
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
            continue
        if char == "#":
            break
        if char in {'"', "'"}:
            quote = char
            continue
        out.append(char)
    return "".join(out).strip()


def parse_kv(text: str, upper: bool = False) -> dict:
    data = {}
    for raw in (text or "").splitlines():
        line = _strip(raw)
        if not line:
            continue
        if "=" in line:
            key, value = line.split("=", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        data[key.upper() if upper else key.lower()] = value
    return data


def _as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _uncommented(text: str, pattern: str) -> bool:
    regex = re.compile(pattern, re.I)
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if regex.search(line):
            return True
    return False


def host_audit_password_checks(files, policy, empty_users):
    files = files or {}
    policy = policy or {}
    login = parse_kv(files.get("/etc/login.defs", ""), upper=True)
    pwquality = parse_kv(files.get("/etc/security/pwquality.conf", ""), upper=False)
    faillock = parse_kv(files.get("/etc/security/faillock.conf", ""), upper=False)
    useradd = parse_kv(files.get("/etc/default/useradd", ""), upper=True)
    pam = "\n".join(
        files.get(path, "")
        for path in (
            "/etc/pam.d/common-password",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
        )
    )
    checks = []

    def _limit(name, actual, ok, detail):
        checks.append(
            {
                "name": name,
                "status": "pass" if ok else "fail",
                "evidence": detail,
            }
        )

    max_days = _as_int(login.get("PASS_MAX_DAYS"))
    _limit(
        "PASS_MAX_DAYS",
        max_days,
        max_days is not None and 0 < max_days <= int(policy.get("pass_max_days", 365)),
        f"PASS_MAX_DAYS={login.get('PASS_MAX_DAYS', 'нет')}, нужно от 1 до {policy.get('pass_max_days', 365)}",
    )
    min_days = _as_int(login.get("PASS_MIN_DAYS"))
    _limit(
        "PASS_MIN_DAYS",
        min_days,
        min_days is not None and min_days >= int(policy.get("pass_min_days", 1)),
        f"PASS_MIN_DAYS={login.get('PASS_MIN_DAYS', 'нет')}, нужно не меньше {policy.get('pass_min_days', 1)}",
    )
    warn_age = _as_int(login.get("PASS_WARN_AGE"))
    _limit(
        "PASS_WARN_AGE",
        warn_age,
        warn_age is not None and warn_age >= int(policy.get("pass_warn_age", 7)),
        f"PASS_WARN_AGE={login.get('PASS_WARN_AGE', 'нет')}, нужно не меньше {policy.get('pass_warn_age', 7)}",
    )
    encrypt = str(login.get("ENCRYPT_METHOD", "")).lower()
    _limit(
        "ENCRYPT_METHOD",
        encrypt,
        encrypt in {"sha512", "yescrypt"},
        f"ENCRYPT_METHOD={login.get('ENCRYPT_METHOD', 'нет')}, нужно SHA512 или yescrypt",
    )

    minlen = _as_int(pwquality.get("minlen"))
    _limit(
        "minlen",
        minlen,
        minlen is not None and minlen >= int(policy.get("minlen", 14)),
        f"pwquality minlen={pwquality.get('minlen', 'нет')}, нужно не меньше {policy.get('minlen', 14)}",
    )
    minclass = _as_int(pwquality.get("minclass"))
    credits_ok = all(_as_int(pwquality.get(name)) is not None and _as_int(pwquality.get(name)) <= -1 for name in ("dcredit", "ucredit", "lcredit", "ocredit"))
    class_ok = minclass is not None and minclass >= int(policy.get("minclass", 4))
    _limit(
        "complexity",
        minclass,
        class_ok or credits_ok,
        "pwquality требует 4 класса или все credit <= -1" if (class_ok or credits_ok) else "pwquality не требует достаточного разнообразия символов",
    )
    _limit(
        "pam_pwquality",
        None,
        "pam_pwquality.so" in pam,
        "pam_pwquality.so подключён" if "pam_pwquality.so" in pam else "в PAM нет pam_pwquality.so",
    )
    remembered = [int(item) for item in re.findall(r"remember=(\d+)", pam)]
    remember_ok = any(item >= int(policy.get("remember", 5)) for item in remembered)
    _limit(
        "remember",
        None,
        remember_ok,
        f"PAM remember={max(remembered) if remembered else 'нет'}, нужно не меньше {policy.get('remember', 5)}",
    )

    faillock_present = "pam_faillock.so" in pam or "pam_tally2.so" in pam
    deny = _as_int(faillock.get("deny"))
    if deny is None:
        found = re.findall(r"deny=(\d+)", pam)
        deny = int(found[0]) if found else None
    unlock = _as_int(faillock.get("unlock_time"))
    if unlock is None:
        found = re.findall(r"unlock_time=(\d+)", pam)
        unlock = int(found[0]) if found else None
    faillock_ok = (
        faillock_present
        and deny is not None
        and 0 < deny <= int(policy.get("fail_deny", 5))
        and unlock is not None
        and (unlock == 0 or unlock >= int(policy.get("unlock_time", 900)))
    )
    _limit(
        "faillock",
        deny,
        faillock_ok,
        f"faillock deny={deny}, unlock_time={unlock}, модуль={'да' if faillock_present else 'нет'}",
    )

    inactive = _as_int(useradd.get("INACTIVE"))
    _limit(
        "INACTIVE",
        inactive,
        inactive is not None and 0 <= inactive <= int(policy.get("inactive_days", 30)),
        f"useradd INACTIVE={useradd.get('INACTIVE', 'нет')}, нужно от 0 до {policy.get('inactive_days', 30)}",
    )
    empties = [name for name in (empty_users or []) if name]
    _limit(
        "empty_passwords",
        None,
        not empties,
        "пустых паролей нет" if not empties else "пустой пароль у: " + ", ".join(empties),
    )
    return checks


def host_audit_accounts(passwd_text, shadow_text):
    shadows = {}
    for line in (shadow_text or "").splitlines():
        name, separator, kind = line.partition(":")
        if separator and name:
            shadows[name] = kind.strip()
    accounts = []
    for line in (passwd_text or "").splitlines():
        parts = line.split(":")
        if len(parts) < 3:
            continue
        name, uid, shell = parts[0], parts[1], parts[2]
        accounts.append(
            {
                "name": name,
                "uid": uid,
                "shell": shell,
                "shadow": shadows.get(name, "missing"),
            }
        )
    return accounts


def _shell_disabled(shell: str) -> bool:
    base = str(shell or "").strip().rsplit("/", 1)[-1]
    return base in {"nologin", "false"}


def _service_problem(services: dict, name: str) -> str:
    for key in (name, f"{name}.service", f"{name}.socket"):
        info = (services or {}).get(key)
        if not info:
            continue
        state = str(info.get("state", "")).lower()
        status = str(info.get("status", "")).lower()
        if state == "running" or status in {"enabled", "enabled-runtime"}:
            return f"{key} state={state or '-'} status={status or '-'}"
    return ""


def host_audit_surface_checks(packages, services, accounts, forbidden_packages, forbidden_services, demo_accounts):
    installed = set(packages or [])
    present_packages = sorted(name for name in (forbidden_packages or []) if name in installed)
    running = [text for name in (forbidden_services or []) if (text := _service_problem(services, name))]
    uid0 = sorted(account["name"] for account in (accounts or []) if str(account.get("uid")) == "0" and account.get("name") != "root")
    demo_hits = []
    wanted = set(demo_accounts or [])
    for account in accounts or []:
        if account.get("name") not in wanted:
            continue
        shell_ok = _shell_disabled(account.get("shell", ""))
        if shell_ok:
            continue
        demo_hits.append(
            f"{account.get('name')} shell={account.get('shell') or '-'} password={account.get('shadow') or 'missing'}"
        )
    return [
        {
            "name": "packages",
            "status": "fail" if present_packages else "pass",
            "evidence": "лишние пакеты: " + ", ".join(present_packages) if present_packages else "запрещённые пакеты не установлены",
        },
        {
            "name": "services",
            "status": "fail" if running else "pass",
            "evidence": "лишние сервисы: " + "; ".join(running) if running else "запрещённые сервисы не запущены и не включены",
        },
        {
            "name": "demo_accounts",
            "status": "fail" if demo_hits else "pass",
            "evidence": "демо-учётки: " + "; ".join(demo_hits) if demo_hits else "демо-учётки отсутствуют или заблокированы",
        },
        {
            "name": "uid0",
            "status": "fail" if uid0 else "pass",
            "severity": "critical",
            "evidence": "UID 0 кроме root: " + ", ".join(uid0) if uid0 else "только root имеет UID 0",
        },
    ]


def _timer_enabled(services: dict, name: str, explicit: dict | None = None) -> bool:
    for key in (name, f"{name}.timer", f"{name}.service"):
        state = str((explicit or {}).get(key, "")).lower()
        if state in {"enabled", "enabled-runtime"}:
            return True
        info = (services or {}).get(key)
        if not info:
            continue
        status = str(info.get("status", "")).lower()
        runtime = str(info.get("state", "")).lower()
        if status in {"enabled", "enabled-runtime"} or runtime == "running":
            return True
    return False


def host_audit_update_checks(os_family, packages, files, services, timers=None):
    packages = set(packages or [])
    files = files or {}
    joined = "\n".join(files.values())
    family = str(os_family or "")
    if family == "Debian":
        enabled = _uncommented(joined, r'APT::Periodic::Unattended-Upgrade\s+"1"')
        security = _uncommented(joined, r"-security\b|esm")
        timer = _timer_enabled(services, "apt-daily-upgrade.timer", timers) or _timer_enabled(
            services, "apt-daily-upgrade", timers
        )
        installed = "unattended-upgrades" in packages
        ok = installed and enabled and security and timer
        evidence = (
            f"пакет={'да' if installed else 'нет'}, "
            f"Unattended-Upgrade={'1' if enabled else 'не 1'}, "
            f"security origin={'да' if security else 'нет'}, "
            f"таймер={'включён' if timer else 'выключен'}"
        )
        return [{"name": "unattended", "status": "pass" if ok else "fail", "evidence": evidence}]
    if family == "RedHat":
        installed = "dnf-automatic" in packages
        timer = _timer_enabled(services, "dnf-automatic-install.timer", timers) or _timer_enabled(
            services, "dnf-automatic.timer", timers
        )
        automatic = parse_kv(files.get("/etc/dnf/automatic.conf", ""), upper=False)
        apply_updates = str(automatic.get("apply_updates", "")).lower() == "yes"
        upgrade_type = str(automatic.get("upgrade_type", "")).lower()
        security = upgrade_type == "security"
        ok = installed and timer and apply_updates and security
        evidence = (
            f"пакет={'да' if installed else 'нет'}, таймер={'включён' if timer else 'выключен'}, "
            f"apply_updates={automatic.get('apply_updates', 'нет')}, upgrade_type={upgrade_type or 'нет'}"
        )
        return [{"name": "dnf_automatic", "status": "pass" if ok else "fail", "evidence": evidence}]
    return [
        {
            "name": "unsupported_os",
            "status": "warn",
            "evidence": f"автообновления для семейства {family or 'unknown'} этой версией роли не проверяются",
        }
    ]


class FilterModule:
    def filters(self):
        return {
            "host_audit_sysctl_checks": host_audit_sysctl_checks,
            "host_audit_perm_checks": host_audit_perm_checks,
            "host_audit_dropin_rows": host_audit_dropin_rows,
            "host_audit_password_checks": host_audit_password_checks,
            "host_audit_surface_checks": host_audit_surface_checks,
            "host_audit_update_checks": host_audit_update_checks,
            "host_audit_accounts": host_audit_accounts,
        }
