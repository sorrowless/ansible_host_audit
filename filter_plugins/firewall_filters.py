"""Decide whether the host firewall is default-deny and limited to the allowlist."""

from __future__ import annotations

import re


_FIREWALLD_SERVICES = {
    "ssh": [("tcp", 22)],
    "http": [("tcp", 80)],
    "https": [("tcp", 443)],
    "cockpit": [("tcp", 9090)],
    "dns": [("tcp", 53), ("udp", 53)],
    "dhcpv6-client": [],
    "mdns": [("udp", 5353)],
    "samba": [("tcp", 445)],
    "ftp": [("tcp", 21)],
    "smtp": [("tcp", 25)],
    "smtps": [("tcp", 465)],
    "imap": [("tcp", 143)],
    "imaps": [("tcp", 993)],
    "pop3": [("tcp", 110)],
    "pop3s": [("tcp", 995)],
    "mysql": [("tcp", 3306)],
    "postgresql": [("tcp", 5432)],
    "rdp": [("tcp", 3389)],
    "telnet": [("tcp", 23)],
    "tftp": [("udp", 69)],
    "ntp": [("udp", 123)],
}


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "running"}


def _unit(services: dict, name: str) -> dict:
    services = services or {}
    for key in (name, f"{name}.service"):
        if key in services:
            return services[key]
    return {}


def _enabled(services: dict, name: str) -> bool:
    status = str(_unit(services, name).get("status", "")).lower()
    return status in {"enabled", "enabled-runtime"}


def _chain_bodies(text: str) -> list[str]:
    """Return the body of each ``chain ... { }`` block, not the enclosing table."""
    bodies = []
    for match in re.finditer(r"\bchain\s+\S+\s*\{", text or "", re.I):
        start = match.end() - 1
        depth = 0
        for pos in range(start, len(text)):
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(text[start + 1 : pos])
                    break
    return bodies


def parse_nft(text: str) -> dict:
    tcp, udp = set(), set()
    policies = []
    wide = []
    for body in _chain_bodies(text or ""):
        if not re.search(r"\bhook\s+input\b", body):
            continue
        policy = re.search(r"\bpolicy\s+(drop|reject|accept)\b", body, re.I)
        policies.append(policy.group(1).lower() if policy else "accept")
        for raw in body.splitlines():
            line = raw.strip().lower()
            if "accept" not in line:
                continue
            match = re.search(r"\b(tcp|udp)\s+dport\s+(\{[^}]+\}|\d+)", line)
            if match:
                proto = match.group(1)
                numbers = [int(item) for item in re.findall(r"\d+", match.group(2))]
                (tcp if proto == "tcp" else udp).update(numbers)
                continue
            if any(token in line for token in ("ct state", "iif", "icmp")):
                continue
            wide.append(raw.strip())
    deny = bool(policies) and all(item in {"drop", "reject"} for item in policies)
    return {"present": bool(policies), "deny": deny, "tcp": tcp, "udp": udp, "wide": wide}


def parse_ufw(text: str) -> dict:
    active = bool(re.search(r"(?im)^status:\s+active\b", text or ""))
    default = re.search(r"(?im)^default:\s+([a-z]+)\s+\(incoming\)", text or "")
    incoming = default.group(1).lower() if default else ""
    tcp, udp = set(), set()
    for raw in (text or "").splitlines():
        match = re.match(r"^\s*([0-9,]+)/(tcp|udp)(?:\s+\(v6\))?\s+allow(?:\s+in)?\b", raw, re.I)
        if not match:
            continue
        proto = match.group(2).lower()
        numbers = [int(item) for item in match.group(1).split(",") if item]
        (tcp if proto == "tcp" else udp).update(numbers)
    return {
        "active": active,
        "deny": incoming in {"deny", "reject", "drop"},
        "tcp": tcp,
        "udp": udp,
        "wide": [],
    }


def parse_iptables(text: str) -> dict:
    policy = re.search(r"(?m)^-P INPUT (ACCEPT|DROP|REJECT)\b", text or "")
    tcp, udp = set(), set()
    wide = []
    present = policy is not None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("-A INPUT") or "-j ACCEPT" not in line:
            continue
        match = re.search(r"--dports?\s+([0-9,]+)", line)
        if match:
            proto = "udp" if "-p udp" in line else "tcp"
            numbers = [int(item) for item in match.group(1).split(",") if item]
            (tcp if proto == "tcp" else udp).update(numbers)
            continue
        if any(token in line for token in ("-i lo", "--ctstate", "-m conntrack", "-p icmp", "--icmp-type")):
            continue
        wide.append(line)
    name = policy.group(1).lower() if policy else "accept"
    return {
        "present": present,
        "deny": name in {"drop", "reject"},
        "tcp": tcp,
        "udp": udp,
        "wide": wide,
    }


def _port_checks(label, tcp, udp, allowed_tcp, allowed_udp, wide) -> list[dict]:
    allowed_tcp = {int(item) for item in allowed_tcp or []}
    allowed_udp = {int(item) for item in allowed_udp or []}
    extra_tcp = sorted(set(tcp) - allowed_tcp)
    extra_udp = sorted(set(udp) - allowed_udp)
    problems = []
    if extra_tcp:
        problems.append("лишние TCP: " + ", ".join(str(item) for item in extra_tcp))
    if extra_udp:
        problems.append("лишние UDP: " + ", ".join(str(item) for item in extra_udp))
    if wide:
        problems.append("ACCEPT без порта: " + "; ".join(wide[:4]))
    if problems:
        return [
            {
                "name": "ports",
                "status": "fail",
                "evidence": f"{label}: " + "; ".join(problems),
            }
        ]
    shown_tcp = ", ".join(str(item) for item in sorted(tcp)) or "нет"
    shown_udp = ", ".join(str(item) for item in sorted(udp)) or "нет"
    return [
        {
            "name": "ports",
            "status": "pass",
            "evidence": f"{label}: открыты только разрешённые порты (tcp: {shown_tcp}; udp: {shown_udp})",
        }
    ]


def host_audit_firewall_checks(observed, services, allowed_tcp, allowed_udp):
    observed = observed or {}
    services = services or {}
    ufw = parse_ufw(observed.get("ufw_text") or "")
    nft = parse_nft(observed.get("nft_text") or "")
    iptables = parse_iptables(observed.get("iptables_text") or "")
    firewalld_active = _as_bool(observed.get("firewalld_active"))

    if ufw["active"]:
        backend = "ufw"
        deny = ufw["deny"]
        ports = _port_checks("ufw", ufw["tcp"], ufw["udp"], allowed_tcp, allowed_udp, ufw["wide"])
        persistent = _enabled(services, "ufw")
        persistent_evidence = "сервис ufw включён" if persistent else "ufw активен, но не enabled и не переживёт перезагрузку"
    elif firewalld_active:
        backend = "firewalld"
        target = str(observed.get("firewalld_target") or "").lower()
        deny = target in {"default", "drop", "reject", "%%reject"}
        tcp, udp = set(), set()
        unknown = []
        for service in observed.get("firewalld_services") or []:
            if service not in _FIREWALLD_SERVICES:
                unknown.append(service)
                continue
            for proto, port in _FIREWALLD_SERVICES[service]:
                (tcp if proto == "tcp" else udp).add(port)
        for raw in observed.get("firewalld_ports") or []:
            match = re.match(r"(\d+)/(tcp|udp)", str(raw).lower())
            if not match:
                unknown.append(str(raw))
                continue
            (tcp if match.group(2) == "tcp" else udp).add(int(match.group(1)))
        wide = [f"неизвестный сервис или порт: {', '.join(unknown)}"] if unknown else []
        ports = _port_checks("firewalld", tcp, udp, allowed_tcp, allowed_udp, wide)
        persistent = _enabled(services, "firewalld")
        persistent_evidence = (
            "сервис firewalld включён" if persistent else "firewalld запущен, но не enabled"
        )
    elif nft["present"]:
        backend = "nftables"
        deny = nft["deny"]
        ports = _port_checks("nftables", nft["tcp"], nft["udp"], allowed_tcp, allowed_udp, nft["wide"])
        persistent = _enabled(services, "nftables")
        persistent_evidence = (
            "сервис nftables включён" if persistent else "правила nft загружены, но сервис nftables не enabled"
        )
    elif iptables["present"]:
        backend = "iptables"
        deny = iptables["deny"]
        ports = _port_checks("iptables", iptables["tcp"], iptables["udp"], allowed_tcp, allowed_udp, iptables["wide"])
        persistent = _enabled(services, "netfilter-persistent") or _enabled(services, "iptables")
        persistent_evidence = (
            "persistence для iptables включена"
            if persistent
            else "политика iptables есть, но сервис сохранения правил не включён"
        )
    else:
        return [
            {
                "name": "backend",
                "status": "fail",
                "evidence": "нет активного ufw, firewalld, nftables или iptables с политикой INPUT",
            }
        ]

    checks = [
        {"name": "backend", "status": "pass", "evidence": f"используется {backend}"},
        {
            "name": "default_deny",
            "status": "pass" if deny else "fail",
            "evidence": f"{backend}: политика входа default-deny" if deny else f"{backend}: вход по умолчанию не запрещён",
        },
    ]
    checks.extend(ports)
    # iptables without a persistence unit is a warning: the policy is real, but it may not survive reboot.
    persistent_status = "pass" if persistent else ("warn" if backend == "iptables" else "fail")
    checks.append({"name": "persistent", "status": persistent_status, "evidence": persistent_evidence})
    return checks


class FilterModule:
    def filters(self):
        return {
            "host_audit_firewall_checks": host_audit_firewall_checks,
            "host_audit_parse_nft": parse_nft,
        }
