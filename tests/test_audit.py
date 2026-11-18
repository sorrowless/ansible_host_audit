"""Unit tests for parsers. They do not need Ansible or Docker."""

from __future__ import annotations

import importlib.util
import struct
import unittest
from base64 import b64encode
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SSH = load("host_audit_sshd", "library/host_audit_sshd.py")
KEYS = load("host_audit_keys", "library/host_audit_keys.py")
SSH_FILTERS = load("ssh_filters", "filter_plugins/ssh_filters.py")
SUDO = load("sudo_filters", "filter_plugins/sudo_filters.py")
FIREWALL = load("firewall_filters", "filter_plugins/firewall_filters.py")
BASELINE = load("baseline_filters", "filter_plugins/baseline_filters.py")
RUNTIME = load("runtime_filters", "filter_plugins/runtime_filters.py")
REPORT = load("report_filters", "filter_plugins/report_filters.py")


VULNERABLE = {
    "/etc/ssh/sshd_config": """
Include /etc/ssh/sshd_config.d/*.conf
# Эти строки выглядят безопасно, но читаются после drop-in.
PasswordAuthentication no
PermitRootLogin no
""",
    "/etc/ssh/sshd_config.d/00-insecure.conf": """
PasswordAuthentication yes
PermitRootLogin yes
""",
    "/etc/ssh/sshd_config.d/50-too-late.conf": """
PasswordAuthentication no
PermitRootLogin no
""",
}

HARDENED = {
    "/etc/ssh/sshd_config": """
Include /etc/ssh/sshd_config.d/*.conf
PasswordAuthentication yes
PermitRootLogin yes
""",
    "/etc/ssh/sshd_config.d/00-hardening.conf": """
PasswordAuthentication no
PermitRootLogin no
AllowUsers auditor
AuthenticationMethods publickey,keyboard-interactive
KbdInteractiveAuthentication yes
UsePAM yes
""",
}


def _fs_reader(files):
    def read_text(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    def list_glob(pattern):
        import fnmatch

        return sorted(path for path in files if fnmatch.fnmatch(path, pattern))

    return read_text, list_glob


class SshdParserTests(unittest.TestCase):
    def test_drop_in_wins_when_it_is_first(self):
        read_text, list_glob = _fs_reader(VULNERABLE)
        parsed = SSH.parse_sshd_tree("/etc/ssh/sshd_config", read_text, list_glob)
        self.assertEqual(parsed["globals"]["passwordauthentication"], "yes")
        self.assertEqual(parsed["globals"]["permitrootlogin"], "yes")
        self.assertTrue(parsed["sources"]["passwordauthentication"].endswith("00-insecure.conf"))
        self.assertNotIn("allowusers", parsed["globals"])

    def test_later_drop_in_does_not_override(self):
        read_text, list_glob = _fs_reader(VULNERABLE)
        parsed = SSH.parse_sshd_tree("/etc/ssh/sshd_config", read_text, list_glob)
        self.assertNotEqual(parsed["sources"]["passwordauthentication"], "/etc/ssh/sshd_config.d/50-too-late.conf")

    def test_early_hardening_beats_main_file(self):
        read_text, list_glob = _fs_reader(HARDENED)
        parsed = SSH.parse_sshd_tree("/etc/ssh/sshd_config", read_text, list_glob)
        self.assertEqual(parsed["globals"]["passwordauthentication"], "no")
        self.assertEqual(parsed["globals"]["permitrootlogin"], "no")
        self.assertEqual(parsed["globals"]["allowusers"], "auditor")
        self.assertTrue(parsed["sources"]["passwordauthentication"].endswith("00-hardening.conf"))

    def test_match_password_is_a_risk_even_when_global_is_no(self):
        files = {
            "/etc/ssh/sshd_config": """
PasswordAuthentication no
PermitRootLogin no
Match User admin
    PasswordAuthentication yes
    PermitRootLogin yes
""",
        }
        read_text, list_glob = _fs_reader(files)
        parsed = SSH.parse_sshd_tree("/etc/ssh/sshd_config", read_text, list_glob)
        self.assertEqual(parsed["globals"]["passwordauthentication"], "no")
        kinds = {risk["kind"] for risk in parsed["risks"]}
        self.assertEqual(kinds, {"passwordauthentication", "permitrootlogin"})

    def test_comments_are_ignored(self):
        files = {"/etc/ssh/sshd_config": "# PasswordAuthentication yes\nPasswordAuthentication no\n"}
        read_text, list_glob = _fs_reader(files)
        parsed = SSH.parse_sshd_tree("/etc/ssh/sshd_config", read_text, list_glob)
        self.assertEqual(parsed["globals"]["passwordauthentication"], "no")

    def test_evaluation_uses_sshd_t_and_names_the_drop_in(self):
        read_text, list_glob = _fs_reader(VULNERABLE)
        parsed = SSH.parse_sshd_tree("/etc/ssh/sshd_config", read_text, list_glob)
        parsed.update(
            {
                "sshd_t": SSH.parse_sshd_t("passwordauthentication yes\npermitrootlogin yes\n"),
                "sshd_t_rc": 0,
                "sshd_t_stderr": "",
                "daemon": {"running": True, "drift": False, "pid": 10},
                "error": "",
            }
        )
        checks = SSH_FILTERS.host_audit_ssh_password_checks(parsed)
        failed = [item for item in checks if item["status"] == "fail"]
        self.assertTrue(any("00-insecure.conf" in item["evidence"] for item in failed))
        self.assertTrue(any("PasswordAuthentication yes" in item["evidence"] for item in failed))

    def test_wildcard_allowusers_is_not_a_restriction(self):
        result = {
            "globals": {"allowusers": "*"},
            "sources": {"allowusers": "/etc/ssh/sshd_config"},
            "sshd_t": {"allowusers": ["*"]},
            "sshd_t_rc": 0,
            "risks": [],
            "warnings": [],
            "daemon": {"running": True, "drift": False, "pid": 1},
            "error": "",
        }
        checks = SSH_FILTERS.host_audit_ssh_access_checks(result)
        self.assertEqual(checks[0]["status"], "fail")


def _openssh(cipher: bytes, kdf: bytes) -> bytes:
    def ssh_string(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    raw = b"openssh-key-v1\x00" + ssh_string(cipher) + ssh_string(kdf) + ssh_string(b"")
    body = b64encode(raw)
    lines = [body[index : index + 70] for index in range(0, len(body), 70)]
    return b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"\n".join(lines) + b"\n-----END OPENSSH PRIVATE KEY-----\n"


class KeyTests(unittest.TestCase):
    def test_openssh_without_passphrase(self):
        self.assertEqual(KEYS.classify_private_key(_openssh(b"none", b"none")), "unencrypted")

    def test_openssh_with_passphrase(self):
        self.assertEqual(KEYS.classify_private_key(_openssh(b"aes256-ctr", b"bcrypt")), "encrypted")

    def test_pem_and_public_key(self):
        pem = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        plain = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        public = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample comment\n"
        self.assertEqual(KEYS.classify_private_key(pem), "encrypted")
        self.assertEqual(KEYS.classify_private_key(plain), "unencrypted")
        self.assertIsNone(KEYS.classify_private_key(public))

    def test_controller_finding(self):
        checks = SSH_FILTERS.host_audit_key_checks(
            {"keys": [{"path": "/tmp/id_ed25519", "state": "unencrypted", "mode": "0600", "exposed": False}], "errors": []},
            "controller",
        )
        self.assertEqual(checks[0]["status"], "fail")


class PolicyTests(unittest.TestCase):
    def test_sudo_ignores_root_and_flags_nopasswd_all(self):
        text = "\n".join(
            [
                "root ALL=(ALL:ALL) ALL",
                "%sudo ALL=(ALL:ALL) ALL",
                "demokey ALL=(ALL) NOPASSWD: ALL",
                "auditor ALL=(root) NOPASSWD: /usr/bin/systemctl status ssh",
                "#includedir /etc/sudoers.d",
            ]
        )
        findings = SUDO.parse_sudoers(text, "/etc/sudoers")
        nopasswd = [item for item in findings if item["nopasswd"]]
        broad = [item for item in findings if not item["nopasswd"]]
        self.assertEqual(len(nopasswd), 1)
        self.assertIn("demokey", nopasswd[0]["text"])
        self.assertEqual(len(broad), 1)
        self.assertIn("%sudo", broad[0]["text"])
        includes = SUDO.sudo_includes(text)
        self.assertEqual(includes[0]["path"], "/etc/sudoers.d")

    def test_nft_default_deny_allows_only_ssh(self):
        ruleset = """
        table inet filter {
            chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                tcp dport 22 accept
                ip protocol icmp accept
            }
            chain output {
                type filter hook output priority filter; policy accept;
            }
        }
        """
        parsed = FIREWALL.parse_nft(ruleset)
        self.assertTrue(parsed["deny"])
        self.assertEqual(parsed["tcp"], {22})
        self.assertFalse(parsed["wide"])
        services = {"nftables.service": {"status": "enabled", "state": "active"}}
        checks = FIREWALL.host_audit_firewall_checks(
            {"nft_text": ruleset, "ufw_text": "", "iptables_text": "", "firewalld_active": False},
            services,
            [22],
            [],
        )
        self.assertTrue(all(item["status"] == "pass" for item in checks))

    def test_nft_extra_port_fails(self):
        ruleset = """
        table inet filter {
            chain input {
                type filter hook input priority filter; policy drop;
                tcp dport { 22, 80 } accept
            }
        }
        """
        checks = FIREWALL.host_audit_firewall_checks(
            {"nft_text": ruleset, "ufw_text": "Status: inactive\n", "iptables_text": "", "firewalld_active": "false"},
            {"nftables.service": {"status": "enabled", "state": "running"}},
            [22],
            [],
        )
        ports = [item for item in checks if item["name"] == "ports"][0]
        self.assertEqual(ports["status"], "fail")
        self.assertIn("80", ports["evidence"])

    def test_password_policy_and_accounts(self):
        files = {
            "/etc/login.defs": "PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD yescrypt\n",
            "/etc/security/pwquality.conf": "minlen = 14\nminclass = 4\n",
            "/etc/security/faillock.conf": "deny = 5\nunlock_time = 900\n",
            "/etc/default/useradd": "INACTIVE=30\n",
            "/etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\npassword required pam_pwhistory.so remember=5\n",
            "/etc/pam.d/common-auth": "auth required pam_faillock.so preauth\n",
        }
        checks = BASELINE.host_audit_password_checks(
            files,
            {
                "pass_max_days": 365,
                "pass_min_days": 1,
                "pass_warn_age": 7,
                "minlen": 14,
                "minclass": 4,
                "remember": 5,
                "fail_deny": 5,
                "unlock_time": 900,
                "inactive_days": 30,
            },
            [],
        )
        self.assertTrue(all(item["status"] == "pass" for item in checks), checks)
        accounts = BASELINE.host_audit_accounts("root:0:/bin/bash\ndemo:1000:/bin/bash\ngames:5:/usr/sbin/nologin\n", "root:set\ndemo:set\ngames:locked\n")
        surface = BASELINE.host_audit_surface_checks(
            ["telnet"],
            {"telnet.service": {"state": "running", "status": "enabled"}},
            accounts,
            ["telnet"],
            ["telnet"],
            ["demo", "games"],
        )
        by_name = {item["name"]: item["status"] for item in surface}
        self.assertEqual(by_name["packages"], "fail")
        self.assertEqual(by_name["services"], "fail")
        self.assertEqual(by_name["demo_accounts"], "fail")
        self.assertEqual(by_name["uid0"], "pass")
        disabled = BASELINE.host_audit_accounts(
            "games:5:/usr/sbin/nologin\nnews:9:/usr/sbin/nologin\n",
            "",
        )
        quiet = BASELINE.host_audit_surface_checks([], {}, disabled, [], [], ["games", "news"])
        self.assertEqual(quiet[2]["status"], "pass")
        updates = BASELINE.host_audit_update_checks(
            "Debian",
            ["unattended-upgrades"],
            {
                "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";\n',
                "/etc/apt/apt.conf.d/50unattended-upgrades": 'Allowed-Origins { "${distro_id}:${distro_codename}-security"; };\n',
            },
            {},
            {"apt-daily-upgrade.timer": "enabled"},
        )
        self.assertEqual(updates[0]["status"], "pass", updates)

    def test_report_threshold(self):
        control = REPORT.host_audit_control(
            [{"name": "one", "status": "fail", "severity": "critical"}],
            "SUD-01",
            "sudo",
            "high",
            "req",
            "fix",
        )
        report = {"controls": [control], "summary": REPORT.host_audit_summary([control]), "host": "test"}
        self.assertTrue(REPORT.host_audit_should_fail(report, "high"))
        self.assertFalse(REPORT.host_audit_should_fail(report, "none"))
        self.assertEqual(control["severity"], "critical")
        self.assertIn("[FAIL] SUD-01", REPORT.host_audit_render_text(report))

    def test_report_name_is_host_vars_directory(self):
        self.assertEqual(REPORT.host_audit_report_name("web-01"), "web-01")
        self.assertEqual(REPORT.host_audit_report_name(" host_vars/bastion/ "), "bastion")
        self.assertEqual(REPORT.host_audit_report_name(""), "unknown")


class RuntimeTests(unittest.TestCase):
    def test_mfa_requires_second_factor(self):
        sshd = {
            "sshd_t": {
                "authenticationmethods": ["publickey,keyboard-interactive"],
                "usepam": ["yes"],
                "kbdinteractiveauthentication": ["yes"],
            }
        }
        pam = "auth required pam_google_authenticator.so\n"
        checks = RUNTIME.host_audit_mfa_checks(sshd, pam, ["pam_google_authenticator.so"], True, ["pam_google_authenticator.so"])
        self.assertTrue(all(item["status"] == "pass" for item in checks), checks)
        skipped = RUNTIME.host_audit_mfa_checks({}, "", [], False, [])
        self.assertEqual(skipped[0]["status"], "skip")

    def test_publickey_only_is_not_mfa(self):
        sshd = {"sshd_t": {"authenticationmethods": ["publickey"], "usepam": ["yes"]}}
        checks = RUNTIME.host_audit_mfa_checks(sshd, "", [], True, ["pam_google_authenticator.so"])
        methods = [item for item in checks if item["name"] == "authentication_methods"][0]
        self.assertEqual(methods["status"], "fail")


if __name__ == "__main__":
    unittest.main()
