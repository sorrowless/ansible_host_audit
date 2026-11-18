"""Build the audit report from individual checks."""

from __future__ import annotations


_STATUS = {"skip": 0, "pass": 1, "warn": 2, "fail": 3}
_SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def host_audit_control(checks, control_id, title, severity, requirement, remediation):
    """Collapse check rows into one control. The worst status wins; skip is ignored."""
    normalized = []
    for check in checks or []:
        status = str(check.get("status", "fail"))
        if status not in _STATUS:
            status = "fail"
        item = {
            "name": str(check.get("name", "check")),
            "status": status,
            "evidence": str(check.get("evidence", "")),
        }
        if check.get("severity") in _SEVERITY:
            item["severity"] = check["severity"]
        normalized.append(item)

    meaningful = [item for item in normalized if item["status"] != "skip"]
    if not meaningful:
        status = "skip"
    else:
        status = max(meaningful, key=lambda item: _STATUS[item["status"]])["status"]

    chosen = severity if severity in _SEVERITY else "high"
    if status == "fail":
        failed = [item for item in normalized if item["status"] == "fail"]
        ranks = [item.get("severity", chosen) for item in failed]
        chosen = max(ranks, key=lambda name: _SEVERITY.get(name, 0))

    return {
        "id": control_id,
        "title": title,
        "status": status,
        "severity": chosen,
        "requirement": requirement,
        "remediation": remediation,
        "checks": normalized,
    }


def host_audit_summary(controls):
    summary = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
    for control in controls or []:
        status = control.get("status", "fail")
        if status not in summary:
            status = "fail"
        summary[status] += 1
    return summary


def host_audit_should_fail(report, threshold):
    level = str(threshold or "none").lower()
    if level in {"none", "false", ""}:
        return False
    if level not in _SEVERITY:
        return True
    limit = _SEVERITY[level]
    for control in report.get("controls") or []:
        if control.get("status") != "fail":
            continue
        rank = _SEVERITY.get(control.get("severity"), _SEVERITY["critical"])
        if rank >= limit:
            return True
    return False


def host_audit_report_name(value):
    """Имя файла отчёта — каталог хоста в host_vars, без разделителей пути."""
    name = str(value or "").strip().replace("\\", "/").rstrip("/")
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    name = name.strip()
    if name in {"", ".", ".."}:
        return "unknown"
    return name


def host_audit_render_text(report):
    summary = report.get("summary") or {}
    lines = [
        "host-audit {host}: fail={fail} warn={warn} pass={pass} skip={skip}".format(
            host=report.get("host", ""),
            fail=summary.get("fail", 0),
            warn=summary.get("warn", 0),
            **{"pass": summary.get("pass", 0)},
            skip=summary.get("skip", 0),
        )
    ]
    for control in report.get("controls") or []:
        lines.append(f"[{control.get('status', 'fail').upper()}] {control.get('id')} {control.get('title')}")
        if control.get("status") not in {"fail", "warn"}:
            continue
        for check in control.get("checks") or []:
            if check.get("status") in {"fail", "warn"}:
                lines.append(f"    - {check.get('name')}: {check.get('evidence')}")
        remediation = control.get("remediation")
        if remediation:
            lines.append(f"    как исправить: {remediation}")
    return "\n".join(lines)


class FilterModule:
    def filters(self):
        return {
            "host_audit_control": host_audit_control,
            "host_audit_summary": host_audit_summary,
            "host_audit_should_fail": host_audit_should_fail,
            "host_audit_render_text": host_audit_render_text,
            "host_audit_report_name": host_audit_report_name,
        }
