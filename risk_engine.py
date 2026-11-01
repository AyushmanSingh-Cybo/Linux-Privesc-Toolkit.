
import re
import stat


def _permission_mode(value):
    """Parse common Unix permission formats safely."""
    if isinstance(value, int):
        return value if 0 <= value <= 0o7777 else None

    text = str(value).strip().lower()

    try:
        if text.startswith("0o"):
            return int(text, 8)
        if re.fullmatch(r"[0-7]{3,4}", text):
            return int(text, 8)
    except ValueError:
        pass

    return None


def assess_risk(finding):
    """Assign preliminary security review priority, not exploitability."""

    if not isinstance(finding, dict):
        finding = {
            "type": "Configuration review",
            "details": str(finding),
        }

    finding_type = str(finding.get("type", "")).lower()
    details = str(finding.get("details", "")).lower()
    path = str(finding.get("path", "")).lower()
    permissions = _permission_mode(finding.get("permissions", ""))

    text = f"{finding_type} {details} {path}"
    score = 10

    # Incomplete scans are operational warnings, not vulnerabilities.
    if finding.get("check_status") == "incomplete" or any(
        word in finding_type
        for word in ("warning", "error", "timeout")
    ):
        return {
            "risk_level": "Low",
            "risk_score": 10,
        }

    # 1. Linux capabilities
    if "capability" in finding_type or "cap_" in text:
        score = 30

        high_risk_capabilities = (
            "cap_sys_admin",
            "cap_sys_ptrace",
            "cap_dac_override",
            "cap_dac_read_search",
            "cap_setuid",
            "cap_setgid",
            "cap_sys_module",
            "cap_sys_rawio",
        )

        if any(cap in text for cap in high_risk_capabilities):
            score = 75
        elif "cap_net_admin" in text:
            score = 60
        elif "cap_setfcap" in text or "cap_setpcap" in text:
            score = 65
        elif "cap_net_raw" in text:
            score = 25

    # 2. SUID/SGID binaries
    elif "suid" in finding_type or "sgid" in finding_type:
        score = 35

        common_system_paths = (
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        )

        if path in common_system_paths:
            score = 25

    # 3. Cron and scheduled tasks
    elif "cron" in finding_type:
        score = 25

        explicitly_writable = (
            finding.get("writable_by_current_user") is True
            or "writable scheduled-task file" in details
            or "writable cron" in details
        )

        if explicitly_writable:
            score = 65

    # 4. File and directory permissions
    elif finding_type in ("file", "directory") or (
    "permission" in finding_type
    and "sudo" not in finding_type
):
        score = 10

        if permissions is not None:
            world_writable = bool(permissions & stat.S_IWOTH)
            group_writable = bool(permissions & stat.S_IWGRP)
            sticky = bool(permissions & stat.S_ISVTX)

            if world_writable:
                if finding_type == "directory" and sticky:
                    score = 30
                else:
                    score = 60

            elif group_writable:
                score = 35

        if "sensitive system file" in details:
            score = max(score, 60)

        if "password shadow file" in details:
            score = max(score, 75)

    # 5. Other writable configuration findings
    elif "world-writable" in text or "world writable" in text:
        score = 55

    elif "writable" in finding_type or "writable" in details:
        score = 35

    # 6. Sudo configuration
    elif "sudo" in finding_type:
        score = 50

        passwordless = (
            "nopasswd" in text
            or "no password" in text
        )

        if passwordless:
            score = 60

        if passwordless and re.search(r"\ball\b", text):
            score = 80

    # Keep score between 0 and 100.
    score = min(max(score, 0), 100)

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_level": level,
        "risk_score": score,
    }


def add_risk_scores(findings):
    """Return a new list with preliminary risk scores added."""

    scored_findings = []

    for finding in findings:
        if isinstance(finding, dict):
            item = finding.copy()
        else:
            item = {
                "type": "Configuration review",
                "details": str(finding),
            }

        item.update(assess_risk(item))
        scored_findings.append(item)

    return scored_findings
