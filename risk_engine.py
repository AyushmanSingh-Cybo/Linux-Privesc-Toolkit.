
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
    permissions = str(finding.get("permissions", "")).lower()

    text = f"{finding_type} {details} {path} {permissions}"
    score = 10

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

        if any(name in path for name in common_system_paths):
            score = 25

     # 3. Cron and scheduled tasks
    elif "cron" in finding_type:
        score = 25

        if (
            finding.get("writable_by_current_user") is True
            or "writable" in details
        ):
            score = 65

    # 4. World-writable files and directories
    elif "world-writable" in text or "world writable" in text:
        score = 55
        

    # 5. Other writable files and directories
    elif "writable" in finding_type or "writable" in details:
        score = 35

    # 6. Sudo configuration
    elif "sudo" in finding_type:
        score = 50

        if "nopasswd" in text or "no password" in text:
            score = 60

        if "all" in text and (
            "nopasswd" in text or "no password" in text
        ):
            score = 80

    # 7. Overly permissive permission bits
    if permissions in ("0o777", "0o1777", "777", "1777"):
        score = max(score, 60)

    # 8. Scanner warnings and operational errors
    if any(
        word in finding_type
        for word in ("warning", "error", "timeout")
    ):
        score = 10

    # Keep score between 0 and 100
    score = min(max(score, 0), 100)

    # Assign severity
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
