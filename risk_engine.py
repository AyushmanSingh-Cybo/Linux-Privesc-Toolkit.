
def assess_risk(finding):
    """Assign a preliminary security review priority, not exploitability."""

    if not isinstance(finding, dict):
        finding = {
            "type": "Configuration review",
            "details": str(finding)
        }

    finding_type = str(finding.get("type", "")).lower()
    details = str(finding.get("details", "")).lower()
    path = str(finding.get("path", "")).lower()
    permissions = str(finding.get("permissions", "")).lower()

    text = f"{finding_type} {details} {path} {permissions}"
    score = 10

    # Linux capabilities
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

    # SUID/SGID: flag for review, but do not automatically call it High
    elif "suid" in finding_type or "sgid" in finding_type:
        score = 35

        # Common system executables still need verification, but their
        # presence alone does not prove a security issue.
        if any(name in path for name in (
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        )):
            score = 25

    # Writable files and directories
    elif "world-writable" in text or "world writable" in text:
        score = 55
    elif "writable" in finding_type or "writable" in details:
        score = 35

    # Sudo configuration
    elif "sudo" in finding_type:
        score = 50
        if "nopasswd" in text or "no password" in text:
            score = 60
        if "all" in text and ("nopasswd" in text or "no password" in text):
            score = 80

    # Scheduled tasks
    elif "cron" in finding_type:
        score = 25
        if "writable" in text:
            score = 65

    # Exact overly permissive permission bits
    if permissions in ("0o777", "0o1777", "777", "1777"):
        score = max(score, 60)

    # Operational issues are not automatically vulnerabilities
    if any(word in finding_type for word in ("warning", "error", "timeout")):
        score = 10

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
        "risk_score": score
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
                "details": str(finding)
            }

        item.update(assess_risk(item))
        scored_findings.append(item)

    return scored_findings
