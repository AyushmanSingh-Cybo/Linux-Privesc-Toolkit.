
from collections import Counter
from datetime import datetime
from pathlib import Path
import json


def get_recommendation(finding):
    """Provide safe, general security review guidance."""
    finding_type = str(finding.get("type", "")).lower()

    if finding.get("check_status") == "incomplete":
        return (
            "This check could not be completed. Review the "
            "reported limitation and rerun it with appropriate "
            "authorization."
        )

    if "suid" in finding_type or "sgid" in finding_type:
        return (
            "Verify that the file's ownership and special "
            "permissions are required. Compare them against "
            "the trusted package or system baseline."
        )

    if "sudo" in finding_type:
        return (
            "Review sudo permissions and apply the principle "
            "of least privilege. Confirm that each permitted "
            "administrative action is necessary."
        )

    if "cron" in finding_type:
        return (
            "Review the scheduled task's ownership, permissions "
            "and command. Ensure that unauthorized users cannot "
            "modify privileged scheduled tasks."
        )

    if "capab" in finding_type:
        return (
            "Verify that the assigned Linux capabilities are "
            "necessary for the application and remove unnecessary "
            "privileges through approved configuration changes."
        )

    if "permission" in finding_type or "writable" in finding_type:
        return (
            "Review file ownership and write permissions. "
            "Restrict unnecessary access according to the "
            "system's operational requirements."
        )

    return (
        "Review this configuration against the organization's "
        "approved security baseline."
    )


def generate_report(findings, output_dir="reports", system_info=None):
    """Generate TXT and JSON security audit reports."""

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    normalized_findings = []

    for finding in findings:
        if isinstance(finding, dict):
            normalized_findings.append(finding.copy())
        else:
            normalized_findings.append({
                "type": "Configuration review",
                "details": str(finding),
            })

    incomplete_checks = [
        finding
        for finding in normalized_findings
        if finding.get("check_status") == "incomplete"
    ]

    audit_status = "PARTIAL" if incomplete_checks else "COMPLETE"

    severity_counts = Counter(
        finding.get("risk_level", "Unknown")
        for finding in normalized_findings
    )

    preferred_keys = [
        "type",
        "path",
        "details",
        "owner",
        "permissions",
        "writable_by_current_user",
        "check_status",
        "risk_level",
        "risk_score",
    ]

    system_info = dict(system_info) if system_info else {}

    text_file = report_dir / "security_audit.txt"

    with text_file.open("w", encoding="utf-8") as file:
        file.write("=" * 62 + "\n")
        file.write("                 LINUX SECURITY AUDIT REPORT\n")
        file.write("=" * 62 + "\n")
        file.write("Automated Linux Configuration Security Review\n")
        file.write("Version: 1.0\n")
        file.write("Author: Ayushman Singh\n")
        file.write(f"Generated: {generated_at}\n\n")

        file.write("1. EXECUTIVE SUMMARY\n")
        file.write("-" * 62 + "\n")
        file.write(f"Audit status       : {audit_status}\n")
        file.write(f"Total findings     : {len(normalized_findings)}\n")
        file.write(f"Incomplete checks  : {len(incomplete_checks)}\n\n")

        file.write("2. SYSTEM INFORMATION\n")
        file.write("-" * 62 + "\n")

        if system_info:
            labels = {
                "username": "Username",
                "uid": "User ID",
                "gid": "Group ID",
                "groups": "Groups",
                "operating_system": "Operating System",
                "kernel_version": "Kernel Version",
                "architecture": "Architecture",
                "is_root": "Running as Root",
            }

            for key, label in labels.items():
                if key in system_info:
                    value = system_info[key]

                    if isinstance(value, list):
                        value = ", ".join(map(str, value))

                    if isinstance(value, bool):
                        value = "Yes" if value else "No"

                    file.write(f"{label:<20}: {value}\n")
        else:
            file.write("System information not provided.\n")

        file.write("\n")

        file.write("3. SEVERITY BREAKDOWN\n")
        file.write("-" * 62 + "\n")

        for level in ["Low", "Medium", "High", "Critical"]:
            file.write(f"{level:<12}: {severity_counts[level]}\n")

        if severity_counts["Unknown"]:
            file.write(
                f"Unknown     : {severity_counts['Unknown']}\n"
            )

        file.write("\n")

        if incomplete_checks:
            file.write("4. AUDIT COMPLETENESS WARNING\n")
            file.write("-" * 62 + "\n")
            file.write(
                "Some checks could not be completed. "
                "The results represent a partial audit.\n"
                "Review incomplete checks before relying "
                "on the report.\n\n"
            )

        file.write("5. DETAILED SECURITY FINDINGS\n")
        file.write("-" * 62 + "\n\n")

        if not normalized_findings:
            file.write("No findings were collected.\n\n")

        for number, finding in enumerate(normalized_findings, start=1):
            file.write(f"FINDING #{number}\n")
            file.write("-" * 40 + "\n")

            for key in preferred_keys:
                if key in finding:
                    label = key.replace("_", " ").title()
                    file.write(f"{label}: {finding[key]}\n")

            for key, value in finding.items():
                if key not in preferred_keys:
                    label = key.replace("_", " ").title()
                    file.write(f"{label}: {value}\n")

            file.write(
                "Recommendation: "
                + get_recommendation(finding)
                + "\n\n"
            )

        file.write("6. LIMITATIONS AND DISCLAIMER\n")
        file.write("-" * 62 + "\n")
        file.write(
            "Risk scores indicate preliminary review priorities, "
            "not confirmed vulnerabilities.\n"
            "The toolkit does not establish exploitability, "
            "and the scan does not guarantee system security.\n"
            "Only authorized systems should be assessed.\n"
            "Manual validation is recommended before making "
            "configuration changes.\n"
        )

    json_file = report_dir / "security_audit.json"

    report_data = {
        "generated_at": generated_at,
        "system_information": system_info,
        "audit_status": audit_status,
        "total_findings": len(normalized_findings),
        "incomplete_checks": len(incomplete_checks),
        "findings": normalized_findings,
    }

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False,
            default=str,
        )
        file.write("\n")

    print(f"[+] Audit status: {audit_status}")
    print(f"[+] Total findings: {len(normalized_findings)}")
    print(f"[+] Incomplete checks: {len(incomplete_checks)}")
    print(f"[+] Text report saved to: {text_file}")
    print(f"[+] JSON report saved to: {json_file}")
