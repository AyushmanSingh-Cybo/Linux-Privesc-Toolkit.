
from datetime import datetime
from pathlib import Path
import json


def generate_report(findings):
    """Generate TXT and JSON reports with an overall audit status."""

    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    # Normalize findings for consistent reporting.
    normalized_findings = []

    for finding in findings:
        if isinstance(finding, dict):
            normalized_findings.append(finding.copy())
        else:
            normalized_findings.append({
                "type": "Configuration review",
                "details": str(finding),
            })

    # Determine whether all checks completed.
    incomplete_checks = [
        finding
        for finding in normalized_findings
        if finding.get("check_status") == "incomplete"
    ]

    audit_status = "PARTIAL" if incomplete_checks else "COMPLETE"

    # Text report
    text_file = report_dir / "security_audit.txt"

    with text_file.open("w", encoding="utf-8") as file:
        file.write("LINUX SECURITY AUDIT REPORT\n")
        file.write("=" * 50 + "\n")
        file.write(f"Generated: {generated_at}\n")
        file.write(f"Audit status: {audit_status}\n")
        file.write(f"Total findings: {len(normalized_findings)}\n")
        file.write(f"Incomplete checks: {len(incomplete_checks)}\n\n")

        if incomplete_checks:
            file.write("WARNING: Some checks could not be completed.\n")
            file.write("Review the incomplete findings before relying on this audit.\n\n")

        for number, finding in enumerate(normalized_findings, start=1):
            file.write(f"FINDING #{number}\n")
            file.write("-" * 30 + "\n")

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

            for key in preferred_keys:
                if key in finding:
                    label = key.replace("_", " ").title()
                    file.write(f"{label}: {finding[key]}\n")

            # Include extra fields added by scanners.
            for key, value in finding.items():
                if key not in preferred_keys:
                    label = key.replace("_", " ").title()
                    file.write(f"{label}: {value}\n")

            file.write("\n")

    # JSON report
    json_file = report_dir / "security_audit.json"

    report_data = {
        "generated_at": generated_at,
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
