
from datetime import datetime
from pathlib import Path
import json


def generate_report(findings):
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    generated_at = datetime.now().isoformat(timespec="seconds")

    # Text report
    text_file = report_dir / "security_audit.txt"

    with text_file.open("w", encoding="utf-8") as file:
        file.write("LINUX SECURITY AUDIT REPORT\n")
        file.write("=" * 40 + "\n")
        file.write(f"Generated: {generated_at}\n")
        file.write(f"Total findings: {len(findings)}\n\n")

        for finding in findings:
            if isinstance(finding, dict):
                file.write(f"Type: {finding.get('type', 'Review')}\n")
                file.write(f"Path: {finding.get('path', 'N/A')}\n")
                file.write(f"Risk: {finding.get('risk_level', 'Unrated')}\n")
                file.write(f"Score: {finding.get('risk_score', 'N/A')}\n")

                for key, value in finding.items():
                    if key not in (
                        "type", "path", "risk_level", "risk_score"
                    ):
                        file.write(f"{key.title()}: {value}\n")
            else:
                file.write(f"Finding: {finding}\n")

            file.write("-" * 30 + "\n")

    # JSON report
    json_file = report_dir / "security_audit.json"
    report_data = {
        "generated_at": generated_at,
        "total_findings": len(findings),
        "findings": findings
    }

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    print(f"[+] Text report saved to: {text_file}")
    print(f"[+] JSON report saved to: {json_file}")