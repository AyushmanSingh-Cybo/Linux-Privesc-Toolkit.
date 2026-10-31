
from collections import Counter
from datetime import datetime

from scanners.suid_sgid import scan_suid_sgid
from scanners.permissions import scan_permissions
from scanners.sudo_checks import scan_sudo
from scanners.cron_checks import scan_cron
from scanners.capabilities import scan_capabilities

from risk_engine import add_risk_scores
from report import generate_report


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_header():
    print("\n" + "=" * 62)
    print(f"{Colors.CYAN}{Colors.BOLD}"
          "          LINUX SECURITY AUDIT TOOLKIT"
          f"{Colors.RESET}")
    print("=" * 62)
    print("  Automated Linux Configuration Security Review")
    print("  Version: 1.0 | Author: Ayushman Singh")
    print("  Started:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 62)


def print_section(number, name):
    print(f"\n{Colors.CYAN}[{number}/5] {name}{Colors.RESET}")
    print("-" * 62)


def main():
    print_header()

    print_section(1, "SUID/SGID Scanner")
    suid_findings = scan_suid_sgid()
    print(f"[+] Findings collected: {len(suid_findings)}")

    print_section(2, "File Permissions Scanner")
    permission_findings = scan_permissions()
    print(f"[+] Findings collected: {len(permission_findings)}")

    print_section(3, "Sudo Permissions Scanner")
    sudo_result = scan_sudo()

    if isinstance(sudo_result, list):
        sudo_findings = sudo_result
    elif isinstance(sudo_result, str) and sudo_result:
        sudo_findings = [
            {"type": "Sudo check output", "path": sudo_result}
        ]
    else:
        sudo_findings = []

    print(f"[+] Findings collected: {len(sudo_findings)}")

    print_section(4, "Cron Configuration Scanner")
    cron_findings = scan_cron()
    print(f"[+] Findings collected: {len(cron_findings)}")

    print_section(5, "Linux Capabilities Scanner")
    capability_findings = scan_capabilities()
    print(f"[+] Findings collected: {len(capability_findings)}")

    all_findings = (
        suid_findings
        + permission_findings
        + sudo_findings
        + cron_findings
        + capability_findings
    )

    all_findings = add_risk_scores(all_findings)

    generate_report(all_findings)

    severity_counts = Counter(
        finding.get("risk_level", "Unknown")
        for finding in all_findings
    )


    incomplete_checks = sum(
        1 for finding in all_findings
        if finding.get("check_status") == "incomplete"
    )

    audit_status = "PARTIAL" if incomplete_checks else "COMPLETE"


    audit_status = "PARTIAL" if incomplete_checks else "COMPLETE"

    print("\n" + "=" * 62)
    print(f"{Colors.BOLD}                 SECURITY AUDIT SUMMARY{Colors.RESET}")
    print("=" * 62)

    print(f"  Total findings : {len(all_findings)}")
    print(f"  Low            : {Colors.GREEN}{severity_counts['Low']}{Colors.RESET}")
    print(f"  Medium         : {Colors.YELLOW}{severity_counts['Medium']}{Colors.RESET}")
    print(f"  High           : {Colors.RED}{severity_counts['High']}{Colors.RESET}")
    print(f"  Critical       : {Colors.RED}{severity_counts['Critical']}{Colors.RESET}")
    print(f"  Incomplete     : {incomplete_checks}")
    print(f"  Audit status   : {audit_status}")

    print("-" * 62)
    print("  Reports generated:")
    print("    reports/security_audit.txt")
    print("    reports/security_audit.json")
    print("=" * 62)

    print(f"\n{Colors.GREEN}[+] Security audit finished.{Colors.RESET}")
    print("Note: Findings are review priorities, not confirmed vulnerabilities.\n")


if __name__ == "__main__":
    main()
