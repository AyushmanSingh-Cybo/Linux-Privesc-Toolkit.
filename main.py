
from scanners.suid_sgid import scan_suid_sgid
from scanners.permissions import scan_permissions
from scanners.sudo_checks import scan_sudo
from scanners.cron_checks import scan_cron
from scanners.capabilities import scan_capabilities

from risk_engine import add_risk_scores
from report import generate_report


def main():
    print("=" * 55)
    print(" Linux Privilege Escalation Automation Toolkit")
    print("=" * 55)

    # 1. SUID/SGID Scanner
    print("\n[1/5] SUID/SGID Scanner")
    suid_findings = scan_suid_sgid()
    print(f"[+] SUID/SGID findings: {len(suid_findings)}")

    # 2. File Permissions Scanner
    print("\n[2/5] File Permissions Scanner")
    permission_findings = scan_permissions()
    print(f"[+] Permission findings: {len(permission_findings)}")

    # 3. Sudo Permissions Scanner
    print("\n[3/5] Sudo Permissions Scanner")
    sudo_result = scan_sudo()

    if isinstance(sudo_result, list):
        sudo_findings = sudo_result
    elif isinstance(sudo_result, str) and sudo_result:
        sudo_findings = [
            {"type": "Sudo check output", "path": sudo_result}
        ]
    else:
        sudo_findings = []

    print(f"[+] Sudo findings: {len(sudo_findings)}")

    # 4. Cron Configuration Scanner
    print("\n[4/5] Cron Configuration Scanner")
    cron_findings = scan_cron()
    print(f"[+] Cron findings: {len(cron_findings)}")

    # 5. Linux Capabilities Scanner
    print("\n[5/5] Linux Capabilities Scanner")
    capability_findings = scan_capabilities()
    print(f"[+] Capabilities findings: {len(capability_findings)}")

    # Combine findings from all scanners
    all_findings = (
        suid_findings
        + permission_findings
        + sudo_findings
        + cron_findings
        + capability_findings
    )

    # Apply risk scores
    all_findings = add_risk_scores(all_findings)

    # Generate TXT and JSON reports
    generate_report(all_findings)

    # Final summary
    print("\n" + "=" * 55)
    print("AUDIT SUMMARY")
    print("=" * 55)
    print(f"SUID/SGID findings: {len(suid_findings)}")
    print(f"Permission findings: {len(permission_findings)}")
    print(f"Sudo findings: {len(sudo_findings)}")
    print(f"Cron findings: {len(cron_findings)}")
    print(f"Capabilities findings: {len(capability_findings)}")
    print(f"Total findings collected: {len(all_findings)}")
    print("Security audit completed.")


if __name__ == "__main__":
    main()
