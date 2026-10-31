
import os
import subprocess


def scan_suid_sgid():
    """Inspect SUID/SGID files without modifying the system."""
    findings = []

    print("[*] Searching for SUID/SGID files...")

    try:
        result = subprocess.run(
            [
                "find", "/usr", "/bin", "/sbin", "/opt",
                "-type", "f",
                "(",
                "-perm", "-4000", "-o", "-perm", "-2000",
                ")",
                "-print",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        for path in result.stdout.splitlines():
            try:
                mode = os.stat(path).st_mode

                has_suid = bool(mode & 0o4000)
                has_sgid = bool(mode & 0o2000)

                if not (has_suid or has_sgid):
                    continue

                if has_suid and has_sgid:
                    file_type = "SUID/SGID"
                elif has_suid:
                    file_type = "SUID"
                else:
                    file_type = "SGID"

                findings.append({
                    "type": file_type,
                    "path": path,
                })

            except OSError as error:
                findings.append({
                    "type": "SUID/SGID scan warning",
                    "path": path,
                    "details": f"Could not inspect file: {error}",
                    "check_status": "incomplete",
                })

        if result.returncode != 0:
            findings.append({
                "type": "SUID/SGID scan warning",
                "details": (
                    result.stderr.strip()
                    or f"find exited with code {result.returncode}"
                ),
                "check_status": "incomplete",
            })

        print(f"[+] Collected {len(findings)} entries.")

    except (OSError, subprocess.TimeoutExpired) as error:
        findings.append({
            "type": "SUID/SGID scan warning",
            "details": f"Scanner could not complete: {error}",
            "check_status": "incomplete",
        })
        print(f"[!] Scanner error: {error}")

    return findings
