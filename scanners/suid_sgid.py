
import os
import subprocess


def scan_suid_sgid():
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
                "-print"
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        for path in result.stdout.splitlines():
            try:
                mode = os.stat(path).st_mode

                if mode & 0o4000:
                    file_type = "SUID"
                elif mode & 0o2000:
                    file_type = "SGID"
                else:
                    continue

                findings.append({
                    "type": file_type,
                    "path": path
                })

            except OSError:
                continue

        print(f"[+] Scan complete. Found {len(findings)} files.")

    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"[!] Scanner error: {error}")

    return findings