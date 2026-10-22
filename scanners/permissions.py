
import os
import stat


def scan_permissions():
    findings = []
    print("[*] Checking selected directories for world-writable items...")

    for root in ("/etc", "/usr/local", "/opt"):
        if not os.path.isdir(root):
            continue

        for current, dirs, files in os.walk(root):
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(current, d))
            ]

            for name in dirs + files:
                path = os.path.join(current, name)

                try:
                    if os.path.islink(path):
                        continue

                    mode = os.stat(path).st_mode

                    if mode & stat.S_IWOTH:
                        findings.append({
                            "path": path,
                            "type": (
                                "directory"
                                if stat.S_ISDIR(mode)
                                else "file"
                            ),
                            "permissions": oct(
                                stat.S_IMODE(mode)
                            )
                        })

                except OSError:
                    continue

    print(f"[+] Found {len(findings)} world-writable items.")

    for item in findings[:50]:
        print(
            f"[REVIEW] {item['type']} | "
            f"{item['permissions']} | {item['path']}"
        )

    if len(findings) > 50:
        print("[*] Showing first 50 findings only.")

    return findings