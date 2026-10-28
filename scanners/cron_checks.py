import os
import stat
import pwd


def inspect_cron_file(path):
    """Collect basic metadata for a cron file."""

    try:
        info = os.stat(path)
        permissions = stat.S_IMODE(info.st_mode)

        try:
            owner = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            owner = str(info.st_uid)

        writable = os.access(path, os.W_OK)

        return {
            "type": "Cron configuration",
            "path": path,
            "details": (
                "Writable scheduled-task file"
                if writable
                else "Scheduled-task file found; review permissions"
            ),
            "permissions": oct(permissions),
            "owner": owner,
            "writable_by_current_user": writable,
        }

    except OSError as error:
        return {
            "type": "Warning",
            "path": path,
            "details": f"Could not inspect file: {error}",
        }


def scan_cron():
    """Inspect common cron directories without modifying system files."""

    print("[*] Checking cron configuration...")

    paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    findings = []

    for path in paths:
        if not os.path.exists(path):
            continue

        if os.path.isfile(path):
            findings.append(inspect_cron_file(path))

        elif os.path.isdir(path):
            try:
                for name in sorted(os.listdir(path)):
                    item = os.path.join(path, name)

                    if os.path.isfile(item):
                        findings.append(inspect_cron_file(item))

            except OSError as error:
                findings.append({
                    "type": "Warning",
                    "path": path,
                    "details": f"Could not list directory: {error}",
                })

    print(f"[+] Inspected {len(findings)} cron files.")

    for finding in findings[:50]:
        print(
            f"[REVIEW] {finding.get('path', 'Unknown')} "
            f"| owner={finding.get('owner', 'unknown')} "
            f"| permissions={finding.get('permissions', 'unknown')} "
            f"| writable={finding.get('writable_by_current_user', 'unknown')}"
        )

    if len(findings) > 50:
        print("[*] Output limited to the first 50 findings.")

    return findings