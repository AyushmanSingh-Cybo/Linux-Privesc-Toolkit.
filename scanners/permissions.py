
import os
import stat


SCAN_DIRECTORIES = (
    "/etc",
    "/usr/local",
    "/opt",
)

SENSITIVE_FILES = (
    "/etc/passwd",
    "/etc/shadow",
)

PRIVILEGED_DIRECTORIES = (
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/systemd/system",
)


def permission_string(mode):
    """Return Unix permission bits in octal format."""
    return oct(stat.S_IMODE(mode))



def add_permission_finding(findings, path, metadata, description):
    """Record a permission finding using compatible type values."""

    item_type = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
    )

    findings.append({
        "type": item_type,
        "path": path,
        "permissions": permission_string(metadata.st_mode),
        "owner": metadata.st_uid,
        "details": description,
    })


def scan_permissions():
    """Perform read-only reviews of selected Linux permissions."""

    findings = []
    print("[*] Reviewing Linux file and directory permissions...")

    # 1. Review world-writable system items.
    for root in SCAN_DIRECTORIES:
        if not os.path.isdir(root):
            continue

        def on_walk_error(error):
            findings.append({
                "type": "File permission scan warning",
                "path": getattr(error, "filename", root),
                "details": str(error),
                "check_status": "incomplete",
            })

        for current, dirs, files in os.walk(
            root,
            followlinks=False,
            onerror=on_walk_error,
        ):
            dirs[:] = [
                name for name in dirs
                if not os.path.islink(
                    os.path.join(current, name)
                )
            ]

            for name in dirs + files:
                path = os.path.join(current, name)

                try:
                    if os.path.islink(path):
                        continue

                    metadata = os.stat(path)

                    if metadata.st_mode & stat.S_IWOTH:
                        add_permission_finding(
                            findings,
                            path,
                            metadata,
                            "World-writable system item. "
                            "Verify that this access is necessary.",
                        )

                except OSError as error:
                    findings.append({
                        "type": "File permission scan warning",
                        "path": path,
                        "details": str(error),
                        "check_status": "incomplete",
                    })

    # 2. Review sensitive system files.
    for path in SENSITIVE_FILES:
        try:
            metadata = os.stat(path)

            if not stat.S_ISREG(metadata.st_mode):
                continue

            if metadata.st_mode & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                add_permission_finding(
                    findings,
                    path,
                    metadata,
                    "Sensitive system file has group or "
                    "other write permissions.",
                )

            if path == "/etc/shadow":
                if metadata.st_mode & stat.S_IROTH:
                    add_permission_finding(
                        findings,
                        path,
                        metadata,
                        "Password shadow file is readable "
                        "by other users.",
                    )

            if metadata.st_uid != 0:
                add_permission_finding(
                    findings,
                    path,
                    metadata,
                    "Sensitive system file is not owned "
                    "by root. Verify against the system baseline.",
                )

        except OSError as error:
            findings.append({
                "type": "File permission scan warning",
                "path": path,
                "details": str(error),
                "check_status": "incomplete",
            })

    # 3. Review home directory permissions.
    try:
        if os.path.isdir("/home"):
            with os.scandir("/home") as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue

                    if not entry.is_dir(follow_symlinks=False):
                        continue

                    metadata = entry.stat(follow_symlinks=False)

                    if metadata.st_mode & (
                        stat.S_IWGRP | stat.S_IWOTH
                    ):
                        add_permission_finding(
                            findings,
                            entry.path,
                            metadata,
                            "Home directory has group or other "
                            "write permissions. Review whether "
                            "the access is appropriate.",
                        )

    except OSError as error:
        findings.append({
            "type": "File permission scan warning",
            "path": "/home",
            "details": str(error),
            "check_status": "incomplete",
        })

    # 4. Review privileged configuration directories.
    for directory in PRIVILEGED_DIRECTORIES:
        if not os.path.isdir(directory):
            continue

        try:
            metadata = os.stat(directory)

            if metadata.st_mode & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                add_permission_finding(
                    findings,
                    directory,
                    metadata,
                    "Privileged configuration directory has "
                    "group or other write permissions. "
                    "Verify effective access and ownership.",
                )

        except OSError as error:
            findings.append({
                "type": "File permission scan warning",
                "path": directory,
                "details": str(error),
                "check_status": "incomplete",
            })

    print(f"[+] Permission review findings: {len(findings)}")

    for finding in findings[:50]:
        print(
            f"[REVIEW] {finding['type']} | "
            f"{finding.get('permissions', 'N/A')} | "
            f"{finding.get('path', 'Unknown')}"
        )

    if len(findings) > 50:
        print("[*] Showing first 50 findings only.")

    return findings


if __name__ == "__main__":
    scan_permissions()
