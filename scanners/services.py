
import os
import shlex
import stat
from pathlib import Path


SERVICE_DIRECTORIES = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
]


def _service_files():
    """Discover regular systemd service files safely."""

    seen = set()

    for directory in SERVICE_DIRECTORIES:
        if not directory.is_dir():
            continue

        for root, dirs, files in os.walk(
            directory,
            followlinks=False
        ):
            dirs[:] = [
                name
                for name in dirs
                if not (Path(root) / name).is_symlink()
            ]

            for filename in files:
                if not filename.endswith(".service"):
                    continue

                path = Path(root) / filename

                # Skip symlinks, including services masked
                # by linking their unit files to /dev/null.
                if path.is_symlink():
                    continue

                try:
                    resolved = path.resolve(strict=True)

                    if not resolved.is_file():
                        continue

                except (OSError, RuntimeError):
                    continue

                if resolved in seen:
                    continue

                seen.add(resolved)
                yield path


def _writable_by_non_root(path):
    """
    Check group/other write permission bits.

    This is a review heuristic, not proof that
    an unprivileged user can modify the file.
    """

    metadata = path.stat()

    return bool(
        metadata.st_mode &
        (stat.S_IWGRP | stat.S_IWOTH)
    )


def scan_services():
    """
    Perform read-only security reviews of systemd
    service unit files.
    """

    findings = []
    inspected = 0

    for service_path in _service_files():

        inspected += 1

        try:
            metadata = service_path.stat()

            # CHECK 1: Service file permissions
            if _writable_by_non_root(service_path):

                findings.append({
                    "type": "Systemd service permission review",
                    "path": str(service_path),
                    "details": (
                        "Service unit has group or other "
                        "write permissions. Verify ownership "
                        "and effective access."
                    ),
                    "permissions": oct(
                        stat.S_IMODE(metadata.st_mode)
                    ),
                })

            contents = service_path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            service_user = "root"
            in_service_section = False

            executable_lines = []
            environment_lines = []

            # CHECK 2: Parse service configuration
            for raw_line in contents.splitlines():

                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith(("#", ";")):
                    continue

                if line.startswith("[") and line.endswith("]"):
                    in_service_section = (
                        line.lower() == "[service]"
                    )
                    continue

                if not in_service_section:
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)

                key = key.strip().lower()
                value = value.strip()

                if key == "user":
                    service_user = value or "root"

                elif key in (
                    "execstart",
                    "execstartpre",
                    "execstartpost",
                    "execreload",
                    "execstop",
                ):
                    executable_lines.append(value)

                elif key == "environment":
                    environment_lines.append(value)

            # Skip executable and PATH checks for services
            # explicitly configured to run as non-root.
            if service_user not in ("root", ""):
                continue

            # CHECK 3: Executable permissions
            for command in executable_lines:

                try:
                    tokens = shlex.split(command)

                except ValueError:
                    continue

                if not tokens:
                    continue

                executable = tokens[0].lstrip("-+!:@")

                if not executable.startswith("/"):
                    continue

                executable_path = Path(executable)

                try:
                    if (
                        executable_path.is_file()
                        and _writable_by_non_root(
                            executable_path
                        )
                    ):

                        findings.append({
                            "type": (
                                "Systemd executable "
                                "permission review"
                            ),
                            "path": str(executable_path),
                            "details": (
                                "A service configured to run "
                                "as root references an executable "
                                "with group or other write bits. "
                                f"Service: {service_path}"
                            ),
                        })

                except OSError as error:

                    findings.append({
                        "type": "Systemd service scan warning",
                        "path": str(service_path),
                        "details": str(error),
                        "check_status": "incomplete",
                    })

            # CHECK 4: PATH configuration review
            for environment in environment_lines:

                if "PATH=" in environment.upper():

                    findings.append({
                        "type": (
                            "Systemd PATH configuration review"
                        ),
                        "path": str(service_path),
                        "details": (
                            "Root service defines a PATH "
                            "environment variable. Verify "
                            "that referenced directories "
                            "are trusted and protected."
                        ),
                    })

        except (OSError, UnicodeError) as error:

            findings.append({
                "type": "Systemd service scan warning",
                "path": str(service_path),
                "details": (
                    f"Unable to inspect service: {error}"
                ),
                "check_status": "incomplete",
            })

    print(
        f"[+] Systemd service files inspected: {inspected}"
    )

    print(
        f"[+] Service review findings: {len(findings)}"
    )

    return findings


if __name__ == "__main__":

    results = scan_services()

    for finding in results[:10]:
        print(finding)
