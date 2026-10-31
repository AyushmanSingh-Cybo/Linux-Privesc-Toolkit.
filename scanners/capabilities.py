
import subprocess


def scan_capabilities():
    """Review Linux file capabilities without modifying files."""
    findings = []
    timeout_seconds = 120

    try:
        result = subprocess.run(
            ["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local/bin"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if result.returncode != 0:
            findings.append({
                "type": "Capabilities scan warning",
                "details": (
                    result.stderr.strip()
                    or f"getcap exited with code {result.returncode}"
                ),
                "check_status": "incomplete",
            })

        for line in result.stdout.splitlines():
            line = line.strip()

            if line:
                findings.append({
                    "type": "Linux capability",
                    "details": line,
                })

        if not findings:
            findings.append({
                "type": "Capabilities scan",
                "details": "No capabilities were reported by getcap.",
            })

    except FileNotFoundError:
        findings.append({
            "type": "Capabilities scan warning",
            "details": "getcap was not found. Install libcap2-bin.",
            "check_status": "incomplete",
        })

    except subprocess.TimeoutExpired:
        findings.append({
            "type": "Capabilities scan warning",
            "details": (
                f"The scan timed out after {timeout_seconds} seconds."
            ),
            "check_status": "incomplete",
        })

    except OSError as exc:
        findings.append({
            "type": "Capabilities scan warning",
            "details": str(exc),
            "check_status": "incomplete",
        })

    return findings
