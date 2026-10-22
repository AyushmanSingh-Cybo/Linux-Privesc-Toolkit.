
import subprocess


def scan_capabilities():
    findings = []

    try:
        result = subprocess.run(
            ["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local/bin"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        if result.returncode not in (0, 1):
            findings.append({
                "type": "Capabilities scan warning",
                "details": result.stderr.strip()
                or f"getcap exited with code {result.returncode}"
            })

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            findings.append({
                "type": "Linux capability",
                "details": line
            })

        if not findings:
            findings.append({
                "type": "Capabilities scan",
                "details": "No capabilities were reported by getcap."
            })

    except FileNotFoundError:
        findings.append({
            "type": "Capabilities scan warning",
            "details": "getcap was not found. Install the libcap2-bin package."
        })

    except subprocess.TimeoutExpired:
        findings.append({
            "type": "Capabilities scan warning",
            "details": "The scan timed out after 60 seconds."
        })

    except OSError as exc:
        findings.append({
            "type": "Capabilities scan warning",
            "details": str(exc)
        })

    return findings
