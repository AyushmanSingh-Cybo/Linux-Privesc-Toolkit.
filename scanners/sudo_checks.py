
import subprocess


def scan_sudo():
    """Inspect sudo permissions without prompting for a password."""

    print("[*] Checking current user's sudo permissions...")

    try:
        result = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode == 0:
            output = result.stdout.strip()
            print("[+] Sudo permissions retrieved.")

            if output:
                print(output)

            return [{
                "type": "Sudo permissions",
                "details": output or "Command succeeded but returned no output",
                "check_status": "completed",
            }]

        error_output = result.stderr.strip()

        if "interactive authentication is required" in error_output.lower():
            details = (
                "Sudo permission check incomplete: "
                "authentication is required."
            )
        else:
            details = (
                "Sudo permission check failed. "
                + (error_output or "No error details were provided.")
            )

        print(f"[!] {details}")

        return [{
            "type": "Warning",
            "details": details,
            "check_status": "incomplete",
        }]

    except subprocess.TimeoutExpired:
        details = "Sudo permission check timed out."
        print(f"[!] {details}")

        return [{
            "type": "Warning",
            "details": details,
            "check_status": "incomplete",
        }]

    except OSError as error:
        details = f"Could not run sudo permission check: {error}"
        print(f"[!] {details}")

        return [{
            "type": "Warning",
            "details": details,
            "check_status": "incomplete",
        }]
