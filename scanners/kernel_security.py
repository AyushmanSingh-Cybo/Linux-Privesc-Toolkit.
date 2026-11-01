
import platform
from pathlib import Path


def get_os_information():
    """Read operating system identification."""
    information = {}

    try:
        contents = Path("/etc/os-release").read_text(
            encoding="utf-8"
        )

        for line in contents.splitlines():
            if "=" not in line or line.startswith("#"):
                continue

            key, value = line.split("=", 1)
            information[key] = value.strip().strip('"')

    except OSError:
        pass

    return information


def assess_kernel_security():
    """
    Perform a read-only kernel security assessment.

    CVE applicability requires verified vendor advisories.
    This module does not infer vulnerabilities from versions.
    """
    kernel = platform.release()
    os_info = get_os_information()

    is_wsl = (
        "microsoft" in kernel.lower()
        or "wsl" in kernel.lower()
    )

    provider = "Microsoft WSL2" if is_wsl else "Linux distribution"

    recommendation = (
        "Review Microsoft WSL kernel release notes and "
        "security updates. Confirm update status through "
        "the Windows WSL management tools."
        if is_wsl else
        "Review the distribution vendor's kernel security "
        "advisories and installed package update status."
    )

    return {
        "type": "Kernel security advisory review",
        "kernel_version": kernel,
        "operating_system": os_info.get(
            "PRETTY_NAME", platform.system()
        ),
        "kernel_provider": provider,
        "environment": "WSL2" if is_wsl else "Standard/Other Linux",
        "cve_status": "Not assessed",
        "check_status": "incomplete",
        "details": (
            "Kernel identified successfully. CVE applicability, "
            "patch status and end-of-life status have not been "
            "verified against current vendor advisories."
        ),
        "recommendation": recommendation,
    }


if __name__ == "__main__":
    result = assess_kernel_security()

    print("\nKERNEL SECURITY ASSESSMENT")
    print("-" * 55)

    for key, value in result.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
