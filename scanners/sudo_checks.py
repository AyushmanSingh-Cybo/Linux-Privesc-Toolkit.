
import subprocess


def scan_sudo():
    print("[*] Checking current user's sudo permissions...")

    try:
        result = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print("[+] Sudo permissions:")
            print(result.stdout.strip())

        elif result.returncode == 1:
            print("[!] Sudo permissions could not be listed non-interactively.")
            print("[*] The user may need to authenticate or may lack permission.")
            if result.stderr.strip():
                print(result.stderr.strip())

        else:
            print("[!] Sudo permission check returned an error.")
            if result.stderr.strip():
                print(result.stderr.strip())

        return result.stdout.strip()

    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"[!] Scanner error: {error}")
        return ""