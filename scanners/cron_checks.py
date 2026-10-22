
import os


def scan_cron():
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

        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="replace") as file:
                    for line_number, line in enumerate(file, 1):
                        line = line.strip()

                        if line and not line.startswith("#"):
                            findings.append(
                                f"{path}:{line_number}: {line}"
                            )

            elif os.path.isdir(path):
                for name in sorted(os.listdir(path)):
                    item = os.path.join(path, name)

                    if os.path.isfile(item):
                        findings.append(
                            f"Scheduled-task file found: {item}"
                        )

        except OSError:
            continue

    print(f"[+] Found {len(findings)} cron entries or files.")

    for finding in findings[:50]:
        print(f"[REVIEW] {finding}")

    if len(findings) > 50:
        print("[*] Output limited to the first 50 findings.")

    return findings