# Linux Privilege Escalation Automation Toolkit

## Overview

The Linix Privilege Escalation Automation Toolkit is a Python-Based security auditing project designed to identify potentially risky Linux configuration and help prioritize manual security reviews.

## Features

- **SUID/SGID Scanner:** Identifies files with SUID or SGID permission bits.
- **Files Permissions Scanner:** checks for potentially unsafe files permissions.
- **Sudo Permissions Scanner:** Collects information about Sudo Permissions and configuration.
- **Cron configuration Scanner:** Checks scheduled-task configurations for potential security concerns.
- **Linux Capabilities Scanner:** Identifies executables with assigned Linux capabilities using `getcap`.
- **Risk Scoring Engine:** Assigns preliminary risk scores to collected findings.
- **Report Generation:** Generates TXT and JSON audit reports.

## Technology Stack

- Python 3
- Linux / Ubuntu on WSL
- VS Code
- Linux command-line utilities, including `getcap`

## Project Structure

```text
linux-privesc-toolkit/
├── main.py
├── risk_engine.py
├── report.py
├── scanners/
│   ├── suid_sgid.py
│   ├── permissions.py
│   ├── sudo_checks.py
│   ├── cron_checks.py
│   └── capabilities.py
└── reports/
    ├── security_audit.txt
    └── security_audit.json
```

## Setup and Usage

1. Install Python 3 and the required Linux utilities.
2. Open the project directory in Ubuntu or another supported Linux environment.
3. Ensure the `getcap` utility is available. On Ubuntu, it is provided by `libcap2-bin`.
4. Navigate to the project directory:

   ```bash
   cd ~/linux-privesc-toolkit
   ```

5. Run the toolkit:

   ```bash
   python3 main.py
   ```

6. Review the generated reports in the `reports/` directory.

## Risk Scoring

The risk engine assigns a preliminary score and severity label to each finding. Scores are intended to help prioritize manual investigation; they do not prove that a vulnerability is exploitable.

Findings should be reviewed in context, including file ownership, permissions, executable behavior, system configuration, and the intended use of Linux capabilities.

## Sample Result

```text
Type: Linux capability
Risk: Low
Score: 10
Details: /usr/bin/ping cap_net_raw=ep
```

This example illustrates a detected capability assignment. It is not automatically a vulnerability.

## Limitations

- Results depend on the permissions of the account running the toolkit and the system being scanned.
- Filesystem scans may be incomplete or time out.
- Risk scores are heuristic estimates and may produce false positives or false negatives.
- The toolkit does not establish exploitability or replace a professional security assessment.
- Report consistency and scanner coverage should be tested across supported Linux environments.

## Future Improvements

- More comprehensive risk rules and severity validation.
- Improved scan error handling and coverage reporting.
- Unit tests and automated regression tests.
- Remediation recommendations for findings.
- HTML reporting and a more detailed audit summary.

## Disclaimer

This project is intended for authorized security auditing, defensive learning, and testing on systems you own or have explicit permission to assess.

## Author

Ayushman Singh

## Project Status

Core scanners, preliminary risk scoring, and TXT/JSON report generation have been implemented. Further testing, documentation review, and validation are recommended before production use.