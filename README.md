
# Linux Privilege Escalation Automation Toolkit

**A Python-based defensive Linux security auditing toolkit**

**Version:** 1.0
**Author:** Ayushman Singh
**Language:** Python 3
**Platform:** Linux / Ubuntu / WSL

---

## Project Overview

The Linux Privilege Escalation Automation Toolkit is a Python-based defensive security auditing project developed to identify potentially risky Linux configurations and prioritize findings for manual security review.

The toolkit performs five configuration checks, assigns heuristic risk scores, tracks incomplete scans, and generates human-readable TXT and structured JSON reports.

It is designed for educational purposes, authorized security assessments, and defensive security learning.

**Important:** The toolkit does not perform privilege escalation or exploit detected configurations.

## Key Features

| Component | Description |
|---|---|
| SUID/SGID Scanner | Identifies files with SUID and SGID permission bits |
| File Permissions Scanner | Checks selected directories for world-writable items |
| Sudo Permissions Scanner | Reviews accessible sudo information and reports authentication limitations |
| Cron Configuration Scanner | Inspects scheduled-task configuration files and their permissions |
| Linux Capabilities Scanner | Identifies assigned file capabilities using `getcap` |
| Risk Scoring Engine | Assigns heuristic risk scores and severity labels |
| Audit Status Tracking | Identifies incomplete checks and reports partial audits |
| Report Generator | Produces detailed TXT and structured JSON reports |
| Automated Testing | Includes 20 unit tests across the toolkit |

## Technology Stack

- Python 3
- Linux / Ubuntu / Windows Subsystem for Linux (WSL)
- Linux command-line utilities
- Python standard library
- Python `unittest`
- Git and GitHub

## Project Structure

```text
linux-privesc-toolkit/
├── main.py
├── generate_sample.py
├── risk_engine.py
├── report.py
├── scanners/
│   ├── __init__.py
│   ├── suid_sgid.py
│   ├── permissions.py
│   ├── sudo_checks.py
│   ├── cron_checks.py
│   └── capabilities.py
├── tests/
│   ├── __init__.py
│   ├── test_report.py
│   ├── test_risk_engine.py
│   ├── test_sudo_checks.py
│   ├── test_capabilities.py
│   ├── test_cron_checks.py
│   ├── test_permissions.py
│   └── test_suid_sgid.py
├── examples/
│   ├── sample_security_audit.json
│   └── sample_security_audit.txt
└── reports/
```

## Installation

### Prerequisites

- Python 3 with virtual environment support
- Linux or Ubuntu on WSL
- Git
- `find` utility
- `getcap` utility, provided by `libcap2-bin` on Ubuntu

On Ubuntu, install the required system packages if they are missing:

```bash
sudo apt update
sudo apt install python3 python3-venv git findutils libcap2-bin
```

### Clone the Repository

```bash
git clone https://github.com/AyushmanSingh-Cybo/Linux-Privesc-Toolkit.git
cd Linux-Privesc-Toolkit
```

### Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

The toolkit uses Python standard-library modules for its core functionality.

## Running the Toolkit

Execute:

```bash
python3 main.py
```

The toolkit will:

1. Scan for SUID/SGID files.
2. Check selected directories for world-writable permissions.
3. Review accessible sudo permission information.
4. Inspect cron configuration files.
5. Scan executable file capabilities.
6. Calculate preliminary risk scores.
7. Generate TXT and JSON reports.

The terminal displays progress, a severity breakdown, incomplete-check information, and the overall audit status.
## Project Screenshots

### Toolkit Overview

![Linux Security Audit Toolkit](screenshots/toolkit-overview.png.png)

### Security Audit Summary

![Security Audit Summary](screenshots/security-audit.png)
## Example Audit Summary

The following is an example from a development-environment audit. Results vary across systems.

```text
==============================================================
                 SECURITY AUDIT SUMMARY
==============================================================
  Total findings : 35
  Low            : 22
  Medium         : 13
  High           : 0
  Critical       : 0
  Incomplete     : 1
  Audit status   : PARTIAL
--------------------------------------------------------------
  Reports generated:
    reports/security_audit.txt
    reports/security_audit.json
==============================================================
```

The audit was marked `PARTIAL` because the sudo permission check required authentication.

**Findings represent items for review, not confirmed vulnerabilities.**

## Risk Scoring

The risk engine assigns preliminary numerical scores and severity labels to findings.

| Severity | Score Range |
|---|---|
| Low | 0–29 |
| Medium | 30–59 |
| High | 60–79 |
| Critical | 80–100 |

These scores are heuristic review priorities rather than verified measurements of exploitability.

A finding's actual significance depends on its context, including file ownership, permissions, executable behavior, system configuration, and assigned capabilities.

Manual validation is required before drawing security conclusions.

## Audit Completeness

The toolkit tracks incomplete checks and identifies when an audit cannot be fully completed.

Examples include:

- Sudo authentication requirements
- Missing system utilities
- Scanner command failures
- Scanner timeouts
- File inspection errors

An incomplete scan does not imply that a system is secure or insecure.

Review audit warnings and incomplete-check details before interpreting the results.

## Generated Reports

The toolkit generates two reports:

**TXT Report**

```text
reports/security_audit.txt
```

Includes a human-readable summary, severity information, individual findings, recommendations, and limitations.

**JSON Report**

```text
reports/security_audit.json
```

Contains structured audit information, including findings, risk scores, audit status, and incomplete-check counts.

## Sample Reports

Generate illustrative sample reports using:

```bash
python3 generate_sample.py
```

Sample files are stored in the `examples/` directory:

```text
examples/sample_security_audit.txt
examples/sample_security_audit.json
```

These samples demonstrate the reporting format and do not represent an actual security assessment.

## Automated Testing

The toolkit includes unit tests covering:

- Risk scoring
- Report generation
- Sudo permission checks
- SUID/SGID detection
- File permission scanning
- Cron configuration scanning
- Linux capability scanning
- Scanner failure handling

Run the full test suite:

```bash
python3 -m unittest discover -s tests -v
```

**Latest verified result: 20 tests passed.**

Tests use controlled inputs and mocking where appropriate, allowing scanner behavior to be validated without modifying system security settings.

## Security and Ethical Use

This toolkit is intended for:

- Defensive security auditing
- Authorized Linux configuration reviews
- Cybersecurity education
- Academic and internship demonstrations

Only run it on systems you own or are explicitly authorized to assess.

The toolkit does not perform exploitation, privilege escalation, or automatic remediation.

## Known Limitations

- Scanning is limited to selected directories and configuration locations.
- Results depend on the current user's permissions.
- Some checks require authentication or additional system utilities.
- Heuristic scores may produce false positives or false negatives.
- Scanner findings do not automatically establish exploitability.
- The toolkit has not been validated across all Linux distributions.
- It is not a replacement for a comprehensive professional security assessment.

## Future Improvements

- Broader Linux distribution compatibility
- Additional scanner regression tests
- More detailed remediation guidance
- HTML reporting and dashboard visualization
- Improved handling of inaccessible directories
- Further validation of heuristic scoring rules

## Author

**Ayushman Singh**

Cybersecurity Student

GitHub: [AyushmanSingh-Cybo](https://github.com/AyushmanSingh-Cybo)

## Disclaimer

This project is provided for educational and authorized defensive security auditing purposes. All findings require contextual interpretation and appropriate manual validation.
