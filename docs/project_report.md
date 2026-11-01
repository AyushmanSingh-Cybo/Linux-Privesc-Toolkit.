
# Linux Privilege Escalation Automation Toolkit
## Technical Internship Project Report

**Prepared by:** Ayushman Singh
**Project Version:** 1.0
**Technology:** Python 3, Linux, Ubuntu, WSL2
**Report Date:** November 2026

---

## 1. Abstract

The Linux Privilege Escalation Automation Toolkit is a Python-based defensive security auditing application developed to identify Linux configurations that may require further security review.

The toolkit performs seven security configuration checks, collects system information, assigns heuristic risk scores, and generates TXT and JSON reports.

The project emphasizes automated configuration assessment, transparent reporting, and responsible cybersecurity practices. It does not perform exploitation or privilege escalation.

## 2. Introduction

Linux operating systems use permissions, ownership, scheduled tasks, services, and privilege-management mechanisms to control access to system resources.

Security misconfigurations in these areas may introduce risks that require investigation.

Manually reviewing these configurations can be time-consuming. This project brings several defensive checks together into one command-line application.

## 3. Project Objectives

The main objectives are:

1. Automate selected Linux configuration security checks.
2. Identify SUID/SGID files and assigned Linux capabilities.
3. Review file permissions, sudo permissions, cron configurations, and systemd services.
4. Collect kernel and operating system information.
5. Assign preliminary risk scores to findings.
6. Track incomplete assessments.
7. Generate readable and structured security reports.
8. Validate application behavior using automated tests.

## 4. Technologies Used

- Python 3
- Ubuntu Linux
- Windows Subsystem for Linux (WSL2)
- Linux command-line utilities
- Python `unittest`
- Git and GitHub

## 5. System Architecture

The application contains the following components:

- Main controller: `main.py`
- Security scanner modules: `scanners/`
- Risk scoring engine: `risk_engine.py`
- Report generator: `report.py`
- Automated tests: `tests/`

The architecture diagram is available in `docs/architecture.md`.

The execution flowchart is available in `docs/flowchart.md`.

## 6. Implementation

### 6.1 SUID/SGID Scanner

Identifies files with SUID or SGID permission bits for further review.

### 6.2 File Permissions Scanner

Reviews selected Linux files and directories for permission concerns and reports inspection limitations.

### 6.3 Sudo Permissions Scanner

Reviews accessible sudo configuration information and reports when authentication prevents a complete assessment.

### 6.4 Cron Configuration Scanner

Inspects selected scheduled-task configuration files, ownership, and permissions.

### 6.5 Linux Capabilities Scanner

Identifies assigned Linux file capabilities using available system utilities.

### 6.6 Systemd Service Scanner

Reviews selected systemd service configuration files for security concerns.

### 6.7 Kernel Security Assessment

Collects kernel information and identifies the limitation that automated CVE matching is not currently implemented.

### 6.8 Risk Scoring Engine

Assigns heuristic scores and severity labels to collected findings.

| Severity | Score Range |
|---|---|
| Low | 0–29 |
| Medium | 30–59 |
| High | 60–79 |
| Critical | 80–100 |

Scores represent preliminary review priorities rather than confirmed vulnerabilities.

### 6.9 Report Generation

The application generates:

- `reports/security_audit.txt`
- `reports/security_audit.json`

Reports contain findings, severity information, and audit completeness information.

## 7. Testing

Automated tests were developed using Python's `unittest` framework.

The tests cover scanner behavior, risk scoring, report generation, system information collection, and selected error-handling scenarios.

**Latest verified result: 38 tests passed.**

Testing does not guarantee the absence of defects or vulnerabilities.

## 8. Results and Observations

The toolkit was executed on Ubuntu 26.04.1 LTS under WSL2.

**Kernel:** `6.18.54.1-microsoft-standard-WSL2`

### Latest Audit Summary

| Metric | Result |
|---|---:|
| Total findings | 40 |
| Low | 26 |
| Medium | 14 |
| High | 0 |
| Critical | 0 |
| Incomplete checks | 6 |
| Audit status | PARTIAL |

The audit collected findings from seven scanner modules.

The systemd scanner inspected 181 service files and reported no service review findings in this run.

The audit remained partial because selected protected locations could not be inspected, sudo authentication was required, and kernel CVE matching was not performed.

The absence of High or Critical findings does not prove that the system is secure.

## 9. Known Limitations

- Scanner coverage is limited to selected configuration locations.
- Some checks depend on the current user's permissions.
- Kernel CVE matching is not implemented.
- Heuristic scores require manual validation.
- Findings may include false positives or false negatives.
- The toolkit has not been validated across all Linux distributions.
- Incomplete assessments limit the conclusions that can be drawn.

## 10. Future Scope

Potential improvements include:

- Verified kernel advisory integration
- Expanded Linux distribution support
- Broader configuration coverage
- Improved remediation recommendations
- Additional regression tests
- HTML reporting and dashboard visualization

## 11. Conclusion

The project demonstrates how Python can automate selected defensive Linux configuration checks and organize the results into structured security reports.

Seven scanner modules, a heuristic risk engine, audit completeness tracking, TXT/JSON reporting, and automated tests have been implemented.

The latest verified test run passed 38 automated tests, and the latest audit produced 40 findings with six incomplete checks.

The toolkit provides a foundation for educational and authorized Linux security assessments while acknowledging its current coverage and validation limitations.

## 12. Repository

GitHub: https://github.com/AyushmanSingh-Cybo/Linux-Privesc-Toolkit

## 13. Disclaimer

This toolkit is intended exclusively for educational and authorized defensive security assessment. Findings are review priorities, not confirmed vulnerabilities.
