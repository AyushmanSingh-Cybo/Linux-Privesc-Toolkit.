
# Linux Security Audit Toolkit — Execution Flowchart

## Audit Execution Flow

```mermaid
flowchart TD
    A([Start]) --> B["Run python3 main.py"]
    B --> C["Collect Linux System Information"]
    C --> D["Initialize Audit Findings"]

    D --> E["Execute Seven Security Scanners"]

    subgraph SCANS["Security Assessment"]
        S1["SUID / SGID Scanner"]
        S2["File Permissions Scanner"]
        S3["Sudo Permissions Scanner"]
        S4["Cron Configuration Scanner"]
        S5["Linux Capabilities Scanner"]
        S6["Systemd Services Scanner"]
        S7["Kernel Security Assessment"]
    end

    E --> S1
    E --> S2
    E --> S3
    E --> S4
    E --> S5
    E --> S6
    E --> S7

    S1 --> F["Aggregate Scanner Results"]
    S2 --> F
    S3 --> F
    S4 --> F
    S5 --> F
    S6 --> F
    S7 --> F

    F --> G["Assign Heuristic Risk Scores"]
    G --> H["Calculate Severity Summary"]
    H --> I{"Any Incomplete Checks?"}

    I -->|Yes| J["Mark Audit PARTIAL"]
    I -->|No| K["No Incomplete Checks Reported"]

    J --> L["Generate TXT and JSON Reports"]
    K --> L

    L --> M["Display Audit Summary"]
    M --> N([End])
```

## Execution Steps

1. The user starts the toolkit using `python3 main.py`.
2. The application collects Linux system information.
3. Seven defensive security scanners review selected configurations.
4. Scanner findings are collected into a combined results list.
5. The risk engine assigns preliminary risk scores and severity levels.
6. The toolkit calculates the severity distribution.
7. Incomplete checks are identified and the audit status is determined.
8. TXT and JSON reports are generated.
9. The terminal displays the final audit summary.

## Audit Status

**PARTIAL:** One or more checks could not be completed.

**No incomplete checks reported:** All tracked checks completed without reporting an incomplete status. This does not guarantee the system is secure or that every possible security issue was assessed.

## Important Limitations

- Findings are review priorities, not confirmed vulnerabilities.
- The toolkit does not perform exploitation or privilege escalation.
- Kernel CVE matching is not currently implemented.
- Results depend on system configuration, scanner coverage, and user permissions.
```
