
# Linux Security Audit Toolkit — Architecture

## System Architecture

```mermaid
flowchart TD
    A["User / Terminal"] --> B["Main Controller: main.py"]
    B --> C["System Information Collection"]
    B --> D["Security Scanner Layer"]

    subgraph SCANNERS["Security Scanner Layer"]
        D1["SUID / SGID"]
        D2["File Permissions"]
        D3["Sudo Permissions"]
        D4["Cron Configuration"]
        D5["Linux Capabilities"]
        D6["Systemd Services"]
        D7["Kernel Security Assessment"]
    end

    D --> D1
    D --> D2
    D --> D3
    D --> D4
    D --> D5
    D --> D6
    D --> D7

    D1 --> E["Collected Findings"]
    D2 --> E
    D3 --> E
    D4 --> E
    D5 --> E
    D6 --> E
    D7 --> E

    E --> F["Risk Scoring Engine: risk_engine.py"]
    F --> G["Audit Completeness Tracking"]
    G --> H["Report Generator: report.py"]

    C --> H
    H --> I["TXT Report"]
    H --> J["JSON Report"]
```

## Component Description

**Main Controller (`main.py`):** Coordinates system information collection, scanner execution, risk scoring, and report generation.

**Security Scanners (`scanners/`):** Perform seven defensive Linux configuration checks.

**Risk Scoring Engine (`risk_engine.py`):** Assigns heuristic review-priority scores and severity labels.

**Audit Completeness Tracking:** Identifies incomplete checks and indicates when an assessment is partial.

**Report Generator (`report.py`):** Produces human-readable TXT and structured JSON reports.

## Security Scope

The toolkit is intended for authorized, read-only configuration assessment. It does not exploit vulnerabilities or attempt privilege escalation.

Kernel CVE matching is not currently implemented. Kernel information is collected, and this limitation is reported.
