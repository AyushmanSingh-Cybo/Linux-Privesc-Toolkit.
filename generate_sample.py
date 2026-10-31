from pathlib import Path
from risk_engine import add_risk_scores
from report import generate_report

sample_findings = [
    {
        "type": "SUID binary",
        "path": "/usr/bin/passwd",
        "details": "Common system SUID binary detected",
        "permissions": "0o4755"
    },
    {
        "type": "Linux capability",
        "path": "/usr/bin/ping",
        "details": "cap_net_raw=ep",
    },
    {
        "type": "Cron check",
        "path": "/etc/cron.d/example-task",
        "details": "Example scheduled task",
        "writable_by_current_user": True,
    },
    {
        "type": "Sudo configuration",
        "details": "Example NOPASSWD ALL configuration",
    },
    {
        "type": "Scanner warning",
        "details": "Sudo check requires authentication",
        "check_status": "incomplete",
    },
]

findings = add_risk_scores(sample_findings)

generate_report(findings, output_dir="examples")

Path("examples/security_audit.json").replace(
    "examples/sample_security_audit.json"
)

Path("examples/security_audit.txt").replace(
    "examples/sample_security_audit.txt"
)

print("Sample reports generated successfully.")