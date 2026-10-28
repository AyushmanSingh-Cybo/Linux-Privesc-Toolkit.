
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from report import generate_report


class TestReport(unittest.TestCase):

    def test_reports_preserve_findings(self):
        sample_findings = [
            {
                "type": "SUID",
                "path": "/usr/bin/example",
                "risk_level": "Medium",
                "risk_score": 35,
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("report.Path", Path):
                with patch("report.Path.mkdir"):
                    with patch("report.Path.open"):
                        pass

            # Run the real report generator in an isolated directory.
            with patch("report.Path") as MockPath:
                report_dir = Path(temp_dir) / "reports"
                MockPath.return_value = report_dir
                MockPath.side_effect = lambda value: Path(temp_dir) / value

                with patch("report.Path.mkdir"):
                    pass

            # Use a temporary working directory for real file output.
            import os
            old_dir = os.getcwd()
            try:
                os.chdir(temp_dir)
                generate_report(sample_findings)

                with open("reports/security_audit.json", encoding="utf-8") as file:
                    data = json.load(file)

                self.assertEqual(data["total_findings"], 1)
                self.assertEqual(len(data["findings"]), 1)
                self.assertEqual(data["findings"][0]["risk_score"], 35)
                self.assertEqual(data["findings"][0]["path"], "/usr/bin/example")

                text_report = Path("reports/security_audit.txt").read_text(
                    encoding="utf-8"
                )
                self.assertIn("LINUX SECURITY AUDIT REPORT", text_report)
                self.assertIn("/usr/bin/example", text_report)
            finally:
                os.chdir(old_dir)


if __name__ == "__main__":
    unittest.main()
