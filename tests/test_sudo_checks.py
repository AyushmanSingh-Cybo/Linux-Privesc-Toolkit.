
import unittest
from unittest.mock import patch

from scanners.sudo_checks import scan_sudo


class TestSudoScanner(unittest.TestCase):

    @patch("scanners.sudo_checks.subprocess.run")
    def test_authentication_required_returns_warning(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = (
            "sudo: interactive authentication is required"
        )

        findings = scan_sudo()

        self.assertIsInstance(findings, list)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "Warning")
        self.assertEqual(findings[0]["check_status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
