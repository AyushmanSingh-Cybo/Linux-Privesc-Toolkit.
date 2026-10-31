
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scanners.capabilities import scan_capabilities


class TestCapabilitiesScanner(unittest.TestCase):

    @patch("scanners.capabilities.subprocess.run")
    def test_detects_capabilities(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            returncode=0,
            stdout="/usr/bin/ping cap_net_raw=ep\n",
            stderr=""
        )

        findings = scan_capabilities()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "Linux capability")
        self.assertIn("cap_net_raw", findings[0]["details"])

    @patch("scanners.capabilities.subprocess.run")
    def test_missing_getcap(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        findings = scan_capabilities()

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["type"],
            "Capabilities scan warning"
        )
        self.assertIn(
            "getcap was not found",
            findings[0]["details"]
        )
        self.assertEqual(
            findings[0]["check_status"],
            "incomplete"
        )

    @patch("scanners.capabilities.subprocess.run")
    def test_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="getcap",
            timeout=120
        )

        findings = scan_capabilities()

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["type"],
            "Capabilities scan warning"
        )
        self.assertIn(
            "timed out",
            findings[0]["details"]
        )
        self.assertEqual(
            findings[0]["check_status"],
            "incomplete"
        )
        self.assertIn(
            "120 seconds",
            findings[0]["details"]
        )


if __name__ == "__main__":
    unittest.main()
