
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scanners.suid_sgid import scan_suid_sgid


class TestSuidSgidScanner(unittest.TestCase):

    @patch("scanners.suid_sgid.os.stat")
    @patch("scanners.suid_sgid.subprocess.run")
    def test_detects_suid_file(self, mock_run, mock_stat):
        mock_run.return_value = SimpleNamespace(
            stdout="/usr/bin/example-suid\n",
            stderr="",
            returncode=0
        )

        mock_stat.return_value = SimpleNamespace(
            st_mode=0o104755
        )

        findings = scan_suid_sgid()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "SUID")
        self.assertEqual(
            findings[0]["path"],
            "/usr/bin/example-suid"
        )

    @patch("scanners.suid_sgid.os.stat")
    @patch("scanners.suid_sgid.subprocess.run")
    def test_detects_sgid_file(self, mock_run, mock_stat):
        mock_run.return_value = SimpleNamespace(
            stdout="/usr/bin/example-sgid\n",
            stderr="",
            returncode=0
        )

        mock_stat.return_value = SimpleNamespace(
            st_mode=0o102755
        )

        findings = scan_suid_sgid()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "SGID")

    @patch("scanners.suid_sgid.os.stat")
    @patch("scanners.suid_sgid.subprocess.run")
    def test_ignores_regular_file(self, mock_run, mock_stat):
        mock_run.return_value = SimpleNamespace(
            stdout="/usr/bin/regular-file\n",
            stderr="",
            returncode=0
        )

        mock_stat.return_value = SimpleNamespace(
            st_mode=0o100755
        )

        findings = scan_suid_sgid()

        self.assertEqual(findings, [])

    @patch("scanners.suid_sgid.subprocess.run")
    def test_find_command_failure(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="Permission denied",
            returncode=1
        )

        findings = scan_suid_sgid()

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["type"],
            "SUID/SGID scan warning"
        )
        self.assertEqual(
            findings[0]["check_status"],
            "incomplete"
        )
        self.assertIn(
            "Permission denied",
            findings[0]["details"]
        )


if __name__ == "__main__":
    unittest.main()
