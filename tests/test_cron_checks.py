
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scanners.cron_checks import inspect_cron_file


class TestCronScanner(unittest.TestCase):

    @patch("scanners.cron_checks.os.access", return_value=True)
    @patch("scanners.cron_checks.pwd.getpwuid")
    @patch("scanners.cron_checks.os.stat")
    def test_writable_cron_file(self, mock_stat, mock_owner, mock_access):
        mock_stat.return_value = SimpleNamespace(
            st_mode=0o100666,
            st_uid=1000
        )
        mock_owner.return_value = SimpleNamespace(pw_name="testuser")

        finding = inspect_cron_file("/tmp/example-cron")

        self.assertEqual(finding["type"], "Cron configuration")
        self.assertEqual(finding["permissions"], "0o666")
        self.assertEqual(finding["owner"], "testuser")
        self.assertTrue(finding["writable_by_current_user"])

    @patch("scanners.cron_checks.os.access", return_value=False)
    @patch("scanners.cron_checks.pwd.getpwuid")
    @patch("scanners.cron_checks.os.stat")
    def test_non_writable_cron_file(self, mock_stat, mock_owner, mock_access):
        mock_stat.return_value = SimpleNamespace(
            st_mode=0o100644,
            st_uid=0
        )
        mock_owner.return_value = SimpleNamespace(pw_name="root")

        finding = inspect_cron_file("/tmp/example-cron")

        self.assertEqual(finding["permissions"], "0o644")
        self.assertEqual(finding["owner"], "root")
        self.assertFalse(finding["writable_by_current_user"])


if __name__ == "__main__":
    unittest.main()
