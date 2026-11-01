
import os
import tempfile
import unittest
from unittest.mock import patch

from scanners.permissions import scan_permissions


class TestPermissionsScanner(unittest.TestCase):

    def test_detects_world_writable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = os.path.join(directory, "test.txt")

            with open(test_file, "w", encoding="utf-8") as file:
                file.write("Test data")

            os.chmod(test_file, 0o666)

            original_isdir = os.path.isdir

            def mock_isdir(path):
                if path in ("/etc", "/usr/local", "/opt"):
                    return path == "/etc"
                return original_isdir(path)

            with patch(
                "scanners.permissions.os.path.isdir",
                side_effect=mock_isdir
            ), patch(
                "scanners.permissions.os.walk",
                return_value=[
                    (directory, [], ["test.txt"])
                ]
            ):
                findings = scan_permissions()

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["path"], test_file)
            self.assertEqual(findings[0]["permissions"], "0o666")
            self.assertEqual(findings[0]["type"], "file")

    def test_ignores_safe_file(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = os.path.join(directory, "safe.txt")

            with open(test_file, "w", encoding="utf-8") as file:
                file.write("Safe test data")

            os.chmod(test_file, 0o644)

            with patch(
                "scanners.permissions.os.path.isdir",
                return_value=True
            ), patch(
                "scanners.permissions.os.walk",
                return_value=[
                    (directory, [], ["safe.txt"])
                ]
            ):
                findings = scan_permissions()

            self.assertEqual(findings, [])

    def test_detects_sensitive_file_write_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = os.path.join(directory, "passwd")

            with open(test_file, "w", encoding="utf-8") as file:
                file.write("Test data")

            os.chmod(test_file, 0o666)

            with patch(
                "scanners.permissions.SCAN_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.SENSITIVE_FILES",
                (test_file,)
            ), patch(
                "scanners.permissions.PRIVILEGED_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.os.path.isdir",
                return_value=False
            ):
                findings = scan_permissions()

            self.assertTrue(any(
                item.get("path") == test_file
                and "write permissions" in item.get("details", "")
                for item in findings
            ))

    def test_detects_world_writable_home_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            home = os.path.join(directory, "home")
            os.mkdir(home)

            user_home = os.path.join(home, "testuser")
            os.mkdir(user_home)
            os.chmod(user_home, 0o777)

            original_isdir = os.path.isdir
            original_scandir = os.scandir

            def mock_isdir(path):
                if path == "/home":
                    return True
                return original_isdir(path)

            def mock_scandir(path):
                if path == "/home":
                    return original_scandir(home)
                return original_scandir(path)

            with patch(
                "scanners.permissions.SCAN_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.SENSITIVE_FILES", ()
            ), patch(
                "scanners.permissions.PRIVILEGED_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.os.path.isdir",
                side_effect=mock_isdir
            ), patch(
                "scanners.permissions.os.scandir",
                side_effect=mock_scandir
            ):
                findings = scan_permissions()

            self.assertTrue(any(
                item.get("path") == user_home
                and item.get("type") == "directory"
                for item in findings
            ))

    def test_detects_writable_privileged_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            privileged = os.path.join(directory, "cron.d")
            os.mkdir(privileged)
            os.chmod(privileged, 0o777)

            with patch(
                "scanners.permissions.SCAN_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.SENSITIVE_FILES", ()
            ), patch(
                "scanners.permissions.PRIVILEGED_DIRECTORIES",
                (privileged,)
            ), patch(
                "scanners.permissions.os.path.isdir",
                side_effect=lambda path: path == privileged
            ):
                findings = scan_permissions()

            self.assertTrue(any(
                item.get("path") == privileged
                and item.get("type") == "directory"
                for item in findings
            ))

    def test_records_incomplete_sensitive_file_check(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_file = os.path.join(
                directory,
                "missing-sensitive-file"
            )

            with patch(
                "scanners.permissions.SCAN_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.SENSITIVE_FILES",
                (missing_file,)
            ), patch(
                "scanners.permissions.PRIVILEGED_DIRECTORIES", ()
            ), patch(
                "scanners.permissions.os.path.isdir",
                return_value=False
            ):
                findings = scan_permissions()

            self.assertTrue(any(
                item.get("check_status") == "incomplete"
                and item.get("path") == missing_file
                for item in findings
            ))


if __name__ == "__main__":
    unittest.main()
