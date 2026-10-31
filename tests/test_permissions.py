
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



if __name__ == "__main__":
    unittest.main()
