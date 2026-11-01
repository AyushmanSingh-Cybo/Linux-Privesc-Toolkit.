
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanners.services import scan_services


class TestSystemdServices(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)

        self.directory_patch = patch(
            "scanners.services.SERVICE_DIRECTORIES",
            [self.directory]
        )
        self.directory_patch.start()

    def tearDown(self):
        self.directory_patch.stop()
        self.temp_dir.cleanup()

    def create_service(self, name, content, mode=0o644):
        path = self.directory / name
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_secure_service_has_no_findings(self):
        self.create_service(
            "safe.service",
            "[Service]\n"
            "User=nobody\n"
            "ExecStart=/usr/bin/true\n"
        )

        findings = scan_services()
        self.assertEqual(findings, [])

    def test_world_writable_service_is_flagged(self):
        path = self.create_service(
            "unsafe.service",
            "[Service]\nExecStart=/usr/bin/true\n",
            mode=0o666
        )

        findings = scan_services()

        self.assertTrue(
            any(
                f["type"] == "Systemd service permission review"
                and f["path"] == str(path)
                for f in findings
            )
        )

    def test_masked_service_is_skipped(self):
        path = self.directory / "masked.service"
        path.symlink_to("/dev/null")

        findings = scan_services()

        self.assertEqual(findings, [])

    def test_root_service_path_is_reviewed(self):
        self.create_service(
            "custom.service",
            "[Service]\n"
            "User=root\n"
            'Environment="PATH=/tmp:/usr/bin"\n'
            "ExecStart=/usr/bin/true\n"
        )

        findings = scan_services()

        self.assertTrue(
            any(
                f["type"] == "Systemd PATH configuration review"
                for f in findings
            )
        )


if __name__ == "__main__":
    unittest.main()
