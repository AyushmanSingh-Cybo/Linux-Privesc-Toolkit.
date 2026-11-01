
import unittest
from unittest.mock import patch

from scanners.system_info import collect_system_info


class TestSystemInfo(unittest.TestCase):

    @patch("scanners.system_info.platform.machine")
    @patch("scanners.system_info.platform.release")
    @patch("scanners.system_info.platform.freedesktop_os_release")
    @patch("scanners.system_info.grp.getgrgid")
    @patch("scanners.system_info.pwd.getpwuid")
    @patch("scanners.system_info.os.getgroups")
    @patch("scanners.system_info.os.getgid")
    @patch("scanners.system_info.os.getuid")
    def test_collect_standard_user(
        self, mock_uid, mock_gid, mock_groups,
        mock_pwd, mock_grp, mock_os,
        mock_kernel, mock_arch
    ):
        mock_uid.return_value = 1000
        mock_gid.return_value = 1000
        mock_groups.return_value = [1000, 27]

        mock_pwd.return_value.pw_name = "testuser"
        mock_grp.side_effect = lambda gid: type(
            "Group", (), {"gr_name": {1000: "testuser", 27: "sudo"}[gid]}
        )()

        mock_os.return_value = {"PRETTY_NAME": "Ubuntu Test"}
        mock_kernel.return_value = "6.8.0-test"
        mock_arch.return_value = "x86_64"

        info = collect_system_info()

        self.assertEqual(info["username"], "testuser")
        self.assertEqual(info["uid"], 1000)
        self.assertEqual(info["gid"], 1000)
        self.assertEqual(info["groups"], ["sudo", "testuser"])
        self.assertEqual(info["operating_system"], "Ubuntu Test")
        self.assertEqual(info["kernel_version"], "6.8.0-test")
        self.assertEqual(info["architecture"], "x86_64")
        self.assertFalse(info["is_root"])

    @patch("scanners.system_info.os.getuid", return_value=0)
    @patch("scanners.system_info.os.getgid", return_value=0)
    @patch("scanners.system_info.os.getgroups", return_value=[0])
    @patch("scanners.system_info.pwd.getpwuid")
    @patch("scanners.system_info.grp.getgrgid")
    def test_detects_root_user(
        self, mock_grp, mock_pwd, mock_groups,
        mock_gid, mock_uid
    ):
        mock_pwd.return_value.pw_name = "root"
        mock_grp.return_value.gr_name = "root"

        info = collect_system_info()

        self.assertEqual(info["uid"], 0)
        self.assertTrue(info["is_root"])
        self.assertEqual(info["username"], "root")


if __name__ == "__main__":
    unittest.main()
