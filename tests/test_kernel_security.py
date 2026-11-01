
import unittest
from unittest.mock import patch

from scanners.kernel_security import assess_kernel_security


class TestKernelSecurity(unittest.TestCase):

    @patch("scanners.kernel_security.get_os_information")
    @patch("scanners.kernel_security.platform.release")
    def test_detects_wsl2_kernel(self, mock_kernel, mock_os):
        mock_kernel.return_value = (
            "6.18.54.1-microsoft-standard-WSL2"
        )
        mock_os.return_value = {
            "PRETTY_NAME": "Ubuntu 26.04.1 LTS"
        }

        result = assess_kernel_security()

        self.assertEqual(result["environment"], "WSL2")
        self.assertEqual(
            result["kernel_provider"], "Microsoft WSL2"
        )
        self.assertEqual(result["cve_status"], "Not assessed")
        self.assertEqual(result["check_status"], "incomplete")

    @patch("scanners.kernel_security.get_os_information")
    @patch("scanners.kernel_security.platform.release")
    def test_detects_standard_linux(self, mock_kernel, mock_os):
        mock_kernel.return_value = "6.8.0-generic"
        mock_os.return_value = {
            "PRETTY_NAME": "Ubuntu Test"
        }

        result = assess_kernel_security()

        self.assertEqual(
            result["environment"], "Standard/Other Linux"
        )
        self.assertEqual(
            result["kernel_provider"], "Linux distribution"
        )

    @patch("scanners.kernel_security.get_os_information")
    @patch("scanners.kernel_security.platform.release")
    def test_does_not_invent_cve_results(
        self, mock_kernel, mock_os
    ):
        mock_kernel.return_value = "5.15.0-test"
        mock_os.return_value = {}

        result = assess_kernel_security()

        self.assertEqual(result["cve_status"], "Not assessed")
        self.assertIn("not been verified", result["details"])


if __name__ == "__main__":
    unittest.main()
