
import unittest

from risk_engine import assess_risk, add_risk_scores


class TestRiskEngine(unittest.TestCase):

    def test_common_suid_binary(self):
        result = assess_risk({
            "type": "SUID",
            "path": "/usr/bin/sudo",
        })
        self.assertEqual(result["risk_score"], 25)
        self.assertEqual(result["risk_level"], "Low")

    def test_custom_suid_binary(self):
        result = assess_risk({
            "type": "SUID",
            "path": "/tmp/custom-tool",
        })
        self.assertEqual(result["risk_score"], 35)
        self.assertEqual(result["risk_level"], "Medium")

    def test_high_risk_capability(self):
        result = assess_risk({
            "type": "Linux capability",
            "details": "cap_sys_admin",
        })
        self.assertEqual(result["risk_score"], 75)
        self.assertEqual(result["risk_level"], "High")

    def test_passwordless_sudo_all(self):
        result = assess_risk({
            "type": "Sudo permissions",
            "details": "NOPASSWD: ALL",
        })
        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["risk_level"], "Critical")

    def test_writable_cron_file(self):
        result = assess_risk({
            "type": "Cron configuration",
            "details": "Writable scheduled-task file",
        })
        self.assertEqual(result["risk_score"], 65)
        self.assertEqual(result["risk_level"], "High")

    def test_warning_is_low_priority(self):
        result = assess_risk({
            "type": "Warning",
            "details": "Sudo check incomplete",
        })
        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(result["risk_level"], "Low")

    def test_add_risk_scores_preserves_original(self):
        original = [
            {
                "type": "SUID",
                "path": "/tmp/custom-tool",
            }
        ]

        scored = add_risk_scores(original)

        self.assertNotIn("risk_score", original[0])
        self.assertEqual(len(scored), 1)
        self.assertIn("risk_score", scored[0])
        self.assertIn("risk_level", scored[0])

    # Regression tests

    def test_safe_cron_file_is_not_high_risk(self):
        result = assess_risk({
            "type": "Cron configuration",
            "details": "Not writable by current user",
            "writable_by_current_user": False,
        })

        self.assertEqual(result["risk_score"], 25)
        self.assertEqual(result["risk_level"], "Low")

    def test_world_writable_file(self):
        result = assess_risk({
            "type": "file",
            "path": "/tmp/test-file",
            "permissions": "0o666",
            "details": "World-writable system item",
        })

        self.assertEqual(result["risk_score"], 60)
        self.assertEqual(result["risk_level"], "High")

    def test_sticky_bit_directory(self):
        result = assess_risk({
            "type": "directory",
            "path": "/tmp",
            "permissions": "0o1777",
            "details": "World-writable directory",
        })

        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "Medium")

    def test_incomplete_check_remains_low_priority(self):
        result = assess_risk({
            "type": "File permission scan warning",
            "path": "/etc/ssl/private",
            "check_status": "incomplete",
            "details": "Permission denied",
        })

        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(result["risk_level"], "Low")

    def test_passwordless_sudo_remains_critical(self):
        result = assess_risk({
            "type": "Sudo permissions",
            "details": "NOPASSWD: ALL",
        })

        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["risk_level"], "Critical")


if __name__ == "__main__":
    unittest.main()
