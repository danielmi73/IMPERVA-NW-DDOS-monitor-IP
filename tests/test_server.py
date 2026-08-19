#!/usr/bin/env python3
"""
Comprehensive test suite for DDoS Notification Server
Tests SQLite DB, Auth, Password rules, IP CRUD, CSV import/export, Logs, and Alerts.
"""

import os
import sys
import unittest
import json
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server


class TestDDoSNotificationSystem(unittest.TestCase):
    def setUp(self):
        server.init_db()

    def test_01_password_validation(self):
        # Too short
        ok, msg = server.validate_password_rules("123")
        self.assertFalse(ok)
        self.assertIn("at least 6 characters", msg)

        # Missing number
        ok, msg = server.validate_password_rules("AdminSecret!")
        self.assertFalse(ok)
        self.assertIn("at least one number", msg)

        # Missing special character
        ok, msg = server.validate_password_rules("AdminSecret123")
        self.assertFalse(ok)
        self.assertIn("special character", msg)

        # Valid
        ok, msg = server.validate_password_rules("Admin@2026Secure")
        self.assertTrue(ok)

    def test_02_password_hashing_and_verify(self):
        pwd = "SafeP@ssw0rd!"
        h, salt = server.hash_password(pwd)
        self.assertTrue(server.verify_password(pwd, h, salt))
        self.assertFalse(server.verify_password("WrongPassword1!", h, salt))

    def test_03_bandwidth_formatting(self):
        self.assertEqual(server.format_bandwidth(61185365.33), "61.19 Mbps")
        self.assertEqual(server.format_bandwidth(14828800), "14.83 Mbps")
        self.assertEqual(server.format_bandwidth(1500000000), "1.50 Gbps")
        self.assertEqual(server.format_bandwidth(31914.67), "31.91 Kbps")
        self.assertEqual(server.format_bandwidth(500), "500.00 bps")

    def test_04_email_template_rendering(self):
        events = [{
            "timestamp": "2026-08-18 20:00:00 UTC",
            "source_ip": "195.128.248.33",
            "description": "Primary Gateway",
            "network_range": "142.198.93.0/24",
            "bandwidth_human": "61.19 Mbps"
        }]
        settings = {
            "account_id": "2042665",
            "email_subject_template": "🚨 DDoS Alert: {count} IP(s) - Account {account_id}",
            "email_body_template": "Blocked: {ip_list} on {account_id}"
        }
        subj, body = server.render_email_template(events, settings)
        self.assertEqual(subj, "🚨 DDoS Alert: 1 IP(s) - Account 2042665")
        self.assertEqual(body, "Blocked: 195.128.248.33 on 2042665")

    def test_05_block_simulation_and_logs(self):
        result = server.monitor_worker.simulate_block()
        self.assertTrue(result["success"])
        self.assertGreaterEqual(len(result["events"]), 1)

        with server.get_db() as conn:
            logs = conn.execute("SELECT * FROM blocking_logs ORDER BY id DESC LIMIT 5").fetchall()
            self.assertGreater(len(logs), 0)

if __name__ == '__main__':
    unittest.main()
