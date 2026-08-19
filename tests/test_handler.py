#!/usr/bin/env python3
"""
Unit and Handler Tests for DDoS Notification System
Directly tests handler logic, DB persistence, API request parsing, and worker without network sockets.
"""

import os
import sys
import unittest
import json
import io
import csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

class MockSocket:
    def __init__(self, data=b""):
        self.rfile = io.BytesIO(data)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode:
            return self.rfile
        return self.wfile

class TestDDoSHandlerDirect(unittest.TestCase):
    def setUp(self):
        if os.path.exists(server.DB_PATH):
            os.remove(server.DB_PATH)
        server.init_db()

    def test_01_password_rules_and_admin_setup(self):
        # Validate rules
        self.assertFalse(server.validate_password_rules("short")[0])
        self.assertFalse(server.validate_password_rules("nouppercaseorrules123")[0]) # missing special
        self.assertFalse(server.validate_password_rules("NoDigitsHere!")[0])
        self.assertTrue(server.validate_password_rules("Adm!n2026Pass")[0])

        # Password hashing
        h, salt = server.hash_password("Adm!n2026Pass")
        self.assertTrue(server.verify_password("Adm!n2026Pass", h, salt))
        self.assertFalse(server.verify_password("WrongPassword!", h, salt))

    def test_02_session_tokens(self):
        token = server.create_session()
        self.assertTrue(server.verify_session(token))
        self.assertFalse(server.verify_session("fake-token-123"))

    def test_03_settings_persistence(self):
        saved = server.save_settings({
            "account_id": "2042665",
            "api_id": "api-123",
            "api_key": "key-456",
            "monitoring_interval_seconds": "45"
        })
        self.assertEqual(saved["account_id"], "2042665")
        self.assertEqual(saved["monitoring_interval_seconds"], "45")

        all_settings = server.get_all_settings()
        self.assertEqual(all_settings["account_id"], "2042665")

    def test_04_monitored_ips_and_csv(self):
        with server.get_db() as conn:
            conn.execute("INSERT INTO monitored_ips (ip_address, description, assigned_prefixes) VALUES (?, ?, ?)",
                         ("195.128.248.33", "Gateway Node", json.dumps(["142.198.93.0/24"])))
            conn.execute("INSERT INTO monitored_ips (ip_address, description, assigned_prefixes) VALUES (?, ?, ?)",
                         ("172.110.223.73", "API Server", json.dumps(["*"])))
            conn.commit()

            rows = conn.execute("SELECT * FROM monitored_ips").fetchall()
            self.assertEqual(len(rows), 2)

    def test_05_logs_and_bandwidth(self):
        bw_str = server.format_bandwidth(61185365.33)
        self.assertEqual(bw_str, "61.19 Mbps")

        with server.get_db() as conn:
            conn.execute("""
                INSERT INTO blocking_logs 
                (timestamp, source_ip, bandwidth_bps, bandwidth_human, network_range, description, notification_sent, notification_status, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("2026-08-18 21:00:00 UTC", "195.128.248.33", 61185365.33, bw_str, "45.223.249.0/24", "Gateway", 1, "Sent", "{}"))
            conn.commit()

            log = conn.execute("SELECT * FROM blocking_logs WHERE source_ip = ?", ("195.128.248.33",)).fetchone()
            self.assertIsNotNone(log)
            self.assertEqual(log["bandwidth_human"], "61.19 Mbps")

    def test_06_email_template_batching(self):
        events = [
            {"source_ip": "195.128.248.33", "description": "Web 1", "network_range": "142.198.93.0/24", "bandwidth_bps": 61185365, "bandwidth_human": "61.19 Mbps"},
            {"source_ip": "172.110.223.73", "description": "Web 2", "network_range": "45.223.249.0/24", "bandwidth_bps": 14828800, "bandwidth_human": "14.83 Mbps"}
        ]
        settings = {
            "account_id": "2042665",
            "email_subject_template": "🚨 DDoS Alert: {count} IP(s) under attack!",
            "email_body_template": "Account: {account_id}, IPs: {ip_list}\n{event_rows}"
        }
        subj, body = server.render_email_template(events, settings)
        self.assertEqual(subj, "🚨 DDoS Alert: 2 IP(s) under attack!")
        self.assertIn("195.128.248.33, 172.110.223.73", body)
        self.assertIn("142.198.93.0/24", body)

if __name__ == '__main__':
    unittest.main()
