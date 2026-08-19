#!/usr/bin/env python3
"""
End-to-End API Integration Test Suite for DDoS Notification Tool.
Tests complete REST lifecycle: Setup, Auth, Settings, Prefixes, IP CSV Import, Monitoring simulation, Logs, and CSV Exports.
"""

import os
import sys
import unittest
import json
import urllib.request
import urllib.parse
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reset DB for a clean test run
        if os.path.exists(server.DB_PATH):
            os.remove(server.DB_PATH)
        server.init_db()

        # Start background test HTTP server
        cls.port = 5099
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.httpd = server.http.server.ThreadingHTTPServer(('127.0.0.1', cls.port), server.DDoSRequestHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _req(self, path, method="GET", data=None, token=None):
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        body = json.dumps(data).encode('utf-8') if data is not None else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return resp.status, json.loads(raw.decode('utf-8'))
                return resp.status, raw.decode('utf-8')
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8')
            try:
                return e.code, json.loads(err_body)
            except Exception:
                return e.code, err_body

    def test_full_lifecycle(self):
        # 1. Check initial status -> should not be setup
        status, res = self._req("/api/auth/status")
        self.assertEqual(status, 200)
        self.assertFalse(res["is_setup"])

        # 2. Setup with weak password -> should fail
        status, res = self._req("/api/auth/setup", method="POST", data={"password": "weak", "confirmPassword": "weak"})
        self.assertEqual(status, 400)

        # 3. Setup with valid password
        status, res = self._req("/api/auth/setup", method="POST", data={
            "password": "SecurePassword123!",
            "confirmPassword": "SecurePassword123!"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res["success"])
        token = res["token"]
        self.assertTrue(bool(token))

        # 4. Save settings
        status, res = self._req("/api/settings", method="POST", data={
            "account_id": "2042665",
            "api_id": "test-api-id",
            "api_key": "test-api-key",
            "monitoring_interval_seconds": "30",
            "monitoring_enabled": "true",
            "smtp_host": "smtp.example.com",
            "smtp_recipients": "alerts@example.com"
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(res["settings"]["account_id"], "2042665")

        # 5. Populate sample protected prefixes in DB
        with server.get_db() as conn:
            sample_prefixes = {
                "9377": "142.198.93.0/24",
                "11330": "142.198.96.0/24",
                "13208": "45.223.249.0/24"
            }
            for pid, prefix in sample_prefixes.items():
                conn.execute("INSERT OR REPLACE INTO protected_prefixes (id, prefix) VALUES (?, ?)", (pid, prefix))
            conn.commit()

        # 6. Fetch prefixes via API
        status, res = self._req("/api/prefixes", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(res["total"], 3)

        # 7. Add monitored IP
        status, res = self._req("/api/ips", method="POST", data={
            "ip_address": "195.128.248.33",
            "description": "Critical Web Node 01",
            "assigned_prefixes": ["45.223.249.0/24"]
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(res["ip"]["ip_address"], "195.128.248.33")

        # 8. Import CSV
        csv_data = """IP, Description, Prefixes
172.110.223.73, API Core Cluster, 142.198.93.0/24
93.123.109.23, DNS Server Primary, *
"""
        status, res = self._req("/api/ips/import-csv", method="POST", data={"csv_text": csv_data}, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(res["imported_count"], 2)

        # 9. List all monitored IPs
        status, res = self._req("/api/ips", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(res["total"], 3)

        # 10. Export IPs CSV
        status, res = self._req("/api/ips/export-csv", token=token)
        self.assertEqual(status, 200)
        self.assertIn("195.128.248.33", res)
        self.assertIn("Critical Web Node 01", res)

        # 11. Trigger simulated DDoS block event matching monitored IP
        status, res = self._req("/api/monitor/simulate", method="POST", data={
            "custom_events": [{
                "timestamp": "2026-08-18 21:00:00 UTC",
                "source_ip": "195.128.248.33",
                "bandwidth_bps": 61185365.33,
                "bandwidth_human": "61.19 Mbps",
                "network_range": "45.223.249.0/24",
                "description": "Critical Web Node 01"
            }]
        }, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(res["success"])

        # 12. Query logs
        status, res = self._req("/api/logs", token=token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["pagination"]["total"], 1)
        self.assertEqual(res["logs"][0]["source_ip"], "195.128.248.33")

        # 13. Query log stats
        status, res = self._req("/api/logs/stats", token=token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["total_events"], 1)
        self.assertEqual(res["peak_bandwidth"], "61.19 Mbps")

        # 14. Export Logs CSV
        status, res = self._req("/api/logs/export-csv", token=token)
        self.assertEqual(status, 200)
        self.assertIn("195.128.248.33", res)
        self.assertIn("61.19 Mbps", res)

if __name__ == '__main__':
    unittest.main()
