#!/usr/bin/env python3
"""
DDoS IP Monitoring & Notification System
Backend server built with Python standard library (Zero external dependencies).
Includes SQLite database, Multi-threaded HTTP REST API, Imperva DDoS API Client,
SMTP Email Dispatcher with templating, and Background Polling Worker.
"""

import http.server
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sqlite3
import hashlib
import hmac
import secrets
import csv
import io
import threading
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
PUBLIC_DIR = os.path.join(BASE_DIR, 'public')
DB_PATH = os.path.join(DATA_DIR, 'ddos_monitor.db')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(PUBLIC_DIR, exist_ok=True)

# ----------------------------------------------------------------------
# Database Initialization & Helpers
# ----------------------------------------------------------------------

def reset_corrupt_db():
    print("[DB] Malformed database file detected. Resetting SQLite database...")
    for ext in ['', '-wal', '-shm']:
        f = DB_PATH + ext
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception as e:
                print(f"[DB] Error removing {f}: {e}")

def get_db():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=20.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return conn
    except sqlite3.DatabaseError as e:
        if "malformed" in str(e).lower() or "disk image" in str(e).lower() or "corrupt" in str(e).lower():
            reset_corrupt_db()
            conn = sqlite3.connect(DB_PATH, timeout=20.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL")
            init_db()
            return conn
        raise

def init_db():
    try:
        _do_init_db()
    except sqlite3.DatabaseError as e:
        if "malformed" in str(e).lower() or "disk image" in str(e).lower() or "corrupt" in str(e).lower():
            reset_corrupt_db()
            _do_init_db()
        else:
            raise

def _do_init_db():
    with sqlite3.connect(DB_PATH, timeout=20.0) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS protected_prefixes (
                id TEXT PRIMARY KEY,
                prefix TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                description TEXT,
                assigned_prefixes TEXT DEFAULT '["*"]',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS blocking_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                bandwidth_bps REAL NOT NULL,
                bandwidth_human TEXT NOT NULL,
                network_range TEXT NOT NULL,
                description TEXT,
                notification_sent INTEGER DEFAULT 0,
                notification_status TEXT,
                raw_data TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON blocking_logs (timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON blocking_logs (source_ip);
            CREATE INDEX IF NOT EXISTS idx_monitored_ip ON monitored_ips (ip_address);
        """)

        # Insert default settings if not exists
        default_settings = {
            "account_id": "",
            "api_id": "",
            "api_key": "",
            "smtp_host": "",
            "smtp_port": "587",
            "smtp_user": "",
            "smtp_pass": "",
            "smtp_encryption": "tls",  # tls, ssl, none
            "smtp_sender": "ddos-alerts@imperva-monitor.local",
            "smtp_recipients": "admin@example.com",
            "email_subject_template": "🚨 [DDoS Alert] Blocked Monitored IP Detected: {count} IP(s)",
            "email_body_template": """<h2>⚠️ DDoS Mitigation Alert: Monitored IP Blocked</h2>
<p>The DDoS Monitoring System has detected that one or more monitored IP addresses are actively being blocked under Imperva DDoS mitigation rules.</p>

<h3>Detected Block Event Details:</h3>
<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%; font-family: sans-serif; font-size: 14px;">
  <thead style="background-color: #f2f2f2;">
    <tr>
      <th style="text-align: left; padding: 8px;">Timestamp</th>
      <th style="text-align: left; padding: 8px;">Blocked Source IP</th>
      <th style="text-align: left; padding: 8px;">Description</th>
      <th style="text-align: left; padding: 8px;">Network Range</th>
      <th style="text-align: left; padding: 8px;">Peak Bandwidth</th>
    </tr>
  </thead>
  <tbody>
{event_rows}
  </tbody>
</table>

<p style="margin-top: 20px;"><strong>Imperva Account ID:</strong> {account_id}</p>
<p><strong>Total Blocked Monitored IPs in Cycle:</strong> {count}</p>
<p style="color: #666; font-size: 12px; margin-top: 25px;"><em>This is an automated notification from the DDoS IP Notification Tool.</em></p>""",
            "monitoring_interval_seconds": "60",
            "monitoring_enabled": "false",
            "cooldown_minutes": "15"
        }

        for k, v in default_settings.items():
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        conn.commit()

init_db()

def get_all_settings():
    with get_db() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

def save_settings(settings_dict):
    with get_db() as conn:
        for k, v in settings_dict.items():
            conn.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (k, str(v) if v is not None else ""))
        conn.commit()
    return get_all_settings()

# ----------------------------------------------------------------------
# Security & Password Utilities
# ----------------------------------------------------------------------

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000)
    return key.hex(), salt

def verify_password(password, stored_hash, salt):
    key, _ = hash_password(password, salt)
    return hmac.compare_digest(key, stored_hash)

def validate_password_rules(password):
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long."
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if not has_digit:
        return False, "Password must contain at least one number."
    if not has_special:
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, ""

def create_session():
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires = now + 7 * 24 * 3600  # 7 days
    with get_db() as conn:
        conn.execute("INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)", (token, now, expires))
        conn.commit()
    return token

def verify_session(token):
    if not token:
        return False
    now = time.time()
    with get_db() as conn:
        row = conn.execute("SELECT expires_at FROM sessions WHERE token = ?", (token,)).fetchone()
        if row and row["expires_at"] > now:
            return True
    return False

# ----------------------------------------------------------------------
# Imperva API Client & Bandwidth Formatter
# ----------------------------------------------------------------------

def format_bandwidth(bps):
    try:
        num = float(bps)
    except (ValueError, TypeError):
        return "0 bps"
    if num >= 1e9:
        return f"{num / 1e9:.2f} Gbps"
    elif num >= 1e6:
        return f"{num / 1e6:.2f} Mbps"
    elif num >= 1e3:
        return f"{num / 1e3:.2f} Kbps"
    return f"{num:.2f} bps"

def imperva_get_protected_networks(account_id=None, api_id=None, api_key=None):
    settings = get_all_settings()
    account_id = (account_id if account_id is not None and account_id != "" else settings.get("account_id", "")).strip()
    api_id = (api_id if api_id is not None and api_id != "" else settings.get("api_id", "")).strip()
    api_key = (api_key if api_key is not None and api_key != "" else settings.get("api_key", "")).strip()

    if not account_id or not api_id or not api_key:
        missing = []
        if not account_id: missing.append("Account ID")
        if not api_id: missing.append("API ID")
        if not api_key: missing.append("API Key")
        raise ValueError(f"Missing required credentials: {', '.join(missing)}.")

    url = f"https://my.imperva.com/api/v2/ddos-protection/account/{urllib.parse.quote(account_id)}/protected-networks-ids"
    req = urllib.request.Request(url, headers={
        "x-API-Id": api_id,
        "x-API-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Imperva-DDoS-Monitor/1.0"
    }, method="GET")

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as err:
        err_body_raw = err.read().decode('utf-8', errors='ignore')
        err_msg = ""
        try:
            err_json = json.loads(err_body_raw)
            err_msg = err_json.get("res_message") or err_json.get("message") or err_json.get("error_description") or err_json.get("debug_info", {}).get("id-info") or err_body_raw
        except Exception:
            err_msg = err_body_raw or err.reason

        if err.code == 401:
            raise ValueError(f"HTTP 401 Unauthorized: Invalid API ID ({api_id}) or API Key. Details: {err_msg}")
        elif err.code == 403:
            raise ValueError(f"HTTP 403 Forbidden: API key does not have permissions for DDoS Protected Networks, or account access is restricted. Details: {err_msg}")
        elif err.code == 404:
            raise ValueError(f"HTTP 404 Not Found: Account ID '{account_id}' does not exist or DDoS Protection is not enabled on this account. Details: {err_msg}")
        else:
            raise ValueError(f"Imperva API HTTP {err.code} Error: {err_msg}")
    except urllib.error.URLError as err:
        raise ValueError(f"Network Connection Error (Unable to reach my.imperva.com): {err.reason}")


def imperva_get_top_table_blocks(prefix, start_ms=None, end_ms=None, account_id=None, api_id=None, api_key=None):
    settings = get_all_settings()
    account_id = (account_id or settings.get("account_id", "")).strip()
    api_id = (api_id or settings.get("api_id", "")).strip()
    api_key = (api_key or settings.get("api_key", "")).strip()

    if not account_id or not api_id or not api_key:
        raise ValueError("Imperva API credentials are not configured.")

    now_ms = int(time.time() * 1000)
    end = end_ms or now_ms
    start = start_ms or (end - 15 * 60 * 1000)

    query_params = urllib.parse.urlencode({
        "account_id": account_id,
        "ip_range": prefix,
        "range_type": "BGP",
        "start": str(start),
        "end": str(end),
        "data_type": "SRC_IP",
        "metric_type": "BW",
        "mitigation_type": "BLOCK",
        "aggregation_type": "PEAK"
    })

    url = f"https://my.imperva.com/api/v1/infra/top-table?{query_params}"
    req = urllib.request.Request(url, data=b"", headers={
        "x-API-Id": api_id,
        "x-API-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Imperva-DDoS-Monitor/1.0"
    }, method="POST")

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as err:
        err_body_raw = err.read().decode('utf-8', errors='ignore')
        err_msg = ""
        try:
            err_json = json.loads(err_body_raw)
            err_msg = err_json.get("res_message") or err_json.get("message") or err_json.get("error_description") or err_body_raw
        except Exception:
            err_msg = err_body_raw or err.reason
        raise ValueError(f"Imperva top-table API HTTP {err.code}: {err_msg}")
    except urllib.error.URLError as err:
        raise ValueError(f"Network error reaching top-table API: {err.reason}")


# ----------------------------------------------------------------------
# SMTP Email Dispatcher & Templating
# ----------------------------------------------------------------------

def render_email_template(events, settings):
    count = len(events)
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    account_id = settings.get("account_id", "N/A")
    ip_list = ", ".join(e["source_ip"] for e in events)

    event_rows = ""
    for e in events:
        event_rows += f"""
        <tr>
          <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">{e.get("timestamp", timestamp)}</td>
          <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-weight: bold; color: #d32f2f;">{e.get("source_ip", "")}</td>
          <td style="padding: 8px; border: 1px solid #ddd;">{e.get("description", "N/A")}</td>
          <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">{e.get("network_range", "N/A")}</td>
          <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">{e.get("bandwidth_human", format_bandwidth(e.get("bandwidth_bps", 0)))}</td>
        </tr>"""

    full_table = f"""
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%; font-family: sans-serif; font-size: 14px;">
      <thead style="background-color: #f8f9fa;">
        <tr>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Timestamp</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Blocked Source IP</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Network Range</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Peak Bandwidth</th>
        </tr>
      </thead>
      <tbody>
        {event_rows}
      </tbody>
    </table>"""

    replacements = {
        "{count}": str(count),
        "{timestamp}": timestamp,
        "{account_id}": account_id,
        "{ip_list}": ip_list,
        "{event_rows}": event_rows,
        "{table}": full_table
    }

    subject = settings.get("email_subject_template", "🚨 [DDoS Alert] Blocked Monitored IP Detected: {count} IP(s)")
    body = settings.get("email_body_template", full_table)

    for k, v in replacements.items():
        subject = subject.replace(k, v)
        body = body.replace(k, v)

    return subject, body

def send_smtp_email(events, custom_settings=None, recipient_override=None, is_test=False):
    settings = custom_settings or get_all_settings()
    host = settings.get("smtp_host", "").strip()
    port = int(settings.get("smtp_port", "587").strip() or "587")
    user = settings.get("smtp_user", "").strip()
    password = settings.get("smtp_pass", "").strip()
    encryption = settings.get("smtp_encryption", "tls").lower().strip()
    sender = settings.get("smtp_sender", "ddos-alerts@imperva-monitor.local").strip()
    recipients_str = recipient_override or settings.get("smtp_recipients", "").strip()

    if not host:
        raise ValueError("SMTP Server host is not configured.")
    if not recipients_str:
        raise ValueError("No recipient email configured.")

    recipients = [r.strip() for r in recipients_str.split(",") if r.strip()]
    if not recipients:
        raise ValueError("Recipient list is empty.")

    subject, html_body = render_email_template(events, settings)
    if is_test:
        subject = f"[TEST] {subject}"
        html_body = f"""<div style="padding: 12px; margin-bottom: 15px; background: #e3f2fd; border-left: 4px solid #2196f3; font-family: sans-serif;">
            <strong>Test Email Notice:</strong> This is a test notification from the DDoS IP Notification Tool to confirm your SMTP configuration is operating properly.
        </div>{html_body}"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    text_fallback = f"DDoS Block Alert: {len(events)} IP(s) blocked.\n" + "\n".join([f"- {e.get('source_ip')} ({e.get('bandwidth_human')}) on {e.get('network_range')}" for e in events])
    msg.attach(MIMEText(text_fallback, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    if encryption == "ssl" or port == 465:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
            if user and password:
                server.login(user, password)
            server.sendmail(sender, recipients, msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            if encryption in ["tls", "starttls"]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server.starttls(context=context)
            if user and password:
                server.login(user, password)
            server.sendmail(sender, recipients, msg.as_string())

    return True

# ----------------------------------------------------------------------
# Background Monitoring Engine
# ----------------------------------------------------------------------

class DDoSMonitorWorker:
    def __init__(self):
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()
        self.is_checking = False
        self.last_check_time = None
        self.last_status = "Idle"
        self.last_error = None
        self.recent_alerts = {}  # ip -> timestamp

    def start(self):
        settings = get_all_settings()
        if settings.get("monitoring_enabled") != "true":
            self.last_status = "Stopped (Disabled in Settings)"
            return

        if self.running and self.thread and self.thread.is_alive():
            return

        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()
        self.last_status = "Running"
        print("[MonitorWorker] DDoS monitoring worker started.")

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.last_status = "Stopped"
        print("[MonitorWorker] DDoS monitoring worker stopped.")

    def restart(self):
        self.stop()
        time.sleep(0.5)
        self.start()

    def get_status_info(self):
        settings = get_all_settings()
        return {
            "running": self.running,
            "enabled": settings.get("monitoring_enabled") == "true",
            "interval_seconds": int(settings.get("monitoring_interval_seconds", "60") or "60"),
            "last_check_time": self.last_check_time,
            "last_check_status": self.last_status,
            "last_error": self.last_error,
            "is_checking": self.is_checking
        }

    def sync_prefixes_from_api(self):
        data = imperva_get_protected_networks()
        if not isinstance(data, dict):
            raise ValueError("Unexpected format from Imperva protected networks API.")

        with get_db() as conn:
            for pid, prefix in data.items():
                conn.execute("""
                    INSERT INTO protected_prefixes (id, prefix, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(id) DO UPDATE SET prefix=excluded.prefix, updated_at=CURRENT_TIMESTAMP
                """, (str(pid), str(prefix)))
            
            # Prune removed prefixes if any
            if data:
                placeholders = ",".join("?" for _ in data)
                conn.execute(f"DELETE FROM protected_prefixes WHERE id NOT IN ({placeholders})", list(data.keys()))
            conn.commit()

        print(f"[MonitorWorker] Synced {len(data)} protected prefixes from Imperva API.")
        return data

    def run_check_cycle(self, force=False):
        if self.is_checking:
            return
        settings = get_all_settings()
        if not force and settings.get("monitoring_enabled") != "true":
            return

        account_id = settings.get("account_id", "").strip()
        api_id = settings.get("api_id", "").strip()
        api_key = settings.get("api_key", "").strip()

        if not account_id or not api_id or not api_key:
            self.last_status = "Credentials Missing"
            self.last_error = "Imperva API credentials not configured in Admin Settings."
            return

        self.is_checking = True
        self.last_check_time = datetime.now(timezone.utc).isoformat()
        self.last_status = "Checking active prefixes..."
        self.last_error = None

        try:
            with get_db() as conn:
                prefixes = [dict(r) for r in conn.execute("SELECT id, prefix FROM protected_prefixes").fetchall()]
                if not prefixes:
                    try:
                        self.sync_prefixes_from_api()
                        prefixes = [dict(r) for r in conn.execute("SELECT id, prefix FROM protected_prefixes").fetchall()]
                    except Exception as e:
                        print(f"[MonitorWorker] Prefix sync error: {e}")

                monitored_rows = [dict(r) for r in conn.execute("SELECT id, ip_address, description, assigned_prefixes FROM monitored_ips").fetchall()]

            if not monitored_rows:
                self.last_status = "Healthy (No monitored IPs registered)"
                self.is_checking = False
                return

            ip_map = {}
            for r in monitored_rows:
                ip_clean = r["ip_address"].strip()
                try:
                    assigned = json.loads(r.get("assigned_prefixes") or '["*"]')
                except Exception:
                    assigned = ["*"]
                ip_map[ip_clean] = {
                    "id": r["id"],
                    "ip": ip_clean,
                    "description": r.get("description", ""),
                    "assigned": assigned
                }

            cooldown_seconds = int(settings.get("cooldown_minutes", "15") or "15") * 60
            now_time = time.time()
            detected_events = []

            for p in prefixes:
                p_id = str(p["id"])
                p_cidr = str(p["prefix"])

                # Check if any monitored IP matches this prefix
                has_relevant_ips = False
                for ip_info in ip_map.values():
                    if "*" in ip_info["assigned"] or p_id in ip_info["assigned"] or p_cidr in ip_info["assigned"]:
                        has_relevant_ips = True
                        break

                if not has_relevant_ips:
                    continue

                try:
                    top_table = imperva_get_top_table_blocks(p_cidr)
                    stats = top_table.get("stats", []) if isinstance(top_table, dict) else []

                    for item in stats:
                        blocked_ip = item.get("object", "").strip()
                        bw = float(item.get("value", 0))

                        if blocked_ip in ip_map:
                            ip_info = ip_map[blocked_ip]
                            if "*" in ip_info["assigned"] or p_id in ip_info["assigned"] or p_cidr in ip_info["assigned"]:
                                last_alert = self.recent_alerts.get(blocked_ip, 0)
                                is_cooling_down = (now_time - last_alert) < cooldown_seconds

                                event = {
                                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                                    "source_ip": blocked_ip,
                                    "bandwidth_bps": bw,
                                    "bandwidth_human": format_bandwidth(bw),
                                    "network_range": p_cidr,
                                    "description": ip_info["description"],
                                    "raw_data": json.dumps(item),
                                    "should_alert": not is_cooling_down,
                                    "status": "Cooldown Suppressed" if is_cooling_down else "Pending"
                                }
                                detected_events.append(event)

                                if not is_cooling_down:
                                    self.recent_alerts[blocked_ip] = now_time

                except Exception as prefix_err:
                    print(f"[MonitorWorker] Error querying prefix {p_cidr}: {prefix_err}")

            if detected_events:
                events_to_alert = [e for e in detected_events if e["should_alert"]]
                email_sent = False
                email_err_msg = ""

                if events_to_alert:
                    try:
                        send_smtp_email(events_to_alert, settings)
                        email_sent = True
                    except Exception as mail_err:
                        email_err_msg = str(mail_err)
                        print(f"[MonitorWorker] SMTP delivery error: {mail_err}")

                with get_db() as conn:
                    for ev in detected_events:
                        if ev["should_alert"]:
                            if email_sent:
                                ev["status"] = "Sent"
                                ev_sent_flag = 1
                            else:
                                ev["status"] = f"Failed ({email_err_msg})" if email_err_msg else "Failed"
                                ev_sent_flag = 0
                        else:
                            ev_sent_flag = 0

                        conn.execute("""
                            INSERT INTO blocking_logs 
                            (timestamp, source_ip, bandwidth_bps, bandwidth_human, network_range, description, notification_sent, notification_status, raw_data)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            ev["timestamp"],
                            ev["source_ip"],
                            ev["bandwidth_bps"],
                            ev["bandwidth_human"],
                            ev["network_range"],
                            ev["description"],
                            ev_sent_flag,
                            ev["status"],
                            ev["raw_data"]
                        ))
                    conn.commit()

                self.last_status = f"Alert Triggered ({len(detected_events)} blocked event(s) logged)"
            else:
                self.last_status = "Healthy (No blocked monitored IPs detected)"

        except Exception as e:
            self.last_error = str(e)
            self.last_status = f"Error: {e}"
            print(f"[MonitorWorker] Loop error: {e}")
        finally:
            self.is_checking = False

    def simulate_block(self, custom_events=None):
        settings = get_all_settings()
        with get_db() as conn:
            monitored = [dict(r) for r in conn.execute("SELECT ip_address, description FROM monitored_ips").fetchall()]
            prefixes = [dict(r) for r in conn.execute("SELECT prefix FROM protected_prefixes").fetchall()]

        if custom_events:
            events = custom_events
        elif monitored:
            prefix_val = prefixes[0]["prefix"] if prefixes else "142.198.93.0/24"
            events = []
            for idx, item in enumerate(monitored[:2]):
                bw = (idx + 1) * 35200000.0
                events.append({
                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "source_ip": item["ip_address"],
                    "bandwidth_bps": bw,
                    "bandwidth_human": format_bandwidth(bw),
                    "network_range": prefix_val,
                    "description": item.get("description") or "Monitored Asset",
                    "raw_data": json.dumps({"object": item["ip_address"], "value": bw, "simulated": True})
                })
        else:
            events = [{
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                "source_ip": "195.128.248.33",
                "bandwidth_bps": 61185365.33,
                "bandwidth_human": format_bandwidth(61185365.33),
                "network_range": "45.223.249.0/24",
                "description": "Critical Web Node",
                "raw_data": json.dumps({"object": "195.128.248.33", "value": 61185365.33, "simulated": True})
            }]

        email_sent = False
        email_err = None
        try:
            send_smtp_email(events, settings)
            email_sent = True
        except Exception as e:
            email_err = str(e)

        with get_db() as conn:
            for ev in events:
                status = "Sent" if email_sent else (f"Failed ({email_err})" if email_err else "Failed")
                conn.execute("""
                    INSERT INTO blocking_logs 
                    (timestamp, source_ip, bandwidth_bps, bandwidth_human, network_range, description, notification_sent, notification_status, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev["timestamp"],
                    ev["source_ip"],
                    ev["bandwidth_bps"],
                    ev["bandwidth_human"],
                    ev["network_range"],
                    ev["description"],
                    1 if email_sent else 0,
                    status,
                    ev.get("raw_data", "{}")
                ))
            conn.commit()

        return {"success": True, "events": events, "email_sent": email_sent, "email_error": email_err}

    def _worker_loop(self):
        time.sleep(2)
        while self.running and not self.stop_event.is_set():
            try:
                self.run_check_cycle()
            except Exception as e:
                print(f"[MonitorWorker] Unhandled loop error: {e}")

            settings = get_all_settings()
            interval = max(10, int(settings.get("monitoring_interval_seconds", "60") or "60"))
            self.stop_event.wait(interval)

monitor_worker = DDoSMonitorWorker()

# ----------------------------------------------------------------------
# HTTP Request Handler & REST API
# ----------------------------------------------------------------------

class DDoSRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message, status=400):
        self._send_json({"error": message, "success": False}, status=status)

    def _read_json_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length).decode('utf-8')
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _get_auth_token(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:].strip()
        return None

    def _require_auth(self):
        token = self._get_auth_token()
        if not verify_session(token):
            self._send_error("Unauthorized: Session expired or invalid.", status=401)
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.end_headers()

    def do_GET(self):
        try:
            self._handle_do_GET()
        except Exception as e:
            if self.path.startswith('/api/'):
                return self._send_error(f"Internal server error: {e}", status=500)
            raise

    def _handle_do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Health
        if path == '/api/health':
            return self._send_json({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})

        # Auth status
        if path == '/api/auth/status':
            with get_db() as conn:
                admin_row = conn.execute("SELECT id FROM admin WHERE id = 1").fetchone()
            is_setup = admin_row is not None
            is_authenticated = verify_session(self._get_auth_token())
            return self._send_json({"is_setup": is_setup, "authenticated": is_authenticated})

        # Protected routes below
        if path.startswith('/api/'):
            if not self._require_auth():
                return

        # Settings
        if path == '/api/settings':
            settings = get_all_settings()
            safe_settings = {k: v for k, v in settings.items()}
            safe_settings["has_smtp_pass"] = bool(settings.get("smtp_pass"))
            safe_settings["has_api_key"] = bool(settings.get("api_key"))
            # Mask sensitive values in read payload
            return self._send_json(safe_settings)

        # Prefixes
        if path == '/api/prefixes':
            with get_db() as conn:
                prefixes = [dict(r) for r in conn.execute("SELECT id, prefix, updated_at FROM protected_prefixes ORDER BY prefix ASC").fetchall()]
            return self._send_json({"prefixes": prefixes, "total": len(prefixes)})

        # Monitored IPs
        if path == '/api/ips':
            search = query.get('search', [''])[0].strip()
            with get_db() as conn:
                if search:
                    q = "%" + search + "%"
                    rows = conn.execute("SELECT * FROM monitored_ips WHERE ip_address LIKE ? OR description LIKE ? ORDER BY created_at DESC", (q, q)).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM monitored_ips ORDER BY created_at DESC").fetchall()
            
            ips = []
            for r in rows:
                item = dict(r)
                try:
                    item["assigned_prefixes"] = json.loads(item.get("assigned_prefixes") or '["*"]')
                except Exception:
                    item["assigned_prefixes"] = ["*"]
                ips.append(item)
            return self._send_json({"ips": ips, "total": len(ips)})

        # Export IPs CSV
        if path == '/api/ips/export-csv':
            with get_db() as conn:
                rows = conn.execute("SELECT ip_address, description, assigned_prefixes, created_at FROM monitored_ips ORDER BY ip_address ASC").fetchall()
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['IP Address', 'Description', 'Assigned Prefixes', 'Date Added'])
            for r in rows:
                try:
                    p = ";".join(json.loads(r["assigned_prefixes"] or '["*"]'))
                except Exception:
                    p = "*"
                writer.writerow([r["ip_address"], r["description"] or "", p, r["created_at"]])

            csv_bytes = output.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="monitored_ips.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        # Logs
        if path == '/api/logs':
            ip = query.get('ip', [''])[0].strip()
            network_range = query.get('network_range', [''])[0].strip()
            status = query.get('status', [''])[0].strip()
            limit = min(500, max(1, int(query.get('limit', ['100'])[0])))
            page = max(1, int(query.get('page', ['1'])[0]))
            offset = (page - 1) * limit

            sql = "SELECT * FROM blocking_logs WHERE 1=1"
            count_sql = "SELECT COUNT(*) as total FROM blocking_logs WHERE 1=1"
            params = []

            if ip:
                sql += " AND source_ip LIKE ?"
                count_sql += " AND source_ip LIKE ?"
                params.append(f"%{ip}%")
            if network_range:
                sql += " AND network_range LIKE ?"
                count_sql += " AND network_range LIKE ?"
                params.append(f"%{network_range}%")
            if status:
                sql += " AND notification_status LIKE ?"
                count_sql += " AND notification_status LIKE ?"
                params.append(f"%{status}%")

            with get_db() as conn:
                total = conn.execute(count_sql, params).fetchone()["total"]
                sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                rows = [dict(r) for r in conn.execute(sql, params + [limit, offset]).fetchall()]

            return self._send_json({
                "logs": rows,
                "pagination": {
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "total_pages": max(1, (total + limit - 1) // limit)
                }
            })

        # Logs KPI stats
        if path == '/api/logs/stats':
            with get_db() as conn:
                total_events = conn.execute("SELECT COUNT(*) as c FROM blocking_logs").fetchone()["c"]
                unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) as c FROM blocking_logs").fetchone()["c"]
                emails_sent = conn.execute("SELECT COUNT(*) as c FROM blocking_logs WHERE notification_sent = 1").fetchone()["c"]
                latest = conn.execute("SELECT timestamp, source_ip, network_range, bandwidth_human FROM blocking_logs ORDER BY timestamp DESC LIMIT 1").fetchone()
                peak_row = conn.execute("SELECT bandwidth_human FROM blocking_logs ORDER BY bandwidth_bps DESC LIMIT 1").fetchone()

            return self._send_json({
                "total_events": total_events,
                "unique_ips": unique_ips,
                "emails_sent": emails_sent,
                "latest_event": dict(latest) if latest else None,
                "peak_bandwidth": peak_row["bandwidth_human"] if peak_row else "0 bps"
            })

        # Export Logs CSV
        if path == '/api/logs/export-csv':
            with get_db() as conn:
                rows = conn.execute("SELECT timestamp, source_ip, description, network_range, bandwidth_bps, bandwidth_human, notification_status FROM blocking_logs ORDER BY timestamp DESC").fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Timestamp', 'Blocked Source IP', 'Description', 'Network Range', 'Bandwidth (bps)', 'Bandwidth (Formatted)', 'Notification Status'])
            for r in rows:
                writer.writerow([r["timestamp"], r["source_ip"], r["description"] or "", r["network_range"], r["bandwidth_bps"], r["bandwidth_human"], r["notification_status"]])

            csv_bytes = output.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="blocking_events.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        # Monitor status
        if path == '/api/monitor/status':
            return self._send_json(monitor_worker.get_status_info())

        # Fallback to static files
        return super().do_GET()

    def do_POST(self):
        try:
            self._handle_do_POST()
        except Exception as e:
            return self._send_error(f"Internal server error: {e}", status=500)

    def _handle_do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        path = parsed.path

        # Setup (First time password creation)
        if path == '/api/auth/setup':
            with get_db() as conn:
                admin_exists = conn.execute("SELECT id FROM admin WHERE id = 1").fetchone()
            if admin_exists:
                return self._send_error("Admin account already configured. Please log in.")

            body = self._read_json_body()
            pwd = body.get("password", "")
            confirm = body.get("confirmPassword", "")

            if pwd != confirm:
                return self._send_error("Passwords do not match.")

            valid, err_msg = validate_password_rules(pwd)
            if not valid:
                return self._send_error(err_msg)

            pwd_hash, salt = hash_password(pwd)
            with get_db() as conn:
                conn.execute("INSERT INTO admin (id, password_hash, salt, created_at, updated_at) VALUES (1, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", (pwd_hash, salt))
                conn.commit()

            token = create_session()
            return self._send_json({"success": True, "message": "Admin password successfully created.", "token": token})

        # Login
        if path == '/api/auth/login':
            body = self._read_json_body()
            pwd = body.get("password", "")
            with get_db() as conn:
                admin_row = conn.execute("SELECT password_hash, salt FROM admin WHERE id = 1").fetchone()

            if not admin_row:
                return self._send_error("Admin user not yet configured. Please complete initial setup.")

            if not verify_password(pwd, admin_row["password_hash"], admin_row["salt"]):
                return self._send_error("Invalid password. Please try again.", status=401)

            token = create_session()
            return self._send_json({"success": True, "message": "Login successful.", "token": token})

        # All subsequent POST endpoints require authentication
        if not self._require_auth():
            return

        # Change Password
        if path == '/api/auth/change-password':
            body = self._read_json_body()
            curr_pwd = body.get("currentPassword", "")
            new_pwd = body.get("newPassword", "")
            confirm_pwd = body.get("confirmPassword", "")

            if new_pwd != confirm_pwd:
                return self._send_error("New passwords do not match.")

            valid, err_msg = validate_password_rules(new_pwd)
            if not valid:
                return self._send_error(err_msg)

            with get_db() as conn:
                admin_row = conn.execute("SELECT password_hash, salt FROM admin WHERE id = 1").fetchone()
                if not verify_password(curr_pwd, admin_row["password_hash"], admin_row["salt"]):
                    return self._send_error("Current password is incorrect.")

                new_hash, new_salt = hash_password(new_pwd)
                conn.execute("UPDATE admin SET password_hash = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1", (new_hash, new_salt))
                conn.commit()

            return self._send_json({"success": True, "message": "Password changed successfully."})

        # Test Imperva credentials
        if path == '/api/settings/test-credentials':
            body = self._read_json_body()
            saved_settings = get_all_settings()
            
            account_id = body.get("account_id") if body.get("account_id") else saved_settings.get("account_id", "")
            api_id = body.get("api_id") if body.get("api_id") else saved_settings.get("api_id", "")
            api_key = body.get("api_key") if body.get("api_key") else saved_settings.get("api_key", "")

            try:
                data = imperva_get_protected_networks(
                    account_id=account_id,
                    api_id=api_id,
                    api_key=api_key
                )
                count = len(data) if isinstance(data, dict) else 0
                return self._send_json({
                    "success": True,
                    "message": f"Connection successful! Verified access to {count} protected network prefix(es) via GET https://my.imperva.com/api/v2/ddos-protection/account/{account_id}/protected-networks-ids",
                    "prefixes": data
                })
            except Exception as e:
                return self._send_error(f"{e} (Target API: GET https://my.imperva.com/api/v2/ddos-protection/account/{account_id or '{account_id}'}/protected-networks-ids)")


        # Test SMTP Email
        if path == '/api/settings/test-email':
            body = self._read_json_body()
            try:
                current_settings = get_all_settings()
                merged = {**current_settings, **body}
                if not body.get("smtp_pass") and current_settings.get("smtp_pass"):
                    merged["smtp_pass"] = current_settings["smtp_pass"]

                dummy_event = [{
                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "source_ip": "198.51.100.42",
                    "description": "Test Monitored Node",
                    "network_range": "198.51.100.0/24",
                    "bandwidth_bps": 45000000.0,
                    "bandwidth_human": "45.00 Mbps"
                }]

                send_smtp_email(dummy_event, custom_settings=merged, recipient_override=body.get("recipientEmail"), is_test=True)
                return self._send_json({"success": True, "message": "Test email sent successfully! Please check your inbox."})
            except Exception as e:
                return self._send_error(f"Failed to dispatch test email: {e}")

        # Save Settings
        if path == '/api/settings':
            body = self._read_json_body()
            current = get_all_settings()
            updates = {k: v for k, v in body.items() if k != "token"}

            # Retain existing password if blank
            if updates.get("smtp_pass") == "" and current.get("smtp_pass") and updates.get("keep_existing_smtp_pass"):
                del updates["smtp_pass"]
            updates.pop("keep_existing_smtp_pass", None)

            saved = save_settings(updates)
            if updates.get("monitoring_enabled") == "true":
                monitor_worker.restart()
            elif updates.get("monitoring_enabled") == "false":
                monitor_worker.stop()

            return self._send_json({"success": True, "message": "Settings saved successfully.", "settings": saved})

        # Sync Prefixes
        if path == '/api/prefixes/sync':
            try:
                data = monitor_worker.sync_prefixes_from_api()
                with get_db() as conn:
                    prefixes = [dict(r) for r in conn.execute("SELECT id, prefix, updated_at FROM protected_prefixes ORDER BY prefix ASC").fetchall()]
                return self._send_json({"success": True, "message": f"Synchronized {len(prefixes)} prefix(es).", "prefixes": prefixes, "count": len(prefixes)})
            except Exception as e:
                return self._send_error(f"Sync failed: {e}")

        # Add Monitored IP
        if path == '/api/ips':
            body = self._read_json_body()
            ip = (body.get("ip_address") or "").strip()
            desc = (body.get("description") or "").strip()
            prefixes = body.get("assigned_prefixes") or ["*"]

            if not ip:
                return self._send_error("IP address is required.")

            try:
                with get_db() as conn:
                    cursor = conn.execute("""
                        INSERT INTO monitored_ips (ip_address, description, assigned_prefixes, created_at, updated_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """, (ip, desc, json.dumps(prefixes)))
                    conn.commit()
                    row_id = cursor.lastrowid
                    row = dict(conn.execute("SELECT * FROM monitored_ips WHERE id = ?", (row_id,)).fetchone())
                    row["assigned_prefixes"] = json.loads(row.get("assigned_prefixes") or '["*"]')
                return self._send_json({"success": True, "message": "Monitored IP added.", "ip": row})
            except sqlite3.IntegrityError:
                return self._send_error(f"IP {ip} is already registered in the monitoring list.")
            except Exception as e:
                return self._send_error(f"Failed to add IP: {e}")

        # Import CSV
        if path == '/api/ips/import-csv':
            body = self._read_json_body()
            csv_text = body.get("csv_text", "")
            if not csv_text.strip():
                return self._send_error("CSV content is empty.")

            reader = csv.reader(io.StringIO(csv_text))
            rows = list(reader)
            if not rows:
                return self._send_error("CSV contains no rows.")

            start_idx = 0
            if rows[0] and ("ip" in rows[0][0].lower() or "address" in rows[0][0].lower()):
                start_idx = 1

            added = 0
            errors = []
            with get_db() as conn:
                for idx, row in enumerate(rows[start_idx:], start=start_idx + 1):
                    if not row or not row[0].strip():
                        continue
                    ip = row[0].strip()
                    desc = row[1].strip() if len(row) > 1 else ""
                    prefixes = ["*"]
                    if len(row) > 2 and row[2].strip():
                        prefixes = [p.strip() for p in row[2].split(";") if p.strip()] or ["*"]

                    try:
                        conn.execute("""
                            INSERT INTO monitored_ips (ip_address, description, assigned_prefixes, created_at, updated_at)
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            ON CONFLICT(ip_address) DO UPDATE SET
                                description = excluded.description,
                                assigned_prefixes = CASE WHEN excluded.assigned_prefixes != '["*"]' THEN excluded.assigned_prefixes ELSE monitored_ips.assigned_prefixes END,
                                updated_at = CURRENT_TIMESTAMP
                        """, (ip, desc, json.dumps(prefixes)))
                        added += 1
                    except Exception as row_err:
                        errors.append(f"Row {idx} ({ip}): {row_err}")
                conn.commit()

            return self._send_json({
                "success": True,
                "message": f"Successfully processed {added} IP(s).",
                "imported_count": added,
                "errors": errors
            })

        # Monitor Controls
        if path == '/api/monitor/toggle':
            body = self._read_json_body()
            enabled = bool(body.get("enabled"))
            save_settings({"monitoring_enabled": "true" if enabled else "false"})
            if enabled:
                monitor_worker.start()
            else:
                monitor_worker.stop()
            return self._send_json({"success": True, "status": monitor_worker.get_status_info()})

        if path == '/api/monitor/check-now':
            threading.Thread(target=monitor_worker.run_check_cycle, kwargs={"force": True}, daemon=True).start()
            return self._send_json({"success": True, "message": "Manual check initiated."})

        if path == '/api/monitor/simulate':
            body = self._read_json_body()
            result = monitor_worker.simulate_block(body.get("custom_events"))
            return self._send_json({"success": True, "result": result})

        self._send_error(f"Endpoint {path} not found.", status=404)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if not self._require_auth():
            return

        if path.startswith('/api/ips/'):
            try:
                ip_id = int(path.split('/')[-1])
            except ValueError:
                return self._send_error("Invalid IP ID.")

            body = self._read_json_body()
            ip = (body.get("ip_address") or "").strip()
            desc = (body.get("description") or "").strip()
            prefixes = body.get("assigned_prefixes") or ["*"]

            if not ip:
                return self._send_error("IP address cannot be blank.")

            try:
                with get_db() as conn:
                    conn.execute("""
                        UPDATE monitored_ips
                        SET ip_address = ?, description = ?, assigned_prefixes = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (ip, desc, json.dumps(prefixes), ip_id))
                    conn.commit()
                    row = conn.execute("SELECT * FROM monitored_ips WHERE id = ?", (ip_id,)).fetchone()
                    if not row:
                        return self._send_error("IP record not found.", status=404)
                    item = dict(row)
                    item["assigned_prefixes"] = json.loads(item.get("assigned_prefixes") or '["*"]')
                return self._send_json({"success": True, "message": "Monitored IP updated.", "ip": item})
            except sqlite3.IntegrityError:
                return self._send_error(f"IP {ip} is already assigned to another entry.")
            except Exception as e:
                return self._send_error(f"Failed to update IP: {e}")

        self._send_error(f"Endpoint {path} not found.", status=404)

    def do_DELETE(self):
        try:
            self._handle_do_DELETE()
        except Exception as e:
            return self._send_error(f"Internal server error: {e}", status=500)

    def _handle_do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)

        path = parsed.path

        if not self._require_auth():
            return

        if path.startswith('/api/ips/'):
            try:
                ip_id = int(path.split('/')[-1])
            except ValueError:
                return self._send_error("Invalid IP ID.")

            with get_db() as conn:
                conn.execute("DELETE FROM monitored_ips WHERE id = ?", (ip_id,))
                conn.commit()
            return self._send_json({"success": True, "message": "Monitored IP removed."})

        if path == '/api/logs':
            with get_db() as conn:
                conn.execute("DELETE FROM blocking_logs")
                conn.commit()
            return self._send_json({"success": True, "message": "All blocking event logs cleared."})

        self._send_error(f"Endpoint {path} not found.", status=404)

def run_server(port=5001):
    server_address = ('0.0.0.0', port)
    httpd = http.server.ThreadingHTTPServer(server_address, DDoSRequestHandler)
    print(f"🚀 DDoS Notification Server running on http://localhost:{port}")
    try:
        monitor_worker.start()
    except Exception as e:
        print(f"[MonitorWorker] Startup error: {e}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        monitor_worker.stop()
        httpd.shutdown()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    run_server(port)
