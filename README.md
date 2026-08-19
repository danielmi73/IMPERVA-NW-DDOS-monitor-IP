# 🛡️ DDoS IP Monitoring & Mitigation Notification Tool

An enterprise-grade web application for monitoring **Imperva / Incapsula DDoS Protected Networks**, detecting when monitored IP addresses are actively blocked under DDoS mitigation rules, recording persistent audit logs, and dispatching consolidated email alerts via SMTP.

---

## 🚀 Key Features

1. **First-Time Setup & Secure Authentication**:
   - Initial admin password configuration enforcing security policies (minimum 6 characters, at least one digit, and at least one special character).
   - PBKDF2-HMAC-SHA256 password hashing with unique per-user salts.
   - Secure token session authentication and password change capabilities.

2. **Admin Configuration**:
   - **Account API**: Configure Imperva Account ID, API ID (`x-API-Id`), and API Key (`x-API-Key`) with interactive **"Test Credentials"** verification.
   - **Email & SMTP Alert Settings**: Configure SMTP Host, Port, Encryption (TLS / SSL / None), Username, Password, Sender address, and Recipient list.
   - **Customizable Email Template**: Built-in template editor with dynamic tag placeholders (`{count}`, `{account_id}`, `{timestamp}`, `{event_rows}`, `{ip_list}`, `{table}`).
   - **"Send Test Email"** functionality to verify mail delivery.
   - **Monitoring Interval**: Configurable polling interval (seconds) and alert cooldown window (minutes) to prevent alert storming.

3. **IP Mapping & Protected Prefixes**:
   - Automatic and manual synchronization of protected network prefixes from Imperva API:
     `GET https://my.imperva.com/api/v2/ddos-protection/account/{account_id}/protected-networks-ids`
   - IP management (Add, Update, Remove) with Description.
   - Multi-prefix mapping (assign an IP to specific BGP prefixes or `"All Prefixes (*)"`).
   - Bulk CSV Import (`IP, Description` or `IP, Description, Prefixes`) and CSV Export.

4. **Periodic DDoS Monitoring Engine**:
   - Autonomous background scheduler querying:
     `POST https://my.imperva.com/api/v1/infra/top-table?account_id={account_id}&ip_range={prefix}&range_type=BGP&data_type=SRC_IP&metric_type=BW&mitigation_type=BLOCK&aggregation_type=PEAK`
   - Detects when source IPs from your monitored list appear in the blocked statistics.
   - **Batched Notification**: If multiple monitored IPs are blocked in a single cycle, consolidates them into a single email alert.

5. **Blocking Event Logs**:
   - Complete audit trail of all blocking events with Timestamp, Blocked Source IP, Description, Network Range, Peak Bandwidth (formatted Gbps / Mbps), and Notification Status.
   - Instant search and filtering by IP, Network Range, Date, and Notification status.
   - Export logs to CSV.
   - **Simulate Block Event**: Built-in testing trigger to simulate DDoS attack block events and verify end-to-end alerting on demand.

---

## 📦 Getting Started

### Requirements
- **Python 3.9+** (Standard library only — zero external packages or dependencies required).

### Running the Application

#### Option 1: Using Docker / OrbStack (Recommended)
```bash
docker compose up -d --build
```

#### Option 3: Deploy to AWS (`il-central-1`) with CloudFront & ELB

Provision AWS infrastructure using Terraform in `terraform/`:

1. Copy the example variable file and fill in your organizational tags:
   ```bash
   cp terraform/terraform.tfvars.example terraform/terraform.tfvars
   ```
2. Run deployment:
   ```bash
   cd terraform
   terraform init
   terraform apply
   ```

> 🔒 **Tagging & Privacy Note**: To protect privacy and prevent committing organization-specific metadata, default values for tagging variables (`tag_name`, `tag_owner_email`, `tag_manager_email`, `tag_team_email`, `tag_description`, `tag_environment`, `tag_dataclassification`) are kept **empty** in `variables.tf`. Please specify your custom tags in `terraform/terraform.tfvars`.

By default, local servers listen on **`http://localhost:5001`**. (To specify a custom port with Python directly, run `python3 server.py <port>`, e.g., `python3 server.py 8080`).

Open your browser to:
👉 **`http://localhost:5001`**


---

## 🛠️ Application Structure

```
.
├── server.py             # Standalone Python backend (REST API, SQLite DB, Worker, SMTP)
├── public/               # Frontend Single Page Web Application
│   ├── index.html        # Main HTML entrypoint
│   ├── style.css         # Custom enterprise Vanilla CSS design system
│   └── app.js            # Frontend application logic and UI interactions
├── data/                 # Persistent SQLite database storage
│   └── ddos_monitor.db   # Settings, prefixes, monitored IPs, and logs
└── tests/                # Test suite
    ├── test_server.py    # Unit tests for core algorithms and formatters
    └── test_handler.py   # Unit tests for DB, auth rules, CSV, and templating
```

---

## 🧪 Running Automated Tests

Run the test suites with:

```bash
python3 tests/test_server.py
python3 tests/test_handler.py
```
