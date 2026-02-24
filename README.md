<p align="center">
  <img src="screenshots/logo.png" alt="Poirot DSPM" width="380">
</p>

<h1 align="center">Poirot DSPM</h1>

<p align="center">
  <strong>Data Security Posture Management</strong><br>
  Detect, classify and manage sensitive data across your data sources.
</p>

<p align="center">
  <a href="https://www.loom.com/share/410cab64f9084212aff7911729f8896b">
    <img src="https://cdn.loom.com/sessions/thumbnails/410cab64f9084212aff7911729f8896b-0d94a39cb9200ceb-full-play.gif#t=0.1" alt="Demo" width="400">
  </a>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python"></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/docker-compose-blue.svg" alt="Docker"></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-15-black.svg" alt="Next.js"></a>
  <a href="https://thehive-project.org/"><img src="https://img.shields.io/badge/TheHive-5.0-orange.svg" alt="TheHive"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
</p>

> Blog: [La Batalla Perdida de la Clasificacion de la Informacion](https://blog.santiagoagustinfernandez.com/la-batalla-perdida-de-la-clasificacion-de-la-informacion)

---

## What is Poirot?

Poirot scans data sources looking for **sensitive information** (credit cards, credentials, PII) using configurable regex patterns. It classifies findings by severity, deduplicates by location, and can automatically create cases in **TheHive** for case management.

The project includes a MySQL database and an S3 bucket (via LocalStack) as **demo sources** to showcase the functionality. It also supports **Google Drive** and **OneDrive** as real data sources.

### Pipeline

![Architecture](screenshots/arquitectura.png)

```
Data Sources --> Hawk-Eye Scanner (regex) --> Severity Classification --> Deduplication (hash/SQLite) --> TheHive (cases)
```

### Features

- Scan data sources with configurable regex patterns (MySQL, S3, Google Drive, OneDrive)
- Classify findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Deduplicate by location hash (same table+column+pattern = 1 alert)
- Detect re-occurrences: if a resolved finding reappears, it gets reopened
- Web dashboard with KPIs, charts, filters and export
- CRUD for patterns and sources from the UI
- Automatic case creation in TheHive
- Notifications via SMTP, Slack, Teams or Webhook
- AI-powered HTML email reports via Ollama (optional)

---

## Stack

| Component | Technology | Port |
|---|---|---|
| Scanner | Python 3.11 + [hawk_scanner](https://github.com/rohitcoder/hawk-eye) | - |
| Dashboard | Next.js + shadcn/ui + Tailwind | `:8080` |
| API | Flask | Internal |
| Case Management | TheHive 5.0 (optional) | `:9000` |
| Tracking | SQLite | - |
| AI Reports | Ollama (optional) | `:11434` |
| *Demo:* Database | MySQL 8.0 | `:3306` |
| *Demo:* Object Storage | LocalStack S3 | `:4566` |

---

## Installation

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Python 3.11+ (to generate test data)

### Standalone Mode (without TheHive)

```bash
git clone https://github.com/safernandez666/poirot.git
cd poirot

# Start services
docker compose up -d

# Generate test data in MySQL and S3
pip3 install pymysql boto3
python3 generar_datos.py

# Run the first scan
docker exec hawk-scanner python3 run_hawk_scanner.py
```

Dashboard: **http://localhost:8080**

### With TheHive

Includes Cassandra + Elasticsearch + TheHive for case management:

```bash
# Enable TheHive in docker-compose.yml:
#   THEHIVE_ENABLED=true (for hawk-scanner and dashboard)

# Start with the thehive profile
docker compose --profile thehive up -d

# Generate data and scan
pip3 install pymysql boto3
python3 generar_datos.py
docker exec hawk-scanner python3 run_hawk_scanner.py
```

Dashboard: **http://localhost:8080** | TheHive: **http://localhost:9000**

#### Configure TheHive API Key

TheHive requires an API key for the scanner to create cases. After TheHive is healthy:

1. Go to http://localhost:9000 (user: `admin@thehive.local` / pass: `secret`)
2. Create organization "poirot"
3. Create user `poirot@thehive.local` with **org-admin** profile
4. Generate an API Key for that user
5. In the dashboard go to **Settings** > **TheHive**, enable it and paste the API Key
6. Test with the **Connect** button

You can also configure via env vars in `docker-compose.yml`:
```yaml
THEHIVE_ENABLED=true
THEHIVE_API_KEY=your-api-key
```

---

## Notifications Configuration

Poirot supports notifications via **SMTP (Email)**, **Slack**, **Microsoft Teams**, and **Webhook**. Configure them in the dashboard at **Settings → Notifications**.

### SMTP (Email)

Send scan reports via email with AI-powered HTML analysis (requires Ollama).

**Setup:**
1. Go to **Settings → Notifications → SMTP**
2. Enable the channel and configure:
   - **Host**: Your SMTP server (e.g., `smtp.gmail.com`)
   - **Port**: Usually `587` (TLS) or `465` (SSL)
   - **Username**: Your email address
   - **Password**: Your email password or app-specific password
   - **From Address**: Sender email
   - **From Name**: Display name (e.g., "Poirot Security")
   - **To Addresses**: Comma-separated recipient emails
   - **Severity Filter**: Which severities trigger notifications

> **Tip:** For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833) instead of your regular password.

### Slack

Send alerts to a Slack channel with rich formatting and AI analysis.

**Setup:**
1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App**
2. Select **From scratch**, name it "Poirot DSPM"
3. Go to **Incoming Webhooks** → Toggle **On** → **Add New Webhook to Workspace**
4. Select the channel for notifications
5. Copy the Webhook URL
6. In Poirot dashboard, go to **Settings → Notifications → Slack**
7. Enable and paste the Webhook URL

### Microsoft Teams

Send alerts to a Teams channel with cards and AI analysis.

**Setup:**
1. In Teams, go to the channel → **...** (more options) → **Connectors**
2. Search for **"Incoming Webhook"** → **Configure**
3. Name: `Poirot DSPM`, optionally upload a logo
4. Click **Create** and copy the Webhook URL
5. In Poirot dashboard, go to **Settings → Notifications → Teams**
6. Enable and paste the Webhook URL

### Webhook (Generic)

Send scan results to any custom endpoint.

**Setup:**
1. Go to **Settings → Notifications → Webhook**
2. Enable and configure:
   - **URL**: Your endpoint URL
   - **Method**: HTTP method (POST, PUT, etc.)
   - **Headers**: Custom headers (e.g., `Authorization`, `X-API-Key`)

**Payload example:**
```json
{
  "source": "poirot-dspm",
  "event": "scan_complete",
  "summary": {
    "total_findings": 20,
    "by_severity": {"CRITICAL": 2, "HIGH": 6, ...},
    "by_source": {"mysql": 9, "s3": 11}
  },
  "new_alerts_count": 5
}
```

---

## AI-Powered Reports (Ollama)

Enable AI-generated analysis and recommendations in email and chat notifications.

**Setup:**
1. Ensure Ollama is running (included in `docker-compose.yml`)
2. Go to **Settings → Ollama**
3. Enable and configure:
   - **URL**: `http://host.docker.internal:11434` (default)
   - **Model**: `llama3.2:3b` or any installed model
4. Test the connection with the **Test** button

**Features:**
- 📧 HTML email reports with professional formatting
- 🔍 Security analysis of findings (3-4 sentences)
- 💡 Actionable recommendations (bullet points)
- 💬 Rich Slack/Teams messages with emojis

---

## Dashboard

The dashboard has 7 sections:

| Page | Description |
|---|---|
| **Dashboard** | KPIs, severity and source charts, recent alerts, "Scan Now" button |
| **Alerts** | Table with severity/status filters, search, CSV/JSON export |
| **Patterns** | Regex pattern CRUD, regex visualizer and validator |
| **Timeline** | Detection chart by day |
| **Sources** | Data source CRUD, connectivity health check |
| **Cases** | TheHive cases, alert sync |
| **Settings** | Notification channels (SMTP, Slack, Teams, Webhook, TheHive), AI (Ollama) config |

---

## Patterns

Patterns are defined in `hawk-scanner/fingerprint.yml` or from the UI:

```yaml
"Credit Card - Visa":
  regex: '\b4[0-9]{12}(?:[0-9]{3})?\b'
  category: PCI
  severity: CRITICAL

"AWS Access Key":
  regex: '\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'
  category: CREDENTIALS
  severity: HIGH
```

Included patterns:

| Category | Patterns | Severity |
|---|---|---|
| **Payment Cards** | Visa, Mastercard, Amex, Discover | CRITICAL |
| **Credentials** | AWS Secret Key, Private Keys | CRITICAL |
| **PII/Access** | SSN, AWS Access Key, Passwords, API Keys, JWT, URLs with credentials | HIGH |
| **Contact** | Email, US/International Phone, Private IP, IBAN | MEDIUM |
| **Crypto** | Bitcoin Address | LOW |

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/stats` | GET | Dashboard KPIs |
| `/api/alerts` | GET | Alerts with filters (`severity`, `status`, `source`) |
| `/api/alerts/export` | GET | Export alerts (`format=csv\|json`) |
| `/api/config/patterns` | GET/POST | List/add patterns |
| `/api/config/patterns/<name>` | PUT/DELETE | Edit/delete pattern |
| `/api/config/sources` | GET/POST | List/add sources |
| `/api/config/sources/<type>/<name>` | DELETE | Delete source |
| `/api/config/sources/health` | GET | Source connectivity check |
| `/api/config/notifications` | GET | Notification channels |
| `/api/config/notifications/<channel>` | PUT | Update channel |
| `/api/config/notifications/<channel>/test` | POST | Send test notification |
| `/api/validate-regex` | POST | Validate regex against text |
| `/api/scanner/run` | POST | Trigger scan |
| `/api/scanner/status` | GET | Scan status |
| `/api/config/ollama` | GET/PUT | Ollama AI config |
| `/api/ollama/models` | POST | List available Ollama models |
| `/api/thehive/status` | GET | TheHive connection |
| `/api/thehive/cases` | GET | List cases |
| `/api/thehive/sync` | POST | Sync pending alerts |

---

## Local Development

To iterate on the dashboard without Docker rebuild:

```bash
# Terminal 1: Flask API
pip3 install flask flask-cors pyyaml requests
python3 dashboard/dev.py

# Terminal 2: Next.js Frontend
cd dashboard/frontend-next
npm install
npm run dev
```

API at http://localhost:5001 | Frontend at http://localhost:3000

---

## Project Structure

```
.
├── docker-compose.yml              # Orchestration
├── Dockerfile                      # Scanner image
├── generar_datos.py                # Test data generator
│
├── hawk-scanner/                   # Scan engine
│   ├── run_hawk_scanner.py         # Main script (dynamic source detection)
│   ├── alert_manager.py            # Tracking & deduplication (SQLite)
│   ├── severity_classifier.py      # Severity from fingerprint.yml
│   ├── notification_manager.py     # SMTP, Slack, Teams, Webhook, TheHive
│   ├── fingerprint.yml             # Regex patterns
│   └── connection.yml              # Sources + notification config
│
├── hawk-eye-contrib/               # Custom connectors for hawk-eye
│   ├── onedrive.py                 # OneDrive connector (Microsoft Graph API)
│   └── install_onedrive.py         # Installs connector into hawk_scanner pkg
│
├── dashboard/                      # Web dashboard
│   ├── Dockerfile                  # Multi-stage: Next.js build + Nginx + Flask
│   ├── api/
│   │   └── api.py                  # Flask REST API
│   └── frontend-next/              # Next.js + shadcn/ui
│       └── src/app/                # Pages: dashboard, alerts, patterns, etc.
│
├── reset.sh                        # Cleans alerts DB and TheHive cases
└── thehive-config/
    └── application.conf
```

---

## Cloud Storage Sources

### Google Drive

Poirot supports scanning Google Drive files using the `gdrive` connector (built into hawk-eye via `pydrive2`).

#### Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/) > APIs & Services > Credentials
2. Create an OAuth 2.0 Client ID (Desktop application)
3. Download the credentials JSON file
4. Place it at a path accessible by the container (e.g., mount as a volume)

#### Configuration

In `hawk-scanner/connection.yml`, add under `sources:`:

```yaml
sources:
  gdrive:
    my_drive:
      credentials_file: /app/credentials/gdrive_credentials.json
      folder_name: ""          # empty = scan all, or specific folder name
      exclude_patterns: []
      cache: false
```

Mount the credentials file in `docker-compose.yml`:
```yaml
hawk-scanner:
  volumes:
    - ./credentials:/app/credentials:ro
```

### OneDrive (Microsoft 365)

Poirot supports scanning OneDrive files via the Microsoft Graph API.

#### Azure App Registration

1. Go to [Azure Portal](https://portal.azure.com/) > Azure Active Directory > App Registrations > New registration
2. Name: `poirot-scanner`, Supported account types: choose as needed
3. Go to **API Permissions** > Add permission > Microsoft Graph > Delegated permissions > `Files.Read.All`
4. Go to **Certificates & Secrets** > New client secret, copy the value
5. Note the **Application (client) ID** and **Directory (tenant) ID** from the Overview page
6. To get a refresh token, use the [OAuth 2.0 authorization code flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow) or a tool like [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)

#### Configuration

In `hawk-scanner/connection.yml`, add under `sources:`:

```yaml
sources:
  onedrive:
    my_onedrive:
      client_id: "your-azure-app-client-id"
      client_secret: "your-azure-app-secret"
      tenant_id: "common"              # or your specific tenant ID
      refresh_token: "your-refresh-token"
      folder_path: ""                  # empty = root, or "Documents/sensitive"
      exclude_patterns:
        - "*.exe"
        - "*.zip"
      cache: false
```

---

## AI-Powered Reports (Ollama)

Poirot can use **Ollama** to generate professional HTML email reports with contextual security analysis. When enabled, SMTP notifications include severity cards, pattern tables, source breakdown, and an AI-written analysis paragraph. Falls back to plain text if Ollama is unavailable.

### Setup

You can use Ollama running on your host machine or as a Docker container.

**Option A: Host Ollama (recommended)**

Install [Ollama](https://ollama.com/) on your machine and pull a model:

```bash
ollama pull llama3.1
```

In the dashboard go to **Settings > AI (Ollama)**, set URL to `http://host.docker.internal:11434`, click **Load Models**, select a model, enable and save.

**Option B: Docker container**

```bash
docker compose --profile ollama up -d ollama
```

This starts an Ollama container that auto-downloads `llama3.2:3b`. In Settings, set URL to `http://ollama:11434`.

### How it works

```
Scan Data --> Python HTML Template (severity cards, tables, sources)
                  |
                  +--> Ollama (analysis paragraph only) --> Injected into template
                  |
              MIMEMultipart('alternative')
                  ├── text/plain (fallback)
                  └── text/html  (AI-enhanced)
```

The HTML template is built deterministically in Python (always correct data). Ollama only generates the contextual analysis paragraph, keeping the email reliable even with smaller models.

---

## Disclaimer

This project is for **educational and security research purposes**. The included data sources (MySQL and S3) contain entirely fictitious data and exist only to demonstrate the scanner's functionality.

---

## License

[MIT License](LICENSE)

## Credits

The scan engine is powered by [Hawk Eye](https://github.com/rohitcoder/hawk-eye) by **[Rohit Kumar](https://www.linkedin.com/in/rohitcoder/)**. Thank you Rohit for always sharing with great energy and for building such a valuable tool for the community.

---

**Santiago Fernandez** - [Blog](https://blog.santiagoagustinfernandez.com) | [GitHub](https://github.com/safernandez666) | [LinkedIn](https://linkedin.com/in/safernandez666)
