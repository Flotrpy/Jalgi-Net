# JalgiNet – Modernized SOC Security Monitor

> **A modernized production-style hybrid cybersecurity monitoring platform** featuring AI-powered threat analysis, real-time WebSockets, cloud-native storage (Supabase), and a glassmorphism SOC dashboard.

---

## 🧠 What is JalgiNet?

JalgiNet simulates a real-world **Security Operations Center (SOC)** monitoring platform. This modernized version enhances the core detection engine with:

- **AI Analysis**: Integrates Google Gemini 1.5 Flash to generate executive summaries, security impact assessments, and recommended actions for every correlated threat.
- **Cloud Storage**: Support for **Supabase (PostgreSQL)** for enterprise-grade, external data persistence alongside local SQLite.
- **Real-time Updates**: Upgraded from polling to **WebSockets (Socket.IO)** for instant alert streaming and live dashboard updates.
- **Device Profiling**: A new **Devices** view that builds security profiles for every active IP on the network.
- **Modern UI**: A complete visual overhaul using **glassmorphism**, **Lucide icons**, and a clean, emoji-free professional design.

---

## 📁 Project Structure

```
jalgi-net/
├── backend/
│   ├── app.py                  # Flask + Socket.IO entry point
│   ├── config.py               # All thresholds, API keys, & feature flags
│   ├── database.py             # SQLite/Supabase abstraction layer
│   ├── modules/
│   │   ├── ai_analyzer.py      # Google Gemini AI integration
│   │   ├── packet_capture.py   # Scapy capture + WebSocket broadcasting
│   │   ├── dos_detector.py     # DoS/DDoS detection engine
│   │   ├── ids_parser.py       # Snort/Suricata parser + simulator
│   │   ├── correlation.py      # AI-linked multi-source correlation engine
│   │   └── geo_ip.py           # GeoIP lookup (ip-api.com)
│   ├── routes/                 # REST API Blueprints
│   └── requirements.txt
├── frontend/
│   ├── index.html              # Modern glassmorphism dashboard
│   ├── css/style.css           # Global design system
│   └── js/
│       ├── app.js              # Core controller & WebSocket handler
│       ├── devices.js          # IP Security profiling logic
│       ├── threats.js          # AI-enhanced threat visualization
│       └── ...                 # Tab-specific modules
└── README.md
```

---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- (Optional) Google Gemini API Key
- (Optional) Supabase Project URL

### 1. Install dependencies

```bash
cd jalgi-net/backend
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)

Create a `.env` file or export variables:
```bash
export GEMINI_API_KEY="your_key"
export USE_SUPABASE="True"
export SUPABASE_DB_URL="postgresql://postgres:password@db.supabase.co:5432/postgres"
```

### 3. Start JalgiNet

```bash
python app.py
```

### 4. Open the dashboard

Navigate to **http://localhost:3000** in your browser.

---

## ⚙️ Modernized Features

| Feature | Description |
|---|---|
| **AI Summaries** | Every correlated threat is analyzed by Gemini to explain the *why* and *how* of the attack. |
| **WebSockets** | 0ms latency for alert arrival. The dashboard stays in sync without page refreshes. |
| **Supabase Integration** | Seamlessly switch from SQLite to PostgreSQL by setting one flag in `config.py`. |
| **Devices Tab** | View per-device security posture, total packets, and AI-generated risk profiles. |
| **Glassmorphism UI** | A high-contrast, professional dark mode UI with backdrop-blur effects and Lucide iconography. |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   JALGI-NET BACKEND                     │
│                                                         │
│  ┌──────────────┐   ┌────────────────┐   ┌───────────┐  │
│  │Packet Capture│──▶│ AI Analyzer    │◀─▶│ Gemini API│  │
│  │ (WebSocket)  │   │(Summarization) │   └───────────┘  │
│  └──────────────┘   └────────────────┘                  │
│           │                ▲                            │
│           ▼                │                            │
│  ┌─────────────────────────────┐         ┌───────────┐  │
│  │     Correlation Engine      │────────▶│  Supabase │  │
│  │  (Risk Score + AI Linking)  │         │ (Postgres)│  │
│  └─────────────────────────────┘         └───────────┘  │
│                    │                           ▲        │
│           ┌────────▼────────┐                  │        │
│           │ Flask + SocketIO│◀─────────────────┘        │
│           │   (port 3000)   │                           │
│           └────────┬────────┘                           │
└────────────────────│────────────────────────────────────┘
                     │ WebSocket (Live Push)
                     ▼
┌─────────────────────────────────────────────────────────┐
│              JALGI-NET DASHBOARD (Frontend)             │
│                                                         │
│  Overview │ Alerts │ Traffic │ IDS │ Threats │ Devices  │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Dashboard Tabs

| Tab | Description |
|---|---|
| **Overview** | Real-time KPI cards, live traffic chart, and system health. |
| **Alerts Feed** | Live-streamed security alerts with instant filtering. |
| **Traffic Analysis** | RPS metrics and protocol distribution. |
| **IDS Events** | Deep dive into Snort/Suricata signature matches. |
| **Correlated Threats** | Multi-stage attacks with **AI Security Summaries**. |
| **Devices** | Security profiles for every detected network asset. |
| **Settings** | Configuration for AI, Storage, and detection thresholds. |

---

## 🛡️ Modernized Detection Logic

### AI-Enhanced Correlation
The correlation engine now passes attack patterns to Gemini 1.5 Flash. The AI provides:
1. **Executive Summary**: A human-readable description of the threat.
2. **Security Impact**: What assets or data are at risk.
3. **Recommended Actions**: Clear steps for remediation (e.g., "Rotate API keys", "Apply patch KB123").

---

## 🛠️ Technologies Used

| Layer | Technology |
|---|---|
| AI | Google Gemini 1.5 Flash |
| Backend | Python 3.10+, Flask, Flask-SocketIO |
| Database | PostgreSQL (Supabase) / SQLite3 |
| Frontend | Vanilla JS, CSS3 (Glassmorphism), Lucide Icons |
| Real-time | Socket.IO (WebSockets) |
| Charts | Chart.js 4.x |

---

*Modernized with ❤️ to provide a cutting-edge SOC monitoring experience.*
