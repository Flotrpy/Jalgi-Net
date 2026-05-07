# JalgiNet – SOC Security Monitor

> **A production-style hybrid cybersecurity monitoring platform** combining DoS/DDoS detection, IDS integration (Snort/Suricata), multi-source threat correlation, and a real-time SOC dashboard.

---

## 🧠 What is JalgiNet?

JalgiNet simulates a real-world **Security Operations Center (SOC)** monitoring platform. It:

- **Captures** live or simulated network traffic (packet-level)
- **Detects** DoS/DDoS attacks using sliding-window rate analysis
- **Integrates** with Snort/Suricata IDS log formats
- **Correlates** multi-source events to detect multi-stage attacks
- **Visualizes** everything in a dark-themed, real-time web dashboard

---

## 📁 Project Structure

```
jalgi-net/
├── backend/
│   ├── app.py                  # Flask entry point – run this
│   ├── config.py               # All thresholds & feature flags
│   ├── database.py             # SQLite schema + CRUD helpers
│   ├── modules/
│   │   ├── packet_capture.py   # Scapy capture + simulation
│   │   ├── dos_detector.py     # DoS/DDoS detection engine
│   │   ├── ids_parser.py       # Snort/Suricata parser + simulator
│   │   ├── correlation.py      # Multi-source correlation engine
│   │   └── geo_ip.py           # GeoIP lookup (ip-api.com)
│   ├── routes/
│   │   ├── alerts.py           # GET /api/alerts
│   │   ├── traffic.py          # GET /api/traffic/*
│   │   ├── ids.py              # GET /api/ids/*
│   │   ├── threats.py          # GET/POST /api/threats/*
│   │   └── settings.py         # GET/POST /api/settings, export
│   └── requirements.txt
├── frontend/
│   ├── index.html              # Single-page dashboard
│   ├── css/style.css           # Dark cyberpunk design system
│   └── js/
│       ├── app.js              # Tab router, API helpers, toasts
│       ├── overview.js         # KPI cards, live chart, health
│       ├── alerts.js           # Real-time alert feed
│       ├── traffic.js          # RPS, protocol, top-IPs charts
│       ├── ids.js              # IDS events table
│       ├── threats.js          # Correlated threat cards
│       └── settings.js         # Settings panel logic
└── README.md
```

---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- pip

### 1. Install dependencies

```bash
cd jalgi-net/backend
pip install -r requirements.txt
```

### 2. Start JalgiNet

```bash
python app.py
```

### 3. Open the dashboard

Navigate to **http://localhost:5000** in your browser.

> The app starts in **Simulation Mode** by default — fully functional without needing Npcap, Snort, or admin privileges.

---

## ⚙️ Configuration

All settings live in `backend/config.py`:

| Setting | Default | Description |
|---|---|---|
| `SIMULATION_MODE` | `True` | Use synthetic traffic/IDS events |
| `DOS_THRESHOLDS["Low"]` | 50 | Pkts/window for Low severity |
| `DOS_THRESHOLDS["Medium"]` | 150 | Pkts/window for Medium severity |
| `DOS_THRESHOLDS["High"]` | 300 | Pkts/window for High severity |
| `DOS_THRESHOLDS["Critical"]` | 600 | Pkts/window for Critical severity |
| `CORRELATION["window_seconds"]` | 300 | Correlation time window (5 min) |
| `AUTO_BLOCK["enabled"]` | `False` | Simulate auto-blocking |

Settings can also be updated **live** from the dashboard Settings tab.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   JALGI-NET BACKEND                     │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐                   │
│  │Packet Capture│──▶│  DoS Detector│──▶ Alerts DB      │
│  │  (Scapy/Sim) │   │ (Sliding Win)│                   │
│  └──────────────┘   └──────────────┘                   │
│                                                         │
│  ┌──────────────┐                                       │
│  │  IDS Parser  │──▶ IDS Events DB ──▶ Alerts DB       │
│  │(Snort/Suric.)│                                       │
│  └──────────────┘                                       │
│           │                │                            │
│           ▼                ▼                            │
│  ┌─────────────────────────────┐                       │
│  │     Correlation Engine      │──▶ Threats DB         │
│  │  (Risk Score + Pattern Det) │                       │
│  └─────────────────────────────┘                       │
│                    │                                    │
│           ┌────────▼────────┐                          │
│           │  Flask REST API  │                          │
│           │  (port 5000)    │                          │
│           └────────┬────────┘                          │
└────────────────────│────────────────────────────────────┘
                     │ HTTP JSON (polled every 3s)
                     ▼
┌─────────────────────────────────────────────────────────┐
│              JALGI-NET DASHBOARD (Frontend)             │
│                                                         │
│  Overview │ Alerts │ Traffic │ IDS │ Threats │ Settings │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Dashboard Tabs

| Tab | Description |
|---|---|
| **Overview** | KPI cards, live traffic chart, top suspicious IPs, system health |
| **Alerts Feed** | Real-time alert stream with filter/search + block action |
| **Traffic Analysis** | RPS timeseries, protocol distribution, top-IPs bar chart |
| **IDS Events** | Parsed Snort/Suricata events with attack-type filter |
| **Correlated Threats** | Multi-stage attack records with risk scores (0–10) |
| **Settings** | Live threshold config, module toggles, export, clear logs |

---

## 🚨 Alert Schema

```json
{
  "type":        "DoS | IDS | Correlated",
  "severity":    "Low | Medium | High | Critical",
  "source_ip":   "185.220.101.42",
  "description": "High packet rate detected: 340 pkts in 60s window",
  "timestamp":   "2026-03-29T21:30:00Z"
}
```

---

## 🛡️ Detection Logic

### DoS Engine
- **Volumetric flood**: per-IP packet count exceeds threshold in sliding window
- **SYN flood**: SYN packet ratio > 85% of total TCP packets
- **Distributed flood**: total spike with 5+ unique source IPs

### Correlation Engine Risk Scoring

```
raw_score = Σ (type_weight × severity_multiplier) per event
+ pattern_bonus (port_scan + brute_force + dos → +20 pts)
final_score = min(raw_score / 8.0, 10.0)
```

| Score | Severity |
|---|---|
| 8.0 – 10.0 | Critical |
| 6.0 – 7.9  | High |
| 4.0 – 5.9  | Medium |
| 0.0 – 3.9  | Low |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | System health & module status |
| GET | `/api/alerts` | Paginated alerts (filter: severity, type) |
| GET | `/api/alerts/summary` | Dashboard KPIs |
| GET | `/api/traffic/stats` | RPS timeseries |
| GET | `/api/traffic/top-ips` | Top IPs by packet count |
| GET | `/api/traffic/protocols` | Protocol breakdown |
| GET | `/api/ids/events` | IDS events (filter: attack_type) |
| GET | `/api/ids/attack-types` | Distinct attack categories |
| GET | `/api/threats/correlated` | Correlated threat records |
| POST | `/api/threats/block` | Block an IP (simulation) |
| POST | `/api/threats/unblock` | Unblock an IP |
| GET | `/api/settings` | Current configuration |
| POST | `/api/settings` | Update thresholds at runtime |
| DELETE | `/api/logs/clear` | Wipe all stored data |
| GET | `/api/export/json` | Full data export |

---

## 💼 Business Value

### Small Businesses
JalgiNet provides an affordable, lightweight SOC monitoring solution. Without needing expensive enterprise software, small businesses can detect volumetric attacks, identify suspicious IPs, and block threats before they impact services.

### Security Analysts
Real-time alert streaming with severity classification enables analysts to triage threats immediately. The searchable, filterable alert feed and IDS event table accelerate incident investigation by providing structured, correlated data rather than raw logs.

### SOC Teams
The Correlation Engine is JalgiNet's most powerful feature for SOC workflows — it automatically links reconnaissance (port scans), lateral movement (brute force), and flooding (DoS) events from the same source IP into a single threat record with a risk score. This transforms hours of manual log correlation into seconds.

---

## 🚀 Bonus Features

| Feature | Status |
|---|---|
| Auto-block IPs | ✅ Simulation mode (toggle in Settings) |
| GeoIP mapping | ✅ Live via ip-api.com free tier |
| JSON export | ✅ Full data dump via Settings tab |
| Browser notifications | ✅ Critical alert popups |
| Real Snort/Suricata | ✅ Set `SIMULATION_MODE=False` + log path |
| Live packet capture | ✅ Install Npcap + set `SIMULATION_MODE=False` |

---

## 🛠️ Technologies Used

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask, Flask-CORS |
| Database | SQLite3 (built-in, zero config) |
| Packet Capture | Scapy (simulation fallback built-in) |
| Frontend | Vanilla HTML5, CSS3, JavaScript |
| Charts | Chart.js 4.x |
| Fonts | Google Fonts — Inter + JetBrains Mono |
| GeoIP | ip-api.com (free tier, no API key needed) |

---

*Built as a production-style cybersecurity prototype demonstrating SOC monitoring architecture, real-time threat detection, and modern dashboard design.*
