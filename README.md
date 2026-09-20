# AI-Based Network Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.x-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-6.x-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A fully integrated, AI/ML-powered Network Intrusion Detection and Real-Time Security Monitoring System**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Application](#running-the-application)
- [Usage Guide](#usage-guide)
  - [Step-by-Step Workflow](#step-by-step-workflow)
  - [Demo Credentials](#demo-credentials)
- [API Reference](#api-reference)
- [ML Models](#ml-models)
- [Frontend Pages](#frontend-pages)
- [Dataset Format](#dataset-format)
- [Configuration](#configuration)
- [Database](#database)
- [Screenshots](#screenshots)
- [Contributing](#contributing)

---

## Overview

This project is an **academic-grade, production-quality** implementation of an AI-powered Network Intrusion Detection System (NIDS). It uses machine learning to classify network traffic flows as either **benign or malicious**, identifies the specific **attack category**, assigns a **severity level**, and raises **security alerts** — all in real time.

The system is built with a clean layered architecture (Frontend → REST API → Service → Repository → Database) and supports both **single-flow** and **batch CSV** analysis, as well as a **live simulation mode** that continuously calls the prediction API to mimic real-world traffic monitoring.

---

## Features

### Security & Detection
- **Live Network Traffic Capture** — sniffs packets in real time from physical or virtual network adapters (Wi-Fi, Ethernet) using Scapy and Npcap.
- **5-Tuple Flow Aggregator** — groups bidirectional packets into flows `(src_ip, dst_ip, src_port, dst_port, protocol)` with active/idle timeout sweeps and TCP FIN/RST termination.
- **77-Feature Extraction Engine** — computes all 77 canonical CIC-IDS2017 flow metrics directly from live packets for the active ML pipeline.
- **Dual-Mode Real-Time Monitor** — seamless switching between **Live Network Capture** (`[LIVE]`) and **Traffic Simulation** (`[SIMULATED]`).
- **Single-flow prediction** — enter network features manually and get an instant ML prediction
- **Batch CSV detection** — upload a CIC-IDS2017 format CSV and classify thousands of records at once
- **10 attack categories** detected: DoS, DDoS, PortScan, FTP-Patator, SSH-Patator, Slowloris, Slowhttptest, GoldenEye, Bot, and Infiltration
- **4-level severity classification**: CRITICAL, HIGH, MEDIUM, LOW
- **Automatic alert creation** for every intrusion detection above the confidence threshold

### Machine Learning
- **4 supported model types**: Random Forest, Decision Tree, Logistic Regression, SVM
- **Model comparison tool** — benchmarks all models on the same dataset
- **Feature importance visualization** for tree-based models
- **Stateful preprocessor** — fits on training data, transforms inference data without data leakage
- **Comprehensive metrics**: Accuracy, Precision, Recall, F1 (Macro/Weighted), ROC-AUC
- **Model versioning** — multiple trained models stored, one active at a time

### Monitoring & Alerts
- **Alert lifecycle management**: Active → Acknowledged → Resolved
- **Investigation notes** on each alert
- **Real-time dashboard** with 4 live Chart.js visualizations
- **Analytics page** with 5 interactive charts (attack distribution, severity, trends, protocol, top IPs)
- **Audit logging** of every significant system event

### Management
- **Dataset management** — upload, validate, and delete training datasets
- **User management** — admin can create, enable/disable, and delete users
- **Role-based access control** — Admin and Analyst roles with different permissions
- **Report generation** — export security reports as **PDF, CSV, or JSON**
- **System settings** — configurable confidence threshold, retention period, batch size

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend API** | Python 3.10+, Flask 3.x, Flask-JWT-Extended, Flask-CORS |
| **ML** | scikit-learn, NumPy, pandas |
| **Database** | MongoDB (primary) / TinyDB (automatic fallback) |
| **Frontend** | Vanilla HTML5, CSS3, JavaScript (ES6+) |
| **Charts** | Chart.js 4.x |
| **Auth** | JWT (JSON Web Tokens) with bcrypt password hashing |
| **PDF Reports** | ReportLab (optional) |

> **No MongoDB required** — the system automatically falls back to TinyDB (a JSON file-based database) when MongoDB is not installed. This means you can run the entire system with zero infrastructure dependencies.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Frontend (13 pages)                 │
│          HTML / Vanilla CSS / Vanilla JavaScript        │
│                   Chart.js for charts                   │
└───────────────────────────┬─────────────────────────────┘
                            │  fetch() + JWT Bearer Token
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  Flask REST API (Port 5000)              │
│   /auth  /dashboard  /datasets  /models  /predict       │
│   /detections  /alerts  /analytics  /reports  /admin    │
└───────────────────────────┬─────────────────────────────┘
                            │
              ┌─────────────┴──────────────┐
              ▼                            ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│   Service Layer     │      │     ML Pipeline             │
│   AuthService       │      │  NIDSPreprocessor (stateful)│
│   DashboardService  │      │  Trainer (4 model types)    │
│   (etc.)            │      │  Predictor (cached)         │
└─────────┬───────────┘      └─────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│              Repository Layer                           │
│  UserRepo / DetectionRepo / AlertRepo / ModelRepo       │
│  DatasetRepo / AuditRepo                                │
└───────────────────────────┬─────────────────────────────┘
                            │
              ┌─────────────┴──────────────┐
              ▼                            ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│  MongoDB (primary)  │      │  TinyDB (auto fallback)     │
│  localhost:27017    │      │  dataset/nids_db.json        │
└─────────────────────┘      └─────────────────────────────┘
```

---

## Project Structure

```
Network Intrusion Detection System/
│
├── backend/                        # Flask backend application
│   ├── app.py                      # Application factory (all blueprints registered here)
│   ├── config.py                   # Environment-based configuration
│   ├── __init__.py
│   │
│   ├── auth/                       # Authentication module
│   │   ├── routes.py               # /auth/* endpoints
│   │   └── service.py              # Login, register, password management
│   │
│   ├── dashboard/                  # Dashboard statistics
│   │   ├── routes.py               # /dashboard/* endpoints
│   │   └── service.py              # Aggregates real-time DB stats
│   │
│   ├── datasets/                   # Dataset management
│   │   ├── routes.py               # /datasets/* endpoints
│   │   └── validator.py            # CSV format validation
│   │
│   ├── ml/                         # Machine learning core
│   │   ├── routes.py               # /models/*, /predict/* endpoints
│   │   ├── feature_config.py       # CIC-IDS2017 feature definitions
│   │   ├── preprocessor.py         # Stateful feature preprocessing
│   │   ├── trainer.py              # Model training engine
│   │   ├── evaluator.py            # Metrics computation
│   │   └── predictor.py            # Inference with in-memory caching
│   │
│   ├── detections/                 # Detection history
│   │   └── routes.py               # /detections/* endpoints
│   │
│   ├── alerts/                     # Alert management
│   │   └── routes.py               # /alerts/* endpoints (ack, resolve, notes)
│   │
│   ├── analytics/                  # Security analytics
│   │   └── routes.py               # /analytics/* endpoints
│   │
│   ├── reports/                    # Report generation
│   │   └── routes.py               # /reports/* endpoints (PDF/CSV/JSON)
│   │
│   ├── admin/                      # Admin panel
│   │   └── routes.py               # /admin/* endpoints
│   │
│   ├── database/                   # Data access layer
│   │   ├── connection.py           # MongoDB + TinyDB connection manager
│   │   └── repositories/
│   │       ├── base.py             # Shared serialization utilities
│   │       ├── user_repo.py
│   │       ├── detection_repo.py
│   │       ├── alert_repo.py
│   │       ├── audit_repo.py
│   │       ├── dataset_repo.py
│   │       └── model_repo.py
│   │
│   └── utils/
│       ├── decorators.py           # @login_required, @admin_required
│       ├── logger.py               # Structured logging
│       └── response.py             # Standardised JSON response helpers
│
├── frontend/                       # Static frontend (13 pages)
│   ├── index.html                  # Login page
│   ├── dashboard.html              # Main dashboard
│   ├── traffic-analysis.html       # Single flow prediction
│   ├── batch-detection.html        # CSV bulk analysis
│   ├── detection-history.html      # Paginated detection log
│   ├── realtime.html               # Live simulation monitor
│   ├── alerts.html                 # Alert management
│   ├── analytics.html              # Charts & intelligence
│   ├── models.html                 # ML model training & management
│   ├── datasets.html               # Dataset upload & management
│   ├── reports.html                # Report generation & export
│   ├── users.html                  # Admin: user management
│   ├── audit-logs.html             # Admin: system event log
│   ├── settings.html               # System settings
│   ├── css/
│   │   └── style.css               # Dark cybersecurity theme
│   └── js/
│       ├── api.js                  # Centralised API client (all fetch calls)
│       ├── auth.js                 # JWT session management
│       ├── utils.js                # Toast, formatters, pagination, charts
│       └── sidebar.js              # Dynamic sidebar component
│
├── dataset/                        # Data storage
│   ├── sample/
│   │   └── sample_nids_data.csv    # Generated sample dataset (10,000 rows)
│   └── nids_db.json                # TinyDB fallback database
│
├── models/                         # Trained model artifacts (auto-created)
│   └── <version>/
│       ├── model.pkl               # Trained classifier
│       ├── scaler.pkl              # StandardScaler
│       ├── imputer.pkl             # SimpleImputer
│       └── metadata.json           # Training parameters and metrics
│
├── scripts/
│   ├── seed_db.py                  # Creates default admin/analyst users
│   └── generate_sample_data.py     # Generates synthetic CIC-IDS2017 CSV
│
├── uploads/                        # Uploaded dataset staging area
├── logs/                           # Application log files
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── .gitignore
└── README.md                       # This file
```

---

## Getting Started

### Prerequisites

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **MongoDB** *(optional — system falls back to TinyDB automatically)*
- **Npcap for Windows** *(optional — required for live packet capture on physical network interfaces; download from [npcap.com](https://npcap.com) with "Install Npcap in WinPcap API-compatible Mode" enabled)*

### Installation

**1. Clone or download the project**
```bash
cd "Network Intrusion Detection System"
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure environment variables** *(optional — defaults work out of the box)*
```bash
copy .env.example .env
# Edit .env if you want to change the MongoDB URI, JWT secret, etc.
```

**4. Seed the database** *(creates default admin and analyst users)*
```bash
python scripts/seed_db.py
```

**5. Generate a sample dataset** *(creates a 10,000-row CIC-IDS2017 format CSV)*
```bash
python scripts/generate_sample_data.py
```

### Running the Application

**Start the Flask backend:**
```bash
python backend/app.py
```

The API will be available at: `http://127.0.0.1:5000`

**Open the frontend:**

Open the following file in your browser:
```
frontend/index.html
```

> **Note:** Because the frontend makes API calls to `http://localhost:5000`, the backend must be running before you open any frontend page (except the login page which will show an error gracefully).

---

## Usage Guide

### Demo Credentials

| Role    | Username  | Password     | Access Level |
|---------|-----------|--------------|--------------|
| Admin   | `admin`   | `Admin@123`  | Full system access |
| Analyst | `analyst` | `Analyst@123`| View + detection, no admin panel |

### Step-by-Step Workflow

#### First-Time Setup
1. Log in as **admin**
2. Go to **Datasets** → Click **Upload Dataset** → Upload `dataset/sample/sample_nids_data.csv`
3. Go to **ML Models** → Click **+ Train New Model**
   - Select the uploaded dataset
   - Choose **Random Forest** (recommended)
   - Set test size to **20%**
   - Click **Start Training**
4. Once training completes, click **Activate** on the model card
5. The system is now ready for detections

#### Single Flow Prediction
1. Go to **Traffic Analysis**
2. Click **Load Sample** to auto-fill features (PortScan pattern) or enter values manually
3. Fill in optional metadata (Source IP, Destination IP, Protocol)
4. Click **Analyze Traffic**
5. View the prediction result with confidence score and severity

#### Batch CSV Detection
1. Go to **Batch Detection**
2. Drag-and-drop or browse for a CIC-IDS2017 format CSV file
3. Click **Run Batch Detection**
4. View the summary (total, intrusions, normal, detection rate) and breakdown by attack type

#### Real-Time Network Monitor (Dual Mode)

The Real-Time Monitor supports two distinct operational modes:

##### 1. Live Network Capture Mode
1. Go to **Real-Time Monitor**
2. Ensure the **Live Network Capture** tab is selected
3. Select your active physical or virtual network adapter (e.g. `Wi-Fi` or `Ethernet`)
4. Verify the packet capture driver status:
   - If **Npcap** is installed, live packet sniffing is active.
   - If Npcap is missing, the system displays a clear warning with setup instructions. You can install Npcap from [npcap.com](https://npcap.com) (check *"Install Npcap in WinPcap API-compatible Mode"*).
5. Click **▶ Start** to begin live packet capture
6. The backend sniffs real packets, aggregates them into bidirectional 5-tuple flows, extracts all 77 CIC-IDS2017 features, and classifies them in real time with the active ML model
7. Live detections appear with the `[LIVE]` tag and automatically update the main Dashboard, active alerts, and detection history
8. Use **Test Normal Flow** and **Test Attack Flow** buttons to verify the entire pipeline on demand
9. Click **⏹ Stop** to safely flush remaining flows and stop packet sniffing

##### 2. Traffic Simulation Mode
1. Click the **Traffic Simulation** tab
2. Select a **Traffic Pattern** (`Mixed (Realistic)`, `Attack Heavy`, or `Mostly Normal`)
3. Adjust the interval (ms)
4. Click **▶ Start**
5. Simulated traffic events appear in the live feed clearly labeled with the `[SIMULATED]` tag without corrupting or misrepresenting real network data

#### Managing Alerts
1. Go to **Alerts**
2. Filter by Status, Severity, or Attack Type
3. Click **Ack** to acknowledge, **Resolve** to close an alert
4. Click **Note** to add investigation notes

#### Generating Reports
1. Go to **Reports**
2. View the live preview panel (updates from real DB data)
3. Click one of the export buttons:
   - **Download PDF Report** — formatted multi-section PDF
   - **Download CSV Report** — spreadsheet-compatible
   - **Download JSON Report** — machine-readable

---

## API Reference

All endpoints return JSON with the structure:
```json
{
  "success": true,
  "message": "Human-readable message",
  "data": { ... }
}
```

Authentication uses `Authorization: Bearer <JWT_TOKEN>` header.

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/login` | Login, returns JWT token |
| `POST` | `/auth/register` | Create new user account |
| `POST` | `/auth/logout` | Invalidate session (audit logged) |
| `GET` | `/auth/me` | Get current user profile |
| `POST` | `/auth/change-password` | Change own password |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/summary` | All key statistics |
| `GET` | `/dashboard/trends` | Hourly/daily trends |
| `GET` | `/dashboard/top-ips` | Top source/destination IPs |

### Datasets
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/datasets` | List all uploaded datasets |
| `POST` | `/datasets/upload` | Upload & validate CSV |
| `DELETE` | `/datasets/<id>` | Delete dataset (admin) |

### ML Models
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/models` | List all trained models |
| `GET` | `/models/active` | Get currently active model |
| `POST` | `/models/train` | Train a new model |
| `POST` | `/models/compare` | Compare all model types |
| `POST` | `/models/<id>/activate` | Set model as active |
| `DELETE` | `/models/<id>` | Delete model |

### Prediction
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/predict` | Single flow prediction |
| `POST` | `/predict/batch` | Batch CSV prediction |

### Detections
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/detections` | Paginated detection history |
| `GET` | `/detections/<id>` | Detection detail |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | Paginated alert list |
| `POST` | `/alerts/<id>/acknowledge` | Acknowledge alert |
| `POST` | `/alerts/<id>/resolve` | Resolve alert |
| `POST` | `/alerts/<id>/notes` | Add investigation note |
| `GET` | `/alerts/summary` | Severity/status counts |

### Analytics
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/analytics/overview` | Aggregated overview |
| `GET` | `/analytics/attacks` | Attack type distribution |
| `GET` | `/analytics/severity` | Severity distribution |
| `GET` | `/analytics/protocols` | Protocol distribution |
| `GET` | `/analytics/trends?days=7` | Time-series trend |
| `GET` | `/analytics/top-ips?limit=10` | Top source/dest IPs |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/reports/preview` | Report data preview |
| `POST` | `/reports/generate` | Download report (`format`: json/csv/pdf) |

### Network & Live Capture
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/network/interfaces` | List physical/virtual adapters & Npcap capability |
| `POST` | `/network/capture/start` | Start live sniffing on selected interface |
| `POST` | `/network/capture/stop` | Stop packet capture & flush active flows |
| `GET` | `/network/capture/status` | Real-time state, session counters, uptime |
| `GET` | `/network/capture/events` | Poll classified flow events (`?limit=50&since=0`) |
| `GET` | `/network/capture/stream` | Server-Sent Events (SSE) live detection stream |
| `POST` | `/network/capture/inject-test-flow` | Pipeline validation with synthetic test flow |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/users` | List all users |
| `DELETE` | `/admin/users/<id>` | Delete user |
| `POST` | `/admin/users/<id>/toggle-active` | Enable/disable user |
| `GET` | `/admin/audit-logs` | System audit log |
| `GET` | `/admin/system-stats` | Counts of all entities |
| `GET/POST` | `/admin/settings` | View/update system settings |

---

## ML Models

### Supported Classifiers

| Model | Key | Notes |
|-------|-----|-------|
| Random Forest | `random_forest` | Best accuracy, recommended default |
| Decision Tree | `decision_tree` | Fast, interpretable, feature importance |
| Logistic Regression | `logistic_regression` | Lightweight, fast inference |
| Support Vector Machine | `svm` | Good with scaled features |

### ML Pipeline

```
Raw CSV
  │
  ▼
NIDSPreprocessor.fit_transform()
  ├── Drop non-feature columns (Flow ID, IP addresses, timestamps)
  ├── Select recognized CIC-IDS2017 features
  ├── Replace infinite values → NaN
  ├── SimpleImputer (median strategy)
  └── StandardScaler (mean=0, std=1)
  │
  ▼
Classifier.fit()
  │
  ▼
Save artifacts:
  ├── model.pkl
  ├── scaler.pkl
  ├── imputer.pkl
  └── metadata.json (metrics, feature list, label encoder)
```

### Attack Label Taxonomy

| Raw Label (CIC-IDS2017) | Normalised Label |
|-------------------------|-----------------|
| BENIGN | BENIGN |
| DoS Hulk / GoldenEye / slowloris / Slowhttptest | DoS |
| DDoS | DDoS |
| PortScan | PortScan |
| FTP-Patator / SSH-Patator | Brute Force |
| Bot | Bot |
| Web Attack – Brute Force / XSS / SQL Injection | Web Attack |
| Infiltration | Infiltration |
| Heartbleed | DoS |

---

## Frontend Pages

| Page | File | Access |
|------|------|--------|
| Login | `index.html` | Public |
| Dashboard | `dashboard.html` | All users |
| Traffic Analysis | `traffic-analysis.html` | All users |
| Batch Detection | `batch-detection.html` | All users |
| Real-Time Monitor | `realtime.html` | All users |
| Detection History | `detection-history.html` | All users |
| Alerts | `alerts.html` | All users |
| Analytics | `analytics.html` | All users |
| ML Models | `models.html` | Train/delete: Admin only |
| Datasets | `datasets.html` | Delete: Admin only |
| Reports | `reports.html` | All users |
| Users | `users.html` | Admin only |
| Audit Logs | `audit-logs.html` | Admin only |
| Settings | `settings.html` | All users (system config: Admin only) |

---

## Dataset Format

The system is compatible with **CIC-IDS2017** dataset format.

### Required Label Column
The CSV must contain a column named ` Label` (with a leading space, as in the original dataset) containing attack category names.

### Key Features Used
The system recognizes **78 flow features** including:
- Flow duration, packet counts, byte lengths
- IAT (Inter-Arrival Time) statistics
- Flag counts (SYN, ACK, FIN, RST, PSH, URG)
- Window sizes, segment sizes
- Bulk transfer statistics
- Active/idle time statistics

### Getting Real Data
Download the CIC-IDS-2017 dataset from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html).

---

## Configuration

Copy `.env.example` to `.env` and edit as needed:

```env
# Flask
FLASK_ENV=development
SECRET_KEY=your-secret-key-change-this-in-production
JWT_SECRET_KEY=your-jwt-secret-change-this-in-production

# MongoDB (optional — TinyDB used automatically if unavailable)
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=nids_db

# File storage
UPLOAD_FOLDER=uploads
MODEL_PATH=models
MAX_CONTENT_LENGTH=104857600  # 100MB

# CORS
CORS_ORIGINS=*
```

---

## Database

### MongoDB (Recommended for Production)

Install MongoDB Community Server:

```bash
# Windows (via winget)
winget install MongoDB.Server

# Then start the service
net start MongoDB
```

The application auto-connects to `mongodb://localhost:27017/nids_db`.

### TinyDB (Zero-Config Development)

If MongoDB is not available, the system automatically uses **TinyDB** — a pure-Python, file-based JSON database stored at `dataset/nids_db.json`. No installation or configuration required.

> **Limitations of TinyDB mode:** Slower for large datasets, no concurrent access, limited aggregation support. For production or datasets > 50,000 records, use MongoDB.

### Collections / Tables

| Collection | Contents |
|------------|----------|
| `users` | User accounts and credentials |
| `detections` | Every ML prediction result |
| `alerts` | Security alerts with lifecycle state |
| `models` | Trained model metadata and metrics |
| `datasets` | Uploaded dataset metadata |
| `audit_logs` | Immutable system event log |
| `system_settings` | Global configuration |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

This project is licensed under the MIT License.

---

<div align="center">

Built for academic research in AI-powered cybersecurity monitoring.

**CIC-IDS2017 Dataset** | **scikit-learn** | **Flask** | **Chart.js**

</div>
