# 🛡️ PhishGuard - AI Phishing Detection Platform

<p align="center">
  <img src="frontend/public/shield.svg" width="100" alt="PhishGuard Logo">
</p>

<p align="center">
  <strong>AI-Powered Phishing Detection for Kenya 🇰🇪</strong><br>
  Protect yourself from email phishing, SMS smishing, and malicious URL attacks
</p>

---

## 🎯 Problem Statement

Phishing and smishing are **major cybersecurity threats in Kenya**, targeting:

- **M-Pesa users** with fake PIN requests and account suspension scams
- **Bank customers** through spoofed login portals (Equity, KCB, Co-op Bank)
- **Students & institutions** via credential harvesting emails
- **Government service users** with fake KRA, NTSA, eCitizen notices
- **Mobile money users** through Fuliza/M-Shwari/Airtel Money scams

According to the Communications Authority of Kenya, phishing attacks increased by **over 50%** in recent years, with mobile money fraud being the most common attack vector.

## 💡 Our Solution

PhishGuard is an AI-powered web platform that analyzes emails, SMS messages, and URLs to detect phishing and smishing attempts in real-time using advanced heuristic analysis and pattern matching.

### Key Features

- **🔍 Real-Time Scanning** — Paste any email, SMS, or URL for instant AI analysis
- **🤖 Multi-Layer Detection** — 10+ detection modules working in parallel
- **📊 Live Dashboard** — Real-time statistics and threat trend visualization
- **📋 Scan History** — Track all past scans with filtering and search
- **📚 Education Center** — Learn about common phishing/smishing tactics
- **🇰🇪 Kenya-Focused** — Specialized rules for M-Pesa, local banks, and government scams
- **🔒 Security Hardened** — Rate limiting, CORS, CSP headers, input sanitization

---

## 🛠️ Tech Stack

| Component      | Technology               | Purpose                          |
| -------------- | ------------------------ | -------------------------------- |
| **Frontend**   | React 18 + Vite          | Single-page application          |
| **Charts**     | Recharts                 | Dashboard data visualization     |
| **Routing**    | React Router v6          | Client-side page routing         |
| **ML Service** | Python 3.9+ + FastAPI    | Phishing detection engine        |
| **Validation** | Pydantic                 | Request/response data validation |
| **Storage**    | Browser localStorage     | Client-side scan history         |
| **Security**   | CSP, CORS, Rate Limiting | Application hardening            |

### Architecture

```
┌─────────────────────────────────────────┐
│           React Frontend                │
│         (Vite, Port 5173)               │
│  ┌──────────┬───────────┬───────────┐   │
│  │ Scanner  │ Dashboard │ History   │   │
│  │ Page     │ (Charts)  │ (Table)   │   │
│  └──────────┴───────────┴───────────┘   │
│  ┌──────────────────────────────────┐   │
│  │  localStorage (Scan Storage)     │   │
│  └──────────────────────────────────┘   │
└──────────────┬──────────────────────────┘
               │ /api/analyze (POST)
               │ /api/patterns (GET)
               ▼
┌──────────────────────────────────────────┐
│       Python FastAPI ML Service          │
│            (Port 8001)                   │
│  ┌────────────────────────────────────┐  │
│  │  Security Layer                    │  │
│  │  • Rate Limiting (30 req/min)      │  │
│  │  • CORS Validation                 │  │
│  │  • Input Sanitization              │  │
│  │  • Security Headers                │  │
│  └────────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │
│  │  Detection Engine (10+ modules)    │  │
│  │  • Urgency Analysis                │  │
│  │  • Credential Harvesting Detection │  │
│  │  • URL Analysis (Advanced)         │  │
│  │  • Homograph Attack Detection      │  │
│  │  • Typosquatting Detection         │  │
│  │  • Kenya Target Detection          │  │
│  │  • Threat Pattern Matching         │  │
│  │  • SMS Scam Detection              │  │
│  │  • Link Mismatch Detection         │  │
│  │  • Financial Request Detection     │  │
│  └────────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │
│  │  Risk Scoring & Classification     │  │
│  │  • Weighted multi-severity scoring │  │
│  │  • Explainable AI output           │  │
│  │  • Context-aware recommendations   │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js 18+** — Frontend build tooling
- **Python 3.9+** — ML service runtime

### 1. Clone & Setup

```bash
git clone <repo-url>
cd Hackathon-pr
```

### 2. Install Dependencies

```bash
# Frontend
cd frontend
npm install

# Python ML Service
cd ../backend-ml
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run Services

**Terminal 1 — ML Service:**

```bash
cd backend-ml
source venv/bin/activate
uvicorn main:app --reload --port 8001
```

**Terminal 2 — Frontend:**

```bash
cd frontend
npm run dev
```

### 4. Open in Browser

Navigate to: **http://localhost:5173**

---

## 🌐 Deployment

### Frontend (Vercel / Netlify)

Set environment variable:

```
VITE_API_URL=https://your-backend-url.com
```

### Backend (Render / Railway / Fly.io)

Set environment variables:

```bash
PRODUCTION=true
FRONTEND_URL=https://your-frontend.vercel.app
ALLOWED_HOSTS=your-backend.onrender.com
RATE_LIMIT=30
```

See `.env.example` files in each directory for all configuration options.


---

## 🔒 Security Features

| Feature                | Implementation                           |
| ---------------------- | ---------------------------------------- |
| **CORS**               | Environment-based origin whitelist       |
| **Rate Limiting**      | 30 req/min per IP (backend + frontend)   |
| **Input Sanitization** | Server + client-side content cleaning    |
| **CSP Headers**        | Content Security Policy on all responses |
| **Trusted Hosts**      | Host header validation                   |
| **X-Frame-Options**    | DENY — prevents clickjacking             |
| **Input Limits**       | 50KB content max, validated types        |
| **Request Abort**      | AbortController for pending requests     |

---

## 🔬 Detection Capabilities

> **Full technical breakdown**: See [DETECTION_GUIDE.md](DETECTION_GUIDE.md)

### Detection Modules

| Module                  | What It Detects                          |
| ----------------------- | ---------------------------------------- |
| Urgency Analysis        | Pressure language ("act now", "expires") |
| Credential Harvesting   | PIN/password/OTP requests                |
| Threat Detection        | Account suspension/legal threats         |
| Advanced URL Analysis   | Suspicious domains, IPs, TLDs            |
| Homograph Detection     | Lookalike character attacks (Cyrillic)   |
| Typosquatting Detection | Misspelled brand domains                 |
| Domain Spoofing         | Brand name in subdomain abuse            |
| Kenya Target Detection  | M-Pesa, banks, government impersonation  |
| SMS Scam Patterns       | Prize scams, callback traps, reply scams |
| Financial Request       | Money transfer/fee payment requests      |
| Link Mismatch           | Display URL ≠ actual destination         |
| Entropy Analysis        | Randomly generated domain detection      |

### Classification Output

| Level             | Confidence | Risk Level      |
| ----------------- | ---------- | --------------- |
| ✅ **Safe**       | < 25%      | Low             |
| ⚠️ **Suspicious** | 25–50%     | Medium          |
| 🚨 **Phishing**   | > 50%      | High / Critical |

---

## Kenya-Specific Detections

| Category         | Targets                                                   |
| ---------------- | --------------------------------------------------------- |
| **M-Pesa**       | M-Pesa, Lipa na M-Pesa, Paybill, Till Number, Send Money  |
| **Banks**        | Equity, KCB, Co-op, NCBA, Stanbic, ABSA, Family Bank, DTB |
| **Telcos**       | Safaricom, Airtel, Telkom Kenya, Faiba                    |
| **Government**   | KRA, NTSA, eCitizen, Huduma, NHIF, NSSF                   |
| **Mobile Money** | Airtel Money, T-Kash, Equitel, M-Shwari, Fuliza           |

---

## 📊 Dashboard Features

- **Total Scans** — Real-time count of all analyses performed
- **Classification Distribution** — Pie chart (phishing/suspicious/safe)
- **Scans by Content Type** — Bar chart (email/SMS/URL)
- **Daily Trends** — Line chart of threats over last 7 days
- **Top Threat Patterns** — Most common attack indicators detected
- **Recent Threats** — Latest phishing/suspicious scans

---

## 👥 Team

| Role                     | Responsibility                        |
| ------------------------ | ------------------------------------- |
| **Lead Developer**       | Frontend (React) + Backend (FastAPI)  |
| **Cybersecurity Expert** | Threat research, phishing patterns    |
| **ML Engineer**          | Detection algorithms, scoring model   |
| **UI/UX Designer**       | Design, color theme, user experience  |
| **Documentation Lead**   | README, detection guide, presentation |

---

## 🎤 Presentation Structure

### 1️⃣ Problem (1 min)

> "Kenyan students, workers, and institutions are losing data and money to phishing and smishing scams daily."

### 2️⃣ Solution (1 min)

> "We built PhishGuard — an AI-powered platform that detects phishing emails, SMS smishing, and malicious URLs in real-time."

### 3️⃣ Demo (3 min)

- Paste a real M-Pesa scam SMS → AI flags it as phishing
- Show threat indicators and severity breakdown
- Navigate to Dashboard for live analytics
- Show Education page with Kenya-specific patterns

### 4️⃣ Impact (1 min)

- Can be integrated into university email systems
- SMS filtering for mobile users
- Educational tool for cybersecurity awareness

### 5️⃣ Future Work (1 min)

- Browser extension
- Mobile app (React Native)
- Real-time email/SMS filtering
- Integration with M-Pesa and banking apps
- Machine learning model training on Kenyan phishing datasets

---

## 🏆 Why PhishGuard Wins

- ✅ **Real-world impact** — Solves actual cybersecurity problems in Kenya
- ✅ **AI-Powered** — Advanced heuristic detection with explainability
- ✅ **Easy to demo** — Visual, interactive, immediate results
- ✅ **Kenya-focused** — M-Pesa, local banks, government-specific rules
- ✅ **Production-ready** — Security hardened, deployable, well-documented
- ✅ **Scalable** — Architecture supports growth beyond hackathon

---

## 📝 Technical Keywords for Judges

- Natural Language Processing (NLP)
- Heuristic Pattern Analysis
- Threat Intelligence
- Real-Time Cyber Threat Detection
- Explainable AI (XAI)
- Secure API Architecture
- Content Security Policy (CSP)
- Shannon Entropy Analysis
- Homograph Attack Detection
- Typosquatting Detection

---

## 📄 License

MIT License — Built for Hackathon 2026

---

<p align="center">
  Built with ❤️ for cybersecurity awareness in Kenya 🇰🇪
</p>
