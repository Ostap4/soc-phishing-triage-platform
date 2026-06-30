# 🛡️ SOC Phishing Triage Platform

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Backend-green.svg)
![React](https://img.shields.io/badge/React-Frontend-blue.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-orange.svg)

A full-stack phishing email analysis platform designed to streamline SOC-style triage workflows and assist Blue Team analysts in initial incident response.

This application allows security analysts to upload suspicious `.eml` files, automatically extract technical phishing indicators, analyze links and attachments against threat intelligence (VirusTotal), and generate an AI-assisted social engineering assessment using local LLMs via Ollama.

---

## 📖 Table of Contents
- [Overview](#overview)
- [Screenshots](#screenshots)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Setup & Installation](#setup--installation)
- [API Endpoints](#api-endpoints)
- [Security Features](#security-features)
- [Limitations & Roadmap](#limitations--roadmap)
- [Disclaimer](#disclaimer)

---

## 🔎 Overview

The **SOC Phishing Triage Platform** is a cybersecurity portfolio project built specifically to address the first stage of suspicious email investigations. It accelerates the triage process by parsing raw email data to extract technical indicators (headers, hidden links, attachment hashes) and combining them with AI-based reasoning to identify urgency, financial pressure, and advanced social engineering techniques.

---

## 📸 Screenshots

### Login Page
<p align="center">
  <img src="./docs/login.jpg" alt="Login page" width="800" />
</p>

### Password Recovery
<p align="center">
  <img src="./docs/reset_passwd.jpg" alt="Password reset page" width="800" />
</p>

### Email Upload
<p align="center">
  <img src="./docs/email.jpg" alt="Email upload page" width="800" />
</p>

### Scan Dashboard
<p align="center">
  <img src="./docs/dashboard.jpg" alt="Scan dashboard" width="800" />
</p>

### Scan Result Details
<p align="center">
  <img src="./docs/verdict.jpg" alt="Scan result details" width="800" />
</p>

---

## ✨ Key Features

**Analysis & Extraction**
- Upload and parse raw `.eml` email files.
- Extract email headers, message body, and attachment metadata.
- Identify visible, hidden, and mismatched links (e.g., visible text differing from the actual `href`).
- Calculate SHA-256 hashes for all attachments.

**Threat Intelligence & AI**
- Automated querying of URLs and file hashes against the **VirusTotal API**.
- Generate an AI-assisted phishing verdict using **Ollama** (detecting urgency, pressure, and social engineering patterns).

**Authentication & Security**
- User registration and login flow with JWT-based authentication.
- Secure password reset flow.
- Cloudflare Turnstile CAPTCHA integration.
- Login attempt tracking and PostgreSQL-backed scan history logging.

---

## 🛠️ Tech Stack

| Category | Technologies |
| :--- | :--- |
| **Backend** | Python, Flask, Flask-SQLAlchemy, PostgreSQL, PyJWT, Werkzeug |
| **Frontend** | Vite, React, TypeScript, Tailwind CSS, Cloudflare Turnstile |
| **AI / Threat Intel** | Ollama (Local LLM, e.g., `phi3`), VirusTotal API |

---

## 📂 Project Structure

```text
soc-phishing-triage-platform/
├── backend/
│   ├── core/
│   ├── models/
│   ├── routers/
│   ├── services/
│   ├── app.py
│   ├── main.py
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   ├── package.json
│   ├── vite.config.ts
│   └── .env.example
│
├── docs/
│   └── screenshots/
│
├── README.md
└── .gitignore
```

---

## ⚙️ How It Works

1.Upload: The user uploads a suspicious .eml email file via the dashboard.

2.Parsing: The backend parses the email, extracting headers, plain text, HTML body, URLs, hidden/mismatched links, and attachment hashes.

3.Threat Intel: Extracted URLs and file hashes are sent to the VirusTotal API for reputation checking.

4.AI Triage: The email content is passed to a local Ollama model.

5.Verdict Generation: The AI module outputs a structured JSON verdict analyzing urgency, pressure, financial manipulation, and specific social engineering tactics.

6.Storage & Review: The final scan result is saved in PostgreSQL, and the frontend displays the analysis in a SOC-style dashboard.



### Example AI Verdict

```json

{
  "urgency_detected": true,
  "financial_pressure": false,
  "social_engineering_tactics": [
    "time pressure",
    "account suspension warning"
  ],
  "verdict": "Suspicious",
  "brief_reason": "The email pressures the user to act quickly and contains suspicious links."
}
```


## 🚀 Setup & Installation

### Backend Setup

Navigate to the backend directory:

```bash
cd backend
```

Create and activate a virtual environment:

```bash
python -m venv venv
```

On Windows:

```bash
venv\Scripts\activate
```

On Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file based on `.env.example`:

```env
SECRET_KEY=replace_with_a_strong_secret_key
DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/phishing_db

SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_app_password

FRONTEND_URL=http://localhost:3000

VT_API_KEY=your_virustotal_api_key
TURNSTILE_SECRET_KEY=your_turnstile_secret_key
TURNSTILE_ENABLED=true

MAX_UPLOAD_MB=10
TRUST_PROXY=false
```

Run the backend server:

```bash
python app.py
```

The backend will be available at:

```text
http://127.0.0.1:5000
```

### Frontend Setup

Navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Create a `.env` file based on `.env.example`:

```env
VITE_TURNSTILE_SITE_KEY=your_turnstile_site_key
VITE_API_URL=http://127.0.0.1:5000
```

Start the development server:

```bash
npm run dev
```

The frontend will be available at:

```text
http://localhost:3000
```


## 📡 API Endpoints

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/auth/register` | `POST` | Register a new user |
| `/auth/login` | `POST` | Authenticate and receive JWT |
| `/auth/forgot-password` | `POST` | Request a password reset token |
| `/auth/reset-password` | `POST` | Reset password using token |
| `/api/scans/upload` | `POST` | Upload a `.eml` file for analysis |
| `/api/scans/history` | `GET` | Retrieve user scan history |
| `/api/scans/<scan_id>` | `GET` | Retrieve details for a specific scan |

---

## 🔒 Security Features & Notes

- **Credential Management:** Passwords are securely hashed; strength validation is enforced during registration and reset.
- **Authentication:** JWT is used for secured API access.
- **Abuse Prevention:** Login attempts are tracked to prevent brute force. CAPTCHA verification protects sensitive authentication flows.
- **Safe Processing:** Uploaded files are processed temporarily in memory. Attachments are statically hashed and **never** executed.
- **Privacy:** AI analysis runs locally through Ollama, preventing sensitive email data from leaking to third-party commercial LLMs.

> **Note:** This project is designed as an educational SOC triage tool. Before deploying in a production environment, implement production-grade secret management, strict CORS policies, request rate limiting, centralized logging, and secure HTTP-only cookies.

---

## 🚧 Current Limitations & Roadmap

### Limitations
- Currently only supports `.eml` files.
- URL extraction is heuristic.
- Analysis speed may be bottlenecked by VirusTotal free-tier API rate limits.
- AI verdicts are designed as analyst support tools, not autonomous final decisions.
- Attachments are not dynamically sandboxed.

## 🚧 Roadmap

The project is currently focused on local SOC-style phishing triage. Future improvements are grouped by security, deployment, and analyst workflow enhancements.

### 🔴 High Priority

- [ ] Add Docker Compose for backend, frontend, PostgreSQL, and Ollama
- [ ] Implement Alembic database migrations
- [ ] Add stricter upload validation and file size enforcement
- [ ] Improve production-ready CORS and environment configuration

### 🟠 Analyst Workflow

- [ ] Add IOC export in JSON and CSV formats
- [ ] Generate detailed downloadable scan reports in PDF format
- [ ] Add scan severity scoring and visual risk indicators
- [ ] Improve email artifact extraction from HTML buttons, images, and nested links

### 🟡 Security & Monitoring

- [ ] Build an admin dashboard for login attempt monitoring
- [ ] Add rate limiting for authentication and scan upload endpoints
- [ ] Add centralized backend logging
- [ ] Add CI checks for linting and dependency security

### 🔵 Testing & Quality

- [ ] Add unit tests for the email parser
- [ ] Add API tests for authentication and scan routes
- [ ] Add sample `.eml` test cases for safe local testing

---

## ⚠️ Disclaimer

This tool is intended strictly for cybersecurity learning, SOC workflow practice, and portfolio demonstration. It should only be used to analyze emails that the user is explicitly authorized to inspect.

---
### Author: Created by Ostap4