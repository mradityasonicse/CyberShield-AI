# 🛡️ CyberShield AI
### Gemini-Powered Cybersecurity Awareness & Threat Analysis Assistant

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Google Gemini API](https://img.shields.io/badge/AI-Google%20Gemini%202.5%20Flash-00f0ff.svg)](https://aistudio.google.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Privacy First](https://img.shields.io/badge/Privacy-Zero%20Data%20Logging-emerald.svg)](#privacy-first-design)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/mradityasonicse/CyberShield-AI)

> **CyberShield AI** is an intelligent cybersecurity tutor and threat analyzer. Paste suspicious emails, SMS texts, lookalike URLs, or security logs — or upload screenshots — and CyberShield AI uses **Google Gemini 2.5 Flash** to break down deception tactics, highlight warning signs in plain English and beginner-friendly **Hinglish**, and generate an interactive 3-question learning quiz for every analyzed threat.

---

## 🎯 The Core Problem
In India and globally, cybercrime tactics like **bank KYC freezes, electricity disconnection smishing, "Digital Arrest" extortion, and deceptive lookalike domains** cause massive financial losses. Non-technical students, seniors, and families fall victim because **attackers exploit panic, artificial urgency, and fear**. 

Traditional antivirus tools give cold, confusing technical alerts. **CyberShield AI changes this paradigm: it explains, rather than just detects**, empowering users to recognize attacker psychology and make informed security decisions.

---

## ✨ Key Features

### 1. 🔍 Phishing & Smishing Message Analyzer
- Analyzes pasted emails, SMS messages, or chat logs.
- Detects psychological traps: **Artificial Urgency** ("Account suspended in 24 hours"), **Credential Harvesting** ("Verify password/OTP"), and **Fake Incentives** ("Lottery/Crypto reward").
- Quotes exact phrases from the message with explanations of *why* each phrase is dangerous.

### 2. 🔗 Suspicious URL & Lookalike Domain Explainer
- Inspects URLs for deceptive practices: **typosquatting** (`amaz0n-support.co`), **misleading subdomains** (`accounts.google.com.phish.xyz`), **raw IP hostnames**, and **high-risk TLDs** (`.top`, `.xyz`, `.club`).
- Includes an ethical advisory clarifying that AI heuristic analysis is an assistive indicator, not a definitive malware blocklist.

### 3. 📷 Multimodal Screenshot Analysis (Gemini Vision)
- Upload or drag-and-drop screenshots of suspicious emails or WhatsApp/SMS messages directly.
- Gemini 2.5 Flash Vision evaluates visual styling, counterfeit logos, and deceptive layouts.

### 4. 🇮🇳 Bilingual Cyber Tutor (English + Hinglish)
- Switch seamlessly between standard English and conversational **Hinglish** (Hindi in Roman script).
- Formatted so students, non-technical parents, and peers can instantly grasp why an attack is fraudulent without cybersecurity jargon.

### 5. 🎮 Learn Mode: Dynamic Interactive Quiz Generator
- For every threat analyzed, Gemini dynamically synthesizes **3 interactive multiple-choice questions** based on the specific deception tactics in that message.
- Users receive real-time feedback, score calculations, and educational explanations to build permanent cybersecurity instincts.

### 6. 🔒 Privacy-First Design & PII Shield
- **Live PII Detection:** Real-time warnings when plain passwords, OTPs, credit cards, or phone numbers are pasted.
- **Auto-Redaction:** Sensitive tokens are sanitized into `[REDACTED_OTP]` before being sent to the AI.
- **Zero Persistent Storage:** Stateless, in-memory processing. Zero database logs or disk storage of user inputs.

### 7. ⚡ Offline Heuristic Fallback Engine
- Runs smoothly **out of the box** even before an API key is entered, thanks to a built-in deterministic heuristic security scanner.
- Ready to unlock live deep neural reasoning the moment a Gemini API key is configured.

---

## 🚀 Gemini API Integration Architecture

| Gemini Capability | CyberShield AI Implementation |
|---|---|
| **Natural Language Understanding (NLU)** | Understands nuanced social engineering, panic induction, and deceptive phrasing in natural language. |
| **Multimodal Input** | Processes image screenshots of fraudulent emails and fake mobile notifications using Gemini 2.5 Flash. |
| **Structured JSON Output** | Returns strict schema JSON (`overall_risk`, `risk_score`, `warning_signs`, `recommended_actions`, `quiz`) to render interactive cards. |
| **Bilingual Generation** | Produces culturally resonant Hinglish explanations for Indian cyber threat contexts (e.g. KYC fraud, electricity scams). |

---

## 📊 AI vs. Local Code: Hybrid Responsibility

To maintain complete architectural integrity in Devpost and Ambassador portfolio presentations, CyberShield AI clearly separates deterministic local code checks from Gemini AI reasoning:

| Responsibility | Handled By | Mechanism |
|---|---|---|
| **PII Detection & Token Masking** | Local Python Code | Regex scanner in `privacy_guard.py` |
| **Syntactic URL Parsing** | Local Python Code | Hostname parsing & TLD registry checks |
| **Contextual Intent & Social Engineering** | Google Gemini AI | Deep semantic analysis of attacker motivation |
| **Multimodal Screenshot Reading** | Google Gemini AI | Gemini Vision OCR and layout analysis |
| **Hinglish Educational Synthesis** | Google Gemini AI | LLM translation and cultural contextualization |
| **Dynamic Quiz Synthesis** | Google Gemini AI | Real-time question generation per threat |

---

## 🛠️ Tech Stack
- **Backend:** Python 3.12+, Flask 3.1, Flask-CORS
- **AI Engine:** Google Gemini API (`gemini-2.5-flash`), official `google-genai` SDK (v2.29+)
- **Frontend:** Vanilla HTML5, Modern CSS (Glassmorphism, Cyber Command Center, CSS Grid), Vanilla JavaScript (Zero external JS framework bloat)
- **Security & Privacy:** Regex PII Sanitization, Stateless In-Memory Architecture

---

## ⚡ Quickstart Guide

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/CyberShield-AI.git
cd CyberShield-AI
```

### 2. Configure Environment (Optional for Live Gemini AI)
Copy `.env.example` to `.env`:
```bash
copy .env.example .env
```
Get a free Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey) and paste it into `.env`:
```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
FLASK_PORT=5000
GEMINI_MODEL=gemini-2.5-flash
```
*(Note: If you don't provide an API key, CyberShield AI will automatically run in its built-in Offline Heuristic Mode!)*

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```
Open your browser at: **`http://127.0.0.1:5000`**

### 5. Run Automated Tests
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 🧪 Pre-Loaded Test Samples
CyberShield AI includes 6 pre-loaded test cases for instant demo evaluation:
1. **Bank KYC Suspension SMS (Urgent Fraud):** Smishing sample with 24-hour urgency and OTP request.
2. **Netflix Account Suspension Email:** Brand impersonation email seeking credit card and CVV updates.
3. **Deceptive Google Drive Shared Document:** Subdomain lookalike domain harvesting credentials.
4. **Crypto Giveaway & Lottery WhatsApp Scam:** Hindi/Hinglish KBC lottery bait with advance fee demand.
5. **Legitimate GitHub Security Alert:** Benign baseline test to verify false-positive control.
6. **Suspicious Authentication Server Log:** SSH brute-force attack followed by root escalation.

---

## 📂 Project Structure
```
CyberShield-AI/
├── .env.example              # Sample environment variables
├── .gitignore                # Git ignore rules
├── requirements.txt          # Python dependencies
├── app.py                    # Flask server & REST API endpoints
├── config.py                 # Configuration loader
├── gemini_analyzer.py        # Gemini client & Local Heuristic Engine
├── privacy_guard.py          # PII detection & auto-masking rules
├── static/
│   ├── css/
│   │   └── style.css         # Cyber command center design system
│   ├── js/
│   │   ├── app.js            # Frontend orchestrator & API integration
│   │   └── quiz.js           # Learn-mode quiz engine
│   └── images/
│       └── logo.svg          # CyberShield AI shield emblem
├── templates/
│   └── index.html            # Main single-page application
├── tests/
│   └── test_analyzer.py      # Automated test suite (13 unit & integration tests)
├── docs/
│   ├── CASE_STUDY.md         # Full portfolio case study
│   ├── DEMO_SCRIPT.md        # 1-2 minute video demo recording script
│   └── ARCHITECTURE.md       # Technical architectural blueprint
└── README.md                 # Complete project documentation
```

---

## ⚠️ Ethical AI Disclaimer
CyberShield AI provides **assistive heuristic analysis for educational and threat-awareness purposes**. It is not an enterprise firewall or a guarantee of complete safety. Users should always independently verify unexpected communications through verified official channels and never share confidential banking OTPs or passwords.

---

## 🏆 Ambassador Portfolio Deliverables
- [x] Fully functioning interactive web application
- [x] Complete test suite passing with 100% exit code 0
- [x] Google Gemini 2.5 Flash integration with structured JSON output
- [x] Multimodal screenshot analysis support
- [x] English + Hinglish bilingual explanations
- [x] Dynamic 3-question quiz generator (Learn Mode)
- [x] Privacy-first PII redaction engine
- [x] 1–2 minute demo video script (`docs/DEMO_SCRIPT.md`)
- [x] Comprehensive case study (`docs/CASE_STUDY.md`)
- [x] Architectural documentation (`docs/ARCHITECTURE.md`)
