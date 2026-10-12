# Case Study: CyberShield AI
## Gemini-Powered Cybersecurity Awareness & Threat Analysis Assistant

---

### 1. Executive Summary & Problem Statement
In India and globally, cybercrime tactics such as **phishing emails, SMS smishing (e.g., electricity bill & bank KYC freezes), "Digital Arrest" extortion scams, and typosquatting lookalike domains** cause billions in financial losses every year. 

Most non-technical internet users, students, and seniors fall victim not because they lack technical tools, but because **attackers exploit emotional vulnerabilities: artificial urgency, fear of account suspension, and greed for fake rewards**. 

Traditional security tools present dense jargon ("DMARC failed", "DKIM signature mismatch", "Reputation score 3.2"), leaving everyday users confused. There was a critical need for an accessible, multilingual assistant that **explains, rather than just detects**, breaking down threat mechanics in conversational English and Hinglish.

---

### 2. The Solution: CyberShield AI
**CyberShield AI** is an intelligent cybersecurity tutor and threat analyzer. Users can paste suspicious messages, emails, SMS texts, URLs, security logs, or upload screenshots. 

CyberShield AI dissects the content, flags psychological manipulation, explains danger zones in beginner-friendly Hinglish, auto-redacts sensitive credentials (passwords/OTPs), and synthesizes an interactive 3-question learning quiz for every analyzed threat.

---

### 3. Google Gemini's Role & Specific Capabilities

| Gemini Capability | How CyberShield AI Uses It |
|---|---|
| **Natural Language Understanding (NLU)** | Decodes nuanced social engineering tactics, context manipulation, and disguised urgency that regex filters miss. |
| **Multimodal Vision (Gemini 2.5 Flash)** | Analyzes screenshots of suspicious emails and WhatsApp/SMS messages directly, identifying fake logos and deceptive UI layouts. |
| **Strict JSON Structured Output** | Enforces structured schema returns (`risk_score`, `warning_signs`, `recommended_actions`, `quiz`) to feed responsive dashboard cards directly without JSON formatting bugs. |
| **Conversational Hinglish Generation** | Generates culturally relevant, accessible explanations for non-technical Indian students and families (e.g., "Bank manager kabhi video call par OTP nahi maangte"). |
| **Dynamic Quiz Synthesis** | Generates 3 contextual learning questions for each unique analyzed message, transforming passive detection into active education. |

---

### 4. Technical Separation: AI Reasoning vs. Local Deterministic Code
A crucial engineering standard of CyberShield AI is **Architectural Transparency**: distinguishing what deterministic code checks perform versus what Gemini AI reasons about.

```
+-------------------------------------------------------------+
|                     USER INPUT (Text/Image)                 |
+-------------------------------------------------------------+
                              |
                              v
       [ STEP 1: Local Privacy Guard (Deterministic Python) ]
       • Scans & auto-masks OTPs, Credit Cards, Passwords, Phone Numbers
       • Enforces Zero-Retention volatile memory guarantee
                              |
                              v
       [ STEP 2: Local Security Heuristics (Python Code) ]
       • Regex detection: High-risk TLDs (.xyz, .top, .tk)
       • Raw IP Hostname inspection (e.g., http://192.168.1.1/...)
       • Known brand name lookalike matching
                              |
                              v
       [ STEP 3: Google Gemini 2.5 Flash API (Deep Reasoning) ]
       • Semantic intent: Artificial urgency & emotional coercion
       • Multimodal visual review (Screenshots)
       • Dual-language generation (English + Hinglish)
       • Dynamic 3-Question educational quiz creation
                              |
                              v
       [ STEP 4: Interactive Dashboard & Learn Mode UI ]
       • Risk Gauge, Warning Signs Grid, Action Checklist, Interactive Quiz
```

#### Responsibility Matrix:
- **Local Python Code:**
  - PII Detection & Auto-Redaction (`privacy_guard.py`)
  - URL Hostname Parsing & TLD Matching (`gemini_analyzer.py` -> `LocalSecurityHeuristics`)
  - Offline Fallback Simulation Engine
- **Google Gemini AI:**
  - Semantic Intent & Psychological Pressure Analysis
  - Multimodal Screenshot Inspection
  - Hinglish & English Threat Explanation
  - Dynamic Custom Quiz Generation

---

### 5. Testing & Verification Matrix
The project was tested against a multi-domain test suite across both synthetic threats and legitimate benign baselines to minimize false positives:

| Test Case | Type | Expected Risk | Detected Warning Signs |
|---|---|---|---|
| **SBI YONO KYC Suspension SMS** | SMS Phishing | **CRITICAL (92%)** | Artificial Urgency (24h), Credential Request (OTP), High-Risk TLD (`.top`) |
| **Netflix Account Hold Email** | Email Phishing | **HIGH (85%)** | Brand Impersonation, Credit Card Request, Deceptive URL (`netflix-billing.xyz`) |
| **Google Drive Shared Doc Link** | Lookalike URL | **HIGH (80%)** | Subdomain Trickery (`accounts.google.com.drive-doc-viewer.xyz`), Credential Harvesting |
| **WhatsApp KBC Lottery & Crypto** | Greed Bait | **HIGH (82%)** | Fake Reward, Advance Fee Fraud (`₹999 registration fee`), Suspicious Link |
| **Legitimate GitHub Token Email** | Benign Baseline | **SAFE (10%)** | Clean notification, no credential harvesting, verified official domain (`github.com`) |
| **SSH Server Auth Log** | Security Log | **CRITICAL (90%)** | Rapid brute-force password guessing followed by root escalation |

---

### 6. Privacy & Ethical Guardrails
1. **Privacy By Default:** CyberShield AI does not store user inputs, messages, or emails in any disk database. Inputs exist solely in memory during analysis.
2. **PII Masking:** Users are warned if plain passwords or OTPs are pasted, and auto-masking converts tokens into harmless placeholders before sending them to the model.
3. **Ethical AI Disclaimer:** CyberShield AI explicitly states that AI threat analysis is an educational heuristic, not a replacement for antivirus software or certified digital forensics.
