# Technical Architecture: CyberShield AI
## Gemini-Powered Cybersecurity Awareness & Threat Analysis Assistant

---

### 1. High-Level System Architecture

CyberShield AI is built as a hybrid intelligence system combining **deterministic rule-based cybersecurity filters** with **Google Gemini 2.5 Flash's semantic and multimodal reasoning**:

```
+----------------------------------------------------------------------------------+
|                            FRONTEND (HTML5 / CSS / JS)                           |
|  • Single-Page Cyber Command Center UI with Glassmorphism & Neon Depth           |
|  • Real-time Client-Side PII Warning Tracker                                     |
|  • Multimodal Drag-and-Drop Image Uploader (Screenshots)                         |
|  • Dynamic Learn-Mode Interactive Quiz Engine (`quiz.js`)                        |
|  • Markdown & JSON Report Exporter with One-Click Clipboard Copy                 |
+----------------------------------------------------------------------------------+
                                        |  REST API (JSON / FormData)
                                        v
+----------------------------------------------------------------------------------+
|                           FLASK SERVER (`app.py`)                                |
|  • Endpoint Routing: `/api/analyze`, `/api/samples`, `/api/scan-pii`, `/api/health` |
|  • Session-based Custom API Key Manager (`/api/set-key`)                         |
|  • File validation & Secure File Streaming (Max 16MB)                            |
+----------------------------------------------------------------------------------+
         |                                                 |
         v                                                 v
+-------------------------------+      +-------------------------------------------+
|  PRIVACY GUARD (`privacy_guard.py`)  |      |   LOCAL HEURISTICS (`gemini_analyzer.py`) |
|  • Regex token recognition    |      |  • Regex Urgency & Panic Detection        |
|  • OTP / PIN Redaction        |      |  • Credential & KYC Harvesting Signatures |
|  • Card & Password Masking    |      |  • Typosquatting & Suspicious TLD Match   |
|  • Zero persistent disk storage|      |  • Raw IP Hostname Identification         |
+-------------------------------+      +-------------------------------------------+
                                        |
                                        v
+----------------------------------------------------------------------------------+
|                       GOOGLE GEMINI 2.5 FLASH API ENGINE                         |
|  • SDK: `google-genai` (v2.29+)                                                  |
|  • Multimodal: Processes textual messages AND email/SMS screenshots              |
|  • Structured Response: Strict JSON schema return (`GenerateContentConfig`)      |
|  • Bilingual Reasoning: Synthesizes English and conversational Hinglish output   |
|  • Educational Quiz Synthesis: 3 custom dynamic questions per threat             |
+----------------------------------------------------------------------------------+
                                        | (Fallback if key absent or quota exceeded)
                                        v
+----------------------------------------------------------------------------------+
|                   OFFLINE HEURISTIC SECURITY ENGINE (FALLBACK)                   |
|  • Guarantees 100% crash-free demo operation out of the box                     |
|  • Structured risk scoring, explanations, and tailored educational quiz          |
+----------------------------------------------------------------------------------+
```

---

### 2. Gemini System Prompt & Schema Design
CyberShield AI utilizes a constrained system prompt with `response_mime_type="application/json"`:

```json
{
  "overall_risk": "SAFE | LOW | MEDIUM | HIGH | CRITICAL",
  "risk_score": 0,
  "confidence_percentage": 0,
  "threat_category": "string",
  "summary_en": "string",
  "summary_hi": "string",
  "warning_signs": [
    {
      "title": "string",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "quote": "string",
      "explanation_en": "string",
      "explanation_hi": "string"
    }
  ],
  "url_analysis": {
    "detected_urls": ["string"],
    "domain_red_flags": ["string"],
    "verdict_note": "string"
  },
  "recommended_actions": [
    {
      "action_en": "string",
      "action_hi": "string",
      "urgency": "IMMEDIATE | RECOMMENDED | OPTIONAL"
    }
  ],
  "cyber_tutor_tip": {
    "topic": "string",
    "takeaway_en": "string",
    "takeaway_hi": "string"
  },
  "quiz": [
    {
      "id": 1,
      "question": "string",
      "options": ["string", "string", "string", "string"],
      "correct_index": 0,
      "explanation": "string"
    }
  ],
  "limitations_disclaimer": "string"
}
```

---

### 3. Privacy-First Data Flow & Sanitization
To ensure zero accidental exposure of private user credentials:
1. **Client-side live monitoring:** Text inputs are debounced against `/api/scan-pii` to alert users that sensitive items (e.g. OTPs or card numbers) are present in the text area.
2. **Server-side token substitution:** If the auto-redaction toggle is active, `privacy_guard.mask_pii()` transforms sensitive tokens into synthetic placeholders (`[REDACTED_OTP]`, `[REDACTED_CARD_NUMBER]`) before any payload is delivered to Google AI Studio.
3. **Stateless RAM execution:** Neither the raw text nor the resulting analysis is stored in any local SQLite, SQL, or disk database. History is purely transient.

---

### 4. Hybrid Security Responsibility Matrix

| Feature | Deterministic Local Python | Google Gemini AI |
|---|---|---|
| **Raw IP & TLD Matching** | Regex parsing on URL strings | Semantic context & brand spoofing |
| **Credential Redaction** | Regex pattern matching & masking | Contextual analysis of anonymized payload |
| **Language Translation** | N/A | Culturally resonant Hinglish synthesis |
| **Multimodal Vision** | File validation & MIME sniffing | Visual inspection of logos & fraudulent layout |
| **Custom Quiz Generation** | Pre-defined bank fallback | Real-time question synthesis tailored to threat |
