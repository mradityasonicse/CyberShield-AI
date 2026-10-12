"""
Privacy Guard Module for CyberShield AI
Detects and sanitizes Personally Identifiable Information (PII) before transmission to LLMs.
Enforces privacy-first design: no passwords, live OTPs, credit cards, or personal IDs leaked.
"""

import re
from typing import Dict, List, Tuple

# Regex Patterns for Sensitive Data Detection
PII_PATTERNS = {
    "credit_card": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "label": "Payment Card Number",
        "replacement": "[REDACTED_CARD_NUMBER]"
    },
    "otp_code": {
        "pattern": r"(?i)\b(?:otp|one[-\s]?time[-\s]?password|verification code|security code|pin)\s*(?:is|:)?\s*([0-9]{4,8})\b",
        "label": "One-Time Password (OTP)",
        "replacement": "[REDACTED_OTP]"
    },
    "standalone_otp": {
        "pattern": r"\b(?<!\d)[0-9]{6}(?!\d)\b",
        "label": "Possible 6-digit OTP/PIN",
        "replacement": "[REDACTED_6DIGIT_PIN]"
    },
    "password_field": {
        "pattern": r"(?i)\b(?:password|pwd|passcode|secret key)\s*[:=]\s*([^\s,;]+)",
        "label": "Plaintext Password",
        "replacement": "password: [REDACTED_PASSWORD]"
    },
    "phone_number": {
        "pattern": r"(?:\+?91[\s-]?)?[6789]\d{9}\b|\b\+?1[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b",
        "label": "Mobile Phone Number",
        "replacement": "[REDACTED_PHONE_NUMBER]"
    },
    "ssn_aadhaar": {
        "pattern": r"\b\d{4}\s\d{4}\s\d{4}\b|\b\d{3}-\d{2}-\d{4}\b",
        "label": "National ID / Aadhaar / SSN",
        "replacement": "[REDACTED_NATIONAL_ID]"
    }
}

def scan_pii(text: str) -> List[Dict[str, str]]:
    """
    Scans input text for sensitive personal data and returns detected warnings.
    """
    if not text:
        return []

    findings = []
    for pii_type, config in PII_PATTERNS.items():
        matches = list(re.finditer(config["pattern"], text))
        if matches:
            findings.append({
                "type": pii_type,
                "label": config["label"],
                "count": len(matches),
                "warning": f"Detected {len(matches)} instance(s) of {config['label']} in the text."
            })
    return findings

def mask_pii(text: str) -> Tuple[str, List[str]]:
    """
    Redacts sensitive personal information and replaces with safe placeholders.
    Returns (sanitized_text, list_of_redactions_performed).
    """
    if not text:
        return text, []

    redacted_text = text
    applied_redactions = []

    # 1. Redact specific label-value patterns first
    for pii_type in ["password_field", "otp_code", "credit_card", "ssn_aadhaar", "phone_number"]:
        config = PII_PATTERNS[pii_type]
        if re.search(config["pattern"], redacted_text):
            if pii_type == "password_field":
                redacted_text = re.sub(config["pattern"], r"password: [REDACTED_PASSWORD]", redacted_text)
            elif pii_type == "otp_code":
                redacted_text = re.sub(config["pattern"], r"OTP: [REDACTED_OTP]", redacted_text)
            else:
                redacted_text = re.sub(config["pattern"], config["replacement"], redacted_text)
            applied_redactions.append(config["label"])

    return redacted_text, applied_redactions
