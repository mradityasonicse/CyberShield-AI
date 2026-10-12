"""
CyberShield AI - Flask Application Server
Gemini-powered Cybersecurity Awareness & Threat Analysis Assistant
"""

import os
import json
import logging
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import config
from privacy_guard import scan_pii, mask_pii
from gemini_analyzer import analyze_with_gemini, LocalSecurityHeuristics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CyberShield")

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

# Curated Sample Threat Cases for Quick Demo & Testing
SAMPLE_CASES = [
    {
        "id": "bank_kyc_sms",
        "title": "Bank KYC Suspension SMS (Urgent Fraud)",
        "category": "SMS Phishing (Smishing)",
        "language_type": "Hinglish / Hindi-English",
        "sample_text": "Dear SBI Customer, Your YONO account will be BLOCKED within 24 hours due to pending KYC verification. Immediately update your PAN and Aadhaar details to avoid suspension. Click link: http://sbi-kyc-verify.top/update or call 9876543210. Share OTP when received."
    },
    {
        "id": "netflix_phishing_email",
        "title": "Netflix Account Suspension Email",
        "category": "Email Brand Impersonation",
        "language_type": "English",
        "sample_text": "Subject: Important: Your Netflix membership is on hold!\n\nDear Member,\nWe're having trouble with your current billing information. We'll try again, but in the meantime, your membership will be suspended within 12 hours unless you update your payment details immediately.\n\nPlease verify your credit card number, CVV and billing address here: https://netflix-billing-support.xyz/login\n\n- The Netflix Support Team"
    },
    {
        "id": "lookalike_google_url",
        "title": "Deceptive Google Drive Shared Document",
        "category": "Lookalike Domain / Credential Harvesting",
        "language_type": "English",
        "sample_text": "Check out this urgent confidential financial document shared with you on Google Drive: https://accounts.google.com.drive-doc-viewer.xyz/auth/login?user=student@university.edu. Login with your Google credentials to download."
    },
    {
        "id": "crypto_lottery_whatsapp",
        "title": "Crypto Giveaway & Lottery WhatsApp Scam",
        "category": "Fake Incentive / Greed Bait",
        "language_type": "Hinglish",
        "sample_text": "Badhaai ho! Aapka number Select hua hai ₹25,00,000 KBC WhatsApp Lottery aur 0.5 Bitcoin reward ke liye. Is inaam ko claim karne ke liye turant link open karein: http://kbc-lottery-winner-2026.club/claim aur registration fee ₹999 pay karein."
    },
    {
        "id": "safe_legitimate_receipt",
        "title": "Legitimate GitHub Security Alert (Safe Baseline)",
        "category": "Legitimate Notification (False-Positive Test)",
        "language_type": "English",
        "sample_text": "Subject: [GitHub] A personal access token has been generated\n\nHi Alex,\nA new Personal Access Token (classic) with repo scope was generated for your account on October 12, 2026 at 14:20 UTC from IP address 203.0.113.45.\n\nIf you created this token, no further action is required. If you did not generate this token, please visit your account settings at https://github.com/settings/tokens to revoke it immediately."
    },
    {
        "id": "suspicious_raw_log",
        "title": "Suspicious Authentication / Server Log",
        "category": "Security Log Analysis",
        "language_type": "Technical",
        "sample_text": "Oct 12 18:04:12 auth-server sshd[28491]: Failed password for root from 194.26.29.112 port 44821 ssh2\nOct 12 18:04:13 auth-server sshd[28494]: Failed password for root from 194.26.29.112 port 44824 ssh2\nOct 12 18:04:15 auth-server sshd[28499]: Failed password for invalid user admin from 194.26.29.112 port 44830 ssh2\nOct 12 18:04:18 auth-server sshd[28503]: Accepted password for root from 194.26.29.112 port 44836 ssh2\nWARNING: Rapid brute-force password guessing detected followed by successful privileged session establishment."
    }
]

@app.route("/")
def index():
    """Main CyberShield AI Command Center View"""
    return render_template("index.html")

@app.route("/api/samples", methods=["GET"])
def get_samples():
    """Returns pre-loaded sample threats for instant demo and evaluation"""
    return jsonify({
        "status": "success",
        "samples": SAMPLE_CASES
    })

@app.route("/api/health", methods=["GET"])
def health_check():
    """System health and active Gemini configuration check"""
    has_env_key = bool(config.GEMINI_API_KEY and config.GEMINI_API_KEY != "your_gemini_api_key_here")
    session_key = bool(session.get("custom_api_key"))
    
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "project": "CyberShield AI",
        "gemini_model": config.GEMINI_MODEL,
        "api_key_configured": has_env_key or session_key,
        "offline_heuristics_ready": True
    })

@app.route("/api/scan-pii", methods=["POST"])
def scan_pii_endpoint():
    """Live PII detection endpoint to notify users before analysis"""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    findings = scan_pii(text)
    return jsonify({
        "has_sensitive_data": len(findings) > 0,
        "findings": findings
    })

@app.route("/api/analyze", methods=["POST"])
def analyze_endpoint():
    """
    Primary Threat Analysis Endpoint
    Accepts text or multipart image screenshot + text.
    Handles PII masking, local deterministic rules, and Gemini reasoning.
    """
    image_bytes = None
    image_mime = None
    user_api_key = session.get("custom_api_key", "")

    # Handle Multipart Form (Image upload) vs JSON Payload
    if request.content_type and "multipart/form-data" in request.content_type:
        text = request.form.get("text", "").strip()
        do_mask_pii = request.form.get("mask_pii", "true").lower() in ("true", "1", "yes")
        custom_key = request.form.get("api_key", "").strip()
        if custom_key:
            user_api_key = custom_key

        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename != "":
                filename = secure_filename(file.filename)
                ext = os.path.splitext(filename)[1].lower()
                if ext in config.UPLOAD_EXTENSIONS:
                    image_bytes = file.read()
                    image_mime = file.mimetype or "image/png"
    else:
        payload = request.get_json(silent=True) or {}
        text = payload.get("text", "").strip()
        do_mask_pii = payload.get("mask_pii", True)
        custom_key = payload.get("api_key", "").strip()
        if custom_key:
            user_api_key = custom_key

    if not text and not image_bytes:
        return jsonify({
            "status": "error",
            "message": "Please enter a message, URL, security log, or upload a screenshot to analyze."
        }), 400

    # Privacy First: Scan & Optionally Redact PII
    pii_warnings = scan_pii(text)
    processed_text = text
    applied_redactions = []

    if do_mask_pii and text:
        processed_text, applied_redactions = mask_pii(text)

    # Perform Analysis
    try:
        report = analyze_with_gemini(
            text=processed_text,
            image_bytes=image_bytes,
            image_mime=image_mime,
            user_api_key=user_api_key
        )

        # Attach privacy audit metadata
        report["privacy_audit"] = {
            "pii_detected": len(pii_warnings) > 0,
            "pii_warnings": pii_warnings,
            "redacted_items": applied_redactions,
            "auto_masked": do_mask_pii,
            "zero_storage_guarantee": "Input processed in volatile memory only; no data stored to disk or database."
        }

        return jsonify({
            "status": "success",
            "data": report
        })

    except Exception as e:
        logger.error(f"Error during threat analysis: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Analysis encountered an error: {str(e)}"
        }), 500

@app.route("/api/set-key", methods=["POST"])
def set_custom_key():
    """Stores custom Gemini API key in session for live API testing"""
    data = request.get_json(silent=True) or {}
    key = data.get("api_key", "").strip()
    if not key:
        session.pop("custom_api_key", None)
        return jsonify({"status": "success", "message": "API key cleared from session."})
    
    session["custom_api_key"] = key
    return jsonify({"status": "success", "message": "API key saved in current session."})

if __name__ == "__main__":
    logger.info(f"Starting CyberShield AI on port {config.FLASK_PORT}...")
    app.run(host="127.0.0.1", port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
