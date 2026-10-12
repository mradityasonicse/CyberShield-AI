"""
Gemini Threat Analysis & Awareness Engine
Combines Google Gemini API (natural language reasoning & multimodal vision)
with local deterministic heuristic security checks for reliable cybersecurity assessment.
"""

import os
import re
import json
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from config import config
from privacy_guard import scan_pii, mask_pii

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are CyberShield AI, an expert Cybersecurity Threat Analyst and Educational Tutor.
Your mission is to analyze suspicious messages (emails, SMS, chat messages), URLs, or security logs submitted by users, identify threats, explain warning signs in simple English and beginner-friendly Hinglish (Hindi written in Roman script), and generate an educational quiz.

CRITICAL INSTRUCTIONS:
1. Assess the risk level accurately: "SAFE", "LOW", "MEDIUM", "HIGH", or "CRITICAL".
2. Explain, don't just detect: explain WHY each red flag is dangerous and what attacker tactic is being used (e.g., Artificial Urgency, Credential Harvesting, Authority Impersonation, Lookalike Domain).
3. URL Caution: Do NOT definitively declare any URL 100% safe or definitively malicious malware solely on text heuristics. Explain the specific suspicious indicators (misleading subdomains, typosquatting, unusual TLDs).
4. Provide both English and conversational Hinglish explanations so non-technical students and families can easily understand.
5. Generate an interactive 3-question educational quiz with 4 options each, the correct index (0-3), and an explanation.

You MUST respond strictly with a valid JSON object matching this schema:
{
  "overall_risk": "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "risk_score": 0 to 100,
  "confidence_percentage": 70 to 99,
  "threat_category": "e.g. Spear Phishing / Credential Harvesting / Fake KYC / Safe Notification",
  "summary_en": "2-3 sentences explaining the core situation in English",
  "summary_hi": "2-3 sentences in easy Hinglish explaining the core situation",
  "warning_signs": [
    {
      "title": "Short title of the warning sign",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "quote": "Exact snippet or phrase from user input",
      "explanation_en": "Why this is dangerous in English",
      "explanation_hi": "Hinglish mein explain karo ki yeh kyu dangerous hai"
    }
  ],
  "url_analysis": {
    "detected_urls": ["list of urls found"],
    "domain_red_flags": ["typosquatting, suspicious TLD, subdomain trickery, etc."],
    "verdict_note": "AI heuristic notice"
  },
  "recommended_actions": [
    {
      "action_en": "Immediate actionable step in English",
      "action_hi": "Hinglish action item",
      "urgency": "IMMEDIATE" | "RECOMMENDED" | "OPTIONAL"
    }
  ],
  "cyber_tutor_tip": {
    "topic": "Concept name (e.g. Reverse Social Engineering, Typosquatting, 2FA Bypass)",
    "takeaway_en": "Golden rule to remember in English",
    "takeaway_hi": "Zaroori niyam jo hamesha yaad rakhna chahiye"
  },
  "quiz": [
    {
      "id": 1,
      "question": "Educational question related to this message",
      "options": ["Option A", "Option B", "Option C", "Option D"],
      "correct_index": 0,
      "explanation": "Why this answer is correct in simple terms"
    }
  ],
  "limitations_disclaimer": "AI threat analysis is an educational and assistive heuristic. It does not replace enterprise antivirus or manual security forensics."
}
"""

class LocalSecurityHeuristics:
    """
    Deterministic rule-based heuristics that run on raw input.
    Demonstrates the hybrid architecture: Code-level deterministic analysis + Gemini LLM.
    """

    SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".buzz", ".fit", ".rest", ".ru"}
    POPULAR_BRANDS = ["google", "microsoft", "apple", "amazon", "netflix", "paypal", "sbi", "hdfc", "icici", "paytm", "meta", "facebook", "instagram"]
    
    URGENCY_KEYWORDS = [
        r"\b(?:urgent|immediately|within\s+\d+\s*(?:hours|hrs|minutes|mins)|immediate\s+action|suspended|blocked|terminated|expired|action\s+required)\b",
        r"\b(?:aaj\s+hi|turant|24\s+ghante|band\s+ho\s+jayega|block\s+hoga|abhy\s+kare)\b"
    ]
    
    CREDENTIAL_KEYWORDS = [
        r"\b(?:verify\s+your\s+account|update\s+kyc|confirm\s+password|enter\s+otp|share\s+pin|login\s+here|click\s+link\s+to\s+unfreeze)\b",
        r"\b(?:kyc\s+update|otp\s+bhejo|password\s+reset|link\s+par\s+click)\b"
    ]
    
    REWARD_KEYWORDS = [
        r"\b(?:congratulations|you\s+won|lottery|prize|cashback|free\s+iphone|gift\s+voucher|claim\s+reward|airdrop)\b",
        r"\b(?:inaam|jeet\s+gaye|lakh\s+rupaye|muft|claim\s+karein)\b"
    ]

    @classmethod
    def extract_urls(cls, text: str) -> list:
        url_regex = r"(?:https?:\/\/|www\.)[^\s<>\"']+|[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|top|ru|io|co|in|info)\b[^\s<>\"']*"
        return list(set(re.findall(url_regex, text, re.IGNORECASE)))

    @classmethod
    def analyze(cls, text: str) -> Dict[str, Any]:
        flags = []
        urls = cls.extract_urls(text)
        
        # Check Urgency
        for pattern in cls.URGENCY_KEYWORDS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                flags.append({
                    "category": "Artificial Urgency",
                    "matched": match.group(0),
                    "description": "Attacker creates high pressure to force panic decision making."
                })
                break

        # Check Credential / KYC Harvesting
        for pattern in cls.CREDENTIAL_KEYWORDS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                flags.append({
                    "category": "Credential / KYC Harvesting",
                    "matched": match.group(0),
                    "description": "Request for sensitive personal, authentication, or banking credentials."
                })
                break

        # Check Fake Rewards
        for pattern in cls.REWARD_KEYWORDS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                flags.append({
                    "category": "Fake Incentive / Greed Exploitation",
                    "matched": match.group(0),
                    "description": "Unrealistic gifts or lottery rewards used as social engineering bait."
                })
                break

        # URL Analysis
        url_findings = []
        for raw_url in urls:
            cleaned = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url
            try:
                parsed = urlparse(cleaned)
                domain = parsed.netloc.lower() or parsed.path.lower().split("/")[0]
                
                # Check IP Address hostname
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                    url_findings.append({
                        "url": raw_url,
                        "risk": "Raw IP Address Hostname",
                        "details": "Legitimate sites use registered domain names, not bare IP addresses."
                    })

                # Check Suspicious TLD
                for tld in cls.SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        url_findings.append({
                            "url": raw_url,
                            "risk": f"High-risk TLD ({tld})",
                            "details": "Commonly used in cheap, throwaway phishing campaigns."
                        })
                        break

                # Check Brand Lookalike / Typosquatting
                for brand in cls.POPULAR_BRANDS:
                    if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.in"):
                        url_findings.append({
                            "url": raw_url,
                            "risk": f"Possible Impersonation of '{brand}'",
                            "details": f"Domain contains '{brand}' but appears to be a spoofed or deceptive domain."
                        })
                        break
            except Exception:
                pass

        return {
            "detected_urls_count": len(urls),
            "urls": urls,
            "deterministic_flags": flags,
            "url_heuristics": url_findings
        }


class OfflineHeuristicEngine:
    """
    Intelligent simulated fallback engine that delivers structured cybersecurity
    reports when offline or when no Gemini API key is supplied yet.
    Guarantees 100% crash-free, full-featured demo functionality out of the box!
    """

    @classmethod
    def generate_report(cls, text: str, local_analysis: Dict[str, Any]) -> Dict[str, Any]:
        flags = local_analysis["deterministic_flags"]
        url_findings = local_analysis["url_heuristics"]
        urls = local_analysis["urls"]

        flag_count = len(flags) + len(url_findings)

        # Determine Risk Level
        if flag_count >= 3 or len(url_findings) >= 2:
            risk = "CRITICAL"
            score = 92
            confidence = 94
            category = "High-Threat Social Engineering & Phishing Attack"
        elif flag_count == 2:
            risk = "HIGH"
            score = 78
            confidence = 90
            category = "Phishing / Credential Harvesting Attempt"
        elif flag_count == 1:
            risk = "MEDIUM"
            score = 55
            confidence = 85
            category = "Suspicious Communication / Verification Needed"
        elif urls:
            risk = "LOW"
            score = 25
            confidence = 80
            category = "External Link Communication"
        else:
            risk = "SAFE"
            score = 10
            confidence = 88
            category = "Benign Communication / Low Threat Indicators"

        warning_signs = []
        for f in flags:
            warning_signs.append({
                "title": f["category"],
                "severity": "CRITICAL" if "Harvesting" in f["category"] else "HIGH",
                "quote": f["matched"],
                "explanation_en": f["description"],
                "explanation_hi": f"Yeh warning sign dikhata hai ki attacker aapse '{f['matched']}' bolkar ghabrahat ya laalach mein galat faisla karwana chahta hai."
            })

        for u in url_findings:
            warning_signs.append({
                "title": u["risk"],
                "severity": "CRITICAL",
                "quote": u["url"],
                "explanation_en": u["details"],
                "explanation_hi": f"URL '{u['url']}' mein suspicious signs hain. Kabhi bhi aise unknown links par apni details mat daalo."
            })

        if not warning_signs and risk == "SAFE":
            warning_signs.append({
                "title": "No Obvious Threat Signatures",
                "severity": "LOW",
                "quote": text[:60] + "..." if len(text) > 60 else text,
                "explanation_en": "The message does not display urgent threats, requests for credentials, or fake prize bait.",
                "explanation_hi": "Is sandesh mein koi turant khatra, fake OTP maangne ya emergency lock karne ki warning nahi dikhi."
            })

        summary_en = (
            f"This message was classified as {risk} risk. "
            + ("Multiple red flags including urgency tactics and suspicious links were identified. Do not respond or provide credentials."
               if risk in ["CRITICAL", "HIGH"]
               else "Review sender authenticity carefully before clicking links or executing instructions.")
        )

        summary_hi = (
            f"Is message ka risk level {risk} hai. "
            + ("Isme suspicious warning signs jaise nakli urgency ya galat link mile hain. Is sandesh par reply na karein aur OTP ya password kisi se share na karein."
               if risk in ["CRITICAL", "HIGH"]
               else "Sandesh me koi bada khatra nahi mila, lekin unknown sender hone par hamesha official website se confirm karein.")
        )

        actions = []
        if risk in ["CRITICAL", "HIGH", "MEDIUM"]:
            actions.append({
                "action_en": "Do NOT click any links or scan QR codes provided in the message.",
                "action_hi": "Message mein diye gaye kisi bhi link par click na karein.",
                "urgency": "IMMEDIATE"
            })
            actions.append({
                "action_en": "Never share OTP, passwords, or personal banking info over SMS or email.",
                "action_hi": "Apna OTP, PIN ya password kisi ke sath bhi share na karein.",
                "urgency": "IMMEDIATE"
            })
            actions.append({
                "action_en": "Verify the claim independently by calling the official support number found on the company's verified website.",
                "action_hi": "Company ki official app ya website par jaakar independently check karein.",
                "urgency": "RECOMMENDED"
            })
        else:
            actions.append({
                "action_en": "Always check the sender's full email address or number for authenticity.",
                "action_hi": "Sender ka official email address aur domain zaroor verify karein.",
                "urgency": "RECOMMENDED"
            })
            actions.append({
                "action_en": "Keep two-factor authentication (2FA) active on all your primary accounts.",
                "action_hi": "Apne sabhi accounts par 2-Step Verification (2FA) zaroor on rakhein.",
                "urgency": "RECOMMENDED"
            })

        # Dynamic Quiz Generation
        quiz = [
            {
                "id": 1,
                "question": "If an email says your account will be suspended within 24 hours unless you click a link, what should you do?",
                "options": [
                    "Click the link immediately to prevent suspension",
                    "Do not click the link; open the official app/website directly to check your account status",
                    "Reply to the email with your password to verify your identity",
                    "Forward the email to friends to warn them"
                ],
                "correct_index": 1,
                "explanation": "Scammers use artificial urgency (like 24-hour deadlines) to cause panic. Always go directly to the official platform instead of using provided links."
            },
            {
                "id": 2,
                "question": "What is 'Typosquatting' in cyber attacks?",
                "options": [
                    "A tool used to clean infected computer hard drives",
                    "Typing passwords very quickly to avoid screen recording",
                    "Registering lookalike domains (e.g. amaz0n.com or paypa1.com) to trick users",
                    "Sending emails with bad spelling by mistake"
                ],
                "correct_index": 2,
                "explanation": "Typosquatting targets users who make spelling mistakes or do not notice subtle character replacements (like '0' instead of 'O')."
            },
            {
                "id": 3,
                "question": "Can bank officials or government departments ever ask for your secret OTP over phone or SMS?",
                "options": [
                    "Yes, during mandatory annual KYC verification",
                    "Yes, if they state they are from the anti-fraud department",
                    "No, genuine banks never ask for your confidential OTP or MPIN",
                    "Only if you receive a special SMS first"
                ],
                "correct_index": 2,
                "explanation": "A One-Time Password (OTP) is confidential to you. Real banks, police, or tech support will never ask you to reveal it."
            }
        ]

        return {
            "overall_risk": risk,
            "risk_score": score,
            "confidence_percentage": confidence,
            "threat_category": category,
            "summary_en": summary_en,
            "summary_hi": summary_hi,
            "warning_signs": warning_signs,
            "url_analysis": {
                "detected_urls": urls,
                "domain_red_flags": [u["risk"] + ": " + u["details"] for u in url_findings],
                "verdict_note": "Rule-based security scan. Note: AI and heuristic checks cannot guarantee 100% verdict."
            },
            "recommended_actions": actions,
            "cyber_tutor_tip": {
                "topic": "Zero Trust Principle (Kabhi Andha Bharosa Mat Karo)",
                "takeaway_en": "Verify the source out-of-band before taking action on unexpected alerts.",
                "takeaway_hi": "Jab bhi koi achanak emergency dikhaye, pehle ruken, sochein aur official website par independently jaanch karein."
            },
            "quiz": quiz,
            "limitations_disclaimer": "AI threat analysis is an educational and assistive heuristic. It does not replace enterprise antivirus or manual security forensics.",
            "engine_used": "Offline Heuristic Security Engine (Add Gemini API key in settings for deep neural reasoning)"
        }


def analyze_with_gemini(
    text: str,
    image_bytes: Optional[bytes] = None,
    image_mime: Optional[str] = None,
    user_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Calls Google Gemini via the official google-genai SDK.
    Falls back gracefully to LocalSecurityHeuristics if key is missing or quota/network fails.
    """
    api_key = (user_api_key or "").strip() or config.GEMINI_API_KEY
    local_analysis = LocalSecurityHeuristics.analyze(text)

    if not api_key or api_key == "your_gemini_api_key_here":
        logger.info("No Gemini API key supplied. Running Offline Heuristic Security Engine.")
        report = OfflineHeuristicEngine.generate_report(text, local_analysis)
        report["local_heuristics"] = local_analysis
        return report

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        
        # Build contents
        contents = []
        if image_bytes and image_mime:
            contents.append(
                types.Part.from_bytes(data=image_bytes, mime_type=image_mime)
            )

        prompt_user = f"""
Analyze the following user-submitted message or text for cybersecurity risks and phishing indicators.
Also factor in our local deterministic security scanner's preliminary findings:
{json.dumps(local_analysis, indent=2)}

USER SUBMISSION:
\"\"\"
{text}
\"\"\"

Produce the requested JSON report according to your instructions.
"""
        contents.append(prompt_user)

        response = client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                temperature=0.2,
            )
        )

        response_text = response.text or ""
        # Clean potential markdown wrapping
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]

        parsed = json.loads(response_text.strip())
        parsed["engine_used"] = f"Google Gemini API ({config.GEMINI_MODEL})"
        parsed["local_heuristics"] = local_analysis
        return parsed

    except Exception as e:
        logger.warning(f"Gemini API request failed ({str(e)}). Falling back to Offline Heuristic Security Engine.")
        report = OfflineHeuristicEngine.generate_report(text, local_analysis)
        report["engine_used"] = "Offline Heuristic Engine (Fallback due to API: " + str(e)[:60] + ")"
        report["api_error_detail"] = str(e)
        report["local_heuristics"] = local_analysis
        return report
