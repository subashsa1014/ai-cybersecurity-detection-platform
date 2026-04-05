"""Text analysis utilities for phishing detection in email and web content."""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class TextRiskLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


@dataclass
class TextAnalysisResult:
    """Container for text analysis results."""
    risk_level: TextRiskLevel
    score: float
    indicators: List[str]
    metrics: Dict


# Phishing keywords commonly used in attacks
PHISHING_KEYWORDS = [
    "urgent", "immediately", "verify", "confirm", "suspended",
    "locked", "compromised", "unusual activity", "security alert",
    "update your account", "click here", "act now", "limited time",
    "password expired", "account blocked", "suspended account",
    "final notice", "last warning", "action required",
    "unauthorized access", "suspicious login", "verify identity",
    "claim your", "congratulations", "you won", "prize",
    "free", "winner", "lottery", "inheritance", "million dollars",
    "nigerian prince", "foreign dignitary", "business proposal",
    "wire transfer", "bank account", "routing number",
    "ssn", "social security", "credit card", "cvv",
    "login credentials", "username", "password",
    "bitly", "tinyurl", "goo.gl", "t.co"
]

# Legitimate-looking patterns that indicate urgency manipulation
URGENCY_PATTERNS = [
    r"\b(expire|expires|expired)\b",
    r"\b(within\s+(\d+\s+)?(hour|minute|day)s?)\b",
    r"\b(last\s+(chance|opportunity|warning|notice))\b",
    r"\b(immediately|urgently|asap|right now)\b",
    r"\b(act\s+(fast|now|quickly))\b",
    r"\b(don\'t\s+miss|miss\s+out)\b",
    r"\b(limited\s+(time|offer|spots))\b"
]

# Patterns indicating request for sensitive information
SENSITIVE_REQUEST_PATTERNS = [
    r"\b(provide|enter|submit|send|share)\s+(your\s+)?(password|pin|ssn|credit\s+card|bank\s+account|cvv|security\s+code)\b",
    r"\b(update|verify|confirm)\s+(your\s+)?(account|identity|information|details)\b",
    r"\b(click\s+(here|the\s+link|below))\b",
    r"\b(download|open|run)\s+(the\s+)?(attachment|file|document)\b"
]


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from text content."""
    url_pattern = r'https?://[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def extract_emails_from_text(text: str) -> List[str]:
    """Extract email addresses from text content."""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)


def count_phishing_keywords(text: str) -> Dict[str, int]:
    """Count occurrences of phishing-related keywords."""
    text_lower = text.lower()
    keyword_counts = {}

    for keyword in PHISHING_KEYWORDS:
        count = text_lower.count(keyword.lower())
        if count > 0:
            keyword_counts[keyword] = count

    return keyword_counts


def detect_urgency_language(text: str) -> List[str]:
    """Detect urgency-inducing language patterns."""
    detected = []
    text_lower = text.lower()

    for pattern in URGENCY_PATTERNS:
        matches = re.findall(pattern, text_lower)
        if matches:
            detected.append(f"Urgency pattern: {matches[0]}")

    return detected


def detect_sensitive_requests(text: str) -> List[str]:
    """Detect requests for sensitive information."""
    detected = []

    for pattern in SENSITIVE_REQUEST_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            detected.append(f"Sensitive request: {matches[0]}")

    return detected


def calculate_text_risk_score(text: str) -> TextAnalysisResult:
    """
    Calculate risk score for text content based on multiple indicators.
    """
    score = 0
    indicators = []

    # Keyword analysis
    keyword_counts = count_phishing_keywords(text)
    total_keywords = sum(keyword_counts.values())
    if total_keywords >= 5:
        score += 30
        indicators.append(f"High phishing keyword count ({total_keywords})")
    elif total_keywords >= 2:
        score += 15
        indicators.append(f"Phishing keywords found ({total_keywords})")

    # Urgency language detection
    urgency_patterns = detect_urgency_language(text)
    if len(urgency_patterns) >= 3:
        score += 25
        indicators.append(f"Multiple urgency patterns ({len(urgency_patterns)})")
    elif urgency_patterns:
        score += 10
        indicators.append(f"Urgency language detected ({len(urgency_patterns)})")

    # Sensitive request detection
    sensitive_requests = detect_sensitive_requests(text)
    if sensitive_requests:
        score += 25
        indicators.append(f"Sensitive info requests ({len(sensitive_requests)})")

    # URL analysis
    urls = extract_urls_from_text(text)
    if urls:
        score += min(len(urls) * 5, 20)
        indicators.append(f"URLs found in text ({len(urls)})")

    # All caps detection (shouting = urgency)
    words = text.split()
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    if len(caps_words) > len(words) * 0.1:
        score += 10
        indicators.append("Excessive use of capital letters")

    # Exclamation marks
    exclamation_count = text.count('!')
    if exclamation_count > 5:
        score += 10
        indicators.append(f"Excessive exclamation marks ({exclamation_count})")

    # Question marks
    question_count = text.count('?')
    if question_count > 5:
        score += 5
        indicators.append(f"Many questions ({question_count})")

    # Email analysis
    emails = extract_emails_from_text(text)
    if emails:
        score += 5
        indicators.append(f"Email addresses found ({len(emails)})")

    # Check for mixed scripts (potential homograph attack)
    if len(set(ord(c) for c in text)) > len(text) * 0.95 and len(text) > 50:
        score += 15
        indicators.append("Potential mixed-script attack (homograph)")

    # Cap score
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = TextRiskLevel.DANGEROUS
    elif score >= 30:
        risk_level = TextRiskLevel.SUSPICIOUS
    else:
        risk_level = TextRiskLevel.SAFE

    metrics = {
        "keyword_count": total_keywords,
        "urgency_patterns": len(urgency_patterns),
        "sensitive_requests": len(sensitive_requests),
        "urls_found": len(urls),
        "emails_found": len(emails),
        "caps_ratio": len(caps_words) / len(words) if words else 0,
        "exclamation_count": exclamation_count,
        "keyword_details": keyword_counts
    }

    return TextAnalysisResult(
        risk_level=risk_level,
        score=score,
        indicators=indicators,
        metrics=metrics
    )


def analyze_email_content(subject: str, body: str) -> Dict:
    """
    Analyze email content for phishing indicators.
    """
    text = f"{subject} {body}"
    result = calculate_text_risk_score(text)

    subject_analysis = calculate_text_risk_score(subject)
    body_analysis = calculate_text_risk_score(body)

    return {
        "overall": {
            "risk_level": result.risk_level.value,
            "score": result.score,
            "indicators": result.indicators,
            "metrics": result.metrics
        },
        "subject": {
            "risk_level": subject_analysis.risk_level.value,
            "score": subject_analysis.score,
            "indicators": subject_analysis.indicators
        },
        "body": {
            "risk_level": body_analysis.risk_level.value,
            "score": body_analysis.score,
            "indicators": body_analysis.indicators
        },
        "extracted_urls": extract_urls_from_text(text),
        "extracted_emails": extract_emails_from_text(text),
        "is_phishing": result.score >= 40,
        "recommendation": "Do not open or reply" if result.score >= 50 else "Verify sender before responding" if result.score >= 25 else "Content appears safe"
    }


def analyze_webpage_text(html_text: str) -> Dict:
    """
    Analyze webpage text content for phishing indicators.
    """
    result = calculate_text_risk_score(html_text)

    return {
        "risk_level": result.risk_level.value,
        "score": result.score,
        "indicators": result.indicators,
        "metrics": result.metrics,
        "is_phishing": result.score >= 40,
        "extracted_urls": extract_urls_from_text(html_text),
        "recommendation": "Do not interact with this page" if result.score >= 50 else "Verify the website" if result.score >= 25 else "Page appears safe"
    }


def batch_analyze_texts(texts: List[str]) -> List[Dict]:
    """
    Analyze multiple text samples and return results.
    """
    results = []
    for text in texts:
        try:
            result = calculate_text_risk_score(text)
            results.append({
                "risk_level": result.risk_level.value,
                "score": result.score,
                "indicators": result.indicators,
                "is_phishing": result.score >= 40
            })
        except Exception as e:
            results.append({
                "error": str(e),
                "risk_level": "error",
                "score": None
            })

    return results
