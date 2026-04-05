"""URL analysis and scoring utilities for phishing detection."""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class URLRiskScore:
    """Container for URL risk assessment."""
    score: float
    risk_level: RiskLevel
    reasons: List[str]
    features: Dict


def calculate_url_risk_score(features: Dict) -> URLRiskScore:
    """
    Calculate risk score for a URL based on extracted features.
    Returns a URLRiskScore with score (0-100), risk level, and reasons.
    """
    score = 0
    reasons = []
    max_score = 100

    # Check for HTTPS vs HTTP
    scheme = features.get("scheme", "").lower()
    if scheme == "http":
        score += 15
        reasons.append("Uses insecure HTTP protocol")
    elif scheme not in ["https", "http"]:
        score += 25
        reasons.append(f"Uses non-standard protocol: {scheme}")

    # Check for IP address in URL
    hostname = features.get("domain", "")
    if hostname and all(part.isdigit() for part in hostname.split(".")):
        score += 30
        reasons.append("Uses IP address instead of domain name")

    # Check for excessive subdomains
    subdomain_count = features.get("subdomain_count", 0)
    if subdomain_count > 3:
        score += 15
        reasons.append(f"Excessive subdomains ({subdomain_count})")
    elif subdomain_count > 0:
        score += 5
        reasons.append(f"Contains {subdomain_count} subdomain(s)")

    # Check for suspicious TLDs
    tld = features.get("tld", "").lower()
    suspicious_tlds = ["xyz", "top", "club", "gq", "ml", "cf", "tk", "ga", "work"]
    if tld in suspicious_tlds:
        score += 20
        reasons.append(f"Suspicious TLD: .{tld}")

    # Check for long URLs
    url_length = features.get("url_length", 0)
    if url_length > 75:
        score += 15
        reasons.append(f"Unusually long URL ({url_length} chars)")
    elif url_length > 50:
        score += 8
        reasons.append(f"Long URL ({url_length} chars)")

    # Check for special characters
    special_char_count = features.get("special_char_count", 0)
    if special_char_count > 10:
        score += 20
        reasons.append(f"Many special characters ({special_char_count})")
    elif special_char_count > 5:
        score += 10
        reasons.append(f"Several special characters ({special_char_count})")

    # Check for URL-encoded characters
    if features.get("has_encoded_chars", False):
        score += 10
        reasons.append("Contains URL-encoded characters")

    # Check for credentials in URL
    if features.get("has_credentials", False):
        score += 25
        reasons.append("Contains credentials in URL (@ symbol)")

    # Check for suspicious redirect parameters
    if features.get("has_redirect_param", False):
        score += 20
        reasons.append("Contains suspicious redirect parameters")

    # Check for shortened URL
    if features.get("is_shortened", False):
        score += 15
        reasons.append("URL is from a shortening service")

    # Check for excessive path depth
    path_depth = features.get("path_depth", 0)
    if path_depth > 5:
        score += 10
        reasons.append(f"Deep path structure ({path_depth} levels)")

    # Check for many query parameters
    query_param_count = features.get("query_param_count", 0)
    if query_param_count > 5:
        score += 8
        reasons.append(f"Many query parameters ({query_param_count})")

    # Check for @ symbol in hostname
    if "@" in features.get("url", ""):
        score += 10
        reasons.append("@ symbol present in URL")

    # Cap score at 100
    score = min(score, max_score)

    # Determine risk level
    if score >= 75:
        risk_level = RiskLevel.CRITICAL
    elif score >= 50:
        risk_level = RiskLevel.HIGH
    elif score >= 25:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return URLRiskScore(
        score=score,
        risk_level=risk_level,
        reasons=reasons,
        features=features
    )


def is_phishing_url(features: Dict, threshold: float = 40.0) -> bool:
    """
    Determine if a URL is likely phishing based on risk score threshold.
    """
    risk_score = calculate_url_risk_score(features)
    return risk_score.score >= threshold


def get_risk_level_description(risk_level: RiskLevel) -> str:
    """Get human-readable description for risk level."""
    descriptions = {
        RiskLevel.LOW: "Low risk - URL appears safe",
        RiskLevel.MEDIUM: "Medium risk - Some suspicious indicators detected",
        RiskLevel.HIGH: "High risk - Multiple suspicious indicators detected",
        RiskLevel.CRITICAL: "Critical risk - URL is very likely malicious"
    }
    return descriptions.get(risk_level, "Unknown risk level")


def generate_url_report(url: str, features: Dict) -> Dict:
    """
    Generate a comprehensive URL analysis report.
    """
    risk_score = calculate_url_risk_score(features)

    return {
        "url": url,
        "is_phishing": risk_score.score >= 40,
        "risk_score": risk_score.score,
        "risk_level": risk_score.risk_level.value,
        "risk_level_description": get_risk_level_description(risk_score.risk_level),
        "risk_reasons": risk_score.reasons,
        "features": features,
        "recommendation": "Block this URL" if risk_score.score >= 50 else "Proceed with caution" if risk_score.score >= 25 else "URL appears safe"
    }


def batch_analyze_urls(urls: List[str]) -> List[Dict]:
    """
    Analyze multiple URLs and return results.
    """
    from .url_feature_extractor import extract_all_features

    results = []
    for url in urls:
        try:
            features = extract_all_features(url)
            report = generate_url_report(url, features)
            results.append(report)
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e),
                "is_phishing": None,
                "risk_score": None,
                "risk_level": "error"
            })

    return results
