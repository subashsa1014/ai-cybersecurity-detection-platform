"""ML-based phishing URL detection service using heuristics, rule-based scoring, and ensemble ML models."""

import re
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from .ml_classifier import MLClassifier


class PhishingDetector:
    """Hybrid phishing URL detector using heuristics, ML classification, and feature extraction."""

    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan", ".zip", ".click",
        ".work", ".date", ".bid", ".gdn", ".stream", ".download"
    }

    PHISHING_KEYWORDS = {
        "login", "signin", "account", "verify", "secure", "update", "password",
        "banking", "paypal", "apple", "microsoft", "amazon", "google", "facebook",
        "suspended", "urgent", "confirm", "alert", "warning", "locked"
    }

    IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    HEX_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")
    AT_SYMBOL = re.compile(r"@")
    PORT_PATTERN = re.compile(r":\d{2,5}")
    SUBDOMAIN_PATTERN = re.compile(r"^[^.]+\.[^.]+\.[^.]+")

    def __init__(self, use_ml: bool = True):
        self.weights = {
            "suspicious_tld": 25,
            "ip_address": 30,
            "long_url": 10,
            "multiple_subdomains": 15,
            "phishing_keywords": 20,
            "hex_encoding": 10,
            "at_symbol": 20,
            "suspicious_port": 10,
            "missing_https": 15,
            "excessive_query_params": 10,
            "brand_impersonation": 25,
        }
        self.use_ml = use_ml
        self.ml_classifier: Optional[MLClassifier] = None
        if self.use_ml:
            self.ml_classifier = MLClassifier()

    def extract_features(self, url: str) -> Dict:
        """Extract heuristic features from URL for risk scoring."""
        features = {}
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        features["url_length"] = len(url)
        features["has_suspicious_tld"] = any(url.lower().endswith(tld) for tld in self.SUSPICIOUS_TLDS)
        features["is_ip_address"] = bool(self.IP_PATTERN.match(hostname))
        features["subdomain_count"] = hostname.count(".")
        features["keyword_count"] = sum(1 for kw in self.PHISHING_KEYWORDS if kw in url.lower())
        features["has_hex_encoding"] = bool(self.HEX_ENCODED.search(url))
        features["has_at_symbol"] = bool(self.AT_SYMBOL.search(url))
        features["has_suspicious_port"] = bool(self.PORT_PATTERN.search(url))
        features["is_https"] = parsed.scheme == "https"
        features["query_param_count"] = len(parse_qs(query))
        features["has_brand_keywords"] = any(
            brand in url.lower() for brand in ["paypal", "amazon", "microsoft", "apple", "google", "facebook"]
        )
        return features

    def calculate_risk_score(self, features: Dict) -> Tuple[int, List[str]]:
        """Calculate heuristic risk score based on extracted features."""
        score = 0
        reasons = []

        if features.get("has_suspicious_tld"):
            score += self.weights["suspicious_tld"]
            reasons.append("Suspicious TLD detected")
        if features.get("is_ip_address"):
            score += self.weights["ip_address"]
            reasons.append("IP address used instead of domain")
        if features.get("url_length", 0) > 75:
            score += self.weights["long_url"]
            reasons.append("Unusually long URL")
        if features.get("subdomain_count", 0) > 2:
            score += self.weights["multiple_subdomains"]
            reasons.append("Multiple subdomains detected")
        if features.get("keyword_count", 0) > 0:
            kw_score = min(features["keyword_count"] * 10, self.weights["phishing_keywords"])
            score += kw_score
            reasons.append(f"Phishing-related keywords found ({features['keyword_count']})")
        if features.get("has_hex_encoding"):
            score += self.weights["hex_encoding"]
            reasons.append("Hex-encoded characters in URL")
        if features.get("has_at_symbol"):
            score += self.weights["at_symbol"]
            reasons.append("@ symbol in URL (credential harvesting technique)")
        if features.get("has_suspicious_port"):
            score += self.weights["suspicious_port"]
            reasons.append("Non-standard port detected")
        if not features.get("is_https"):
            score += self.weights["missing_https"]
            reasons.append("Not using HTTPS")
        if features.get("query_param_count", 0) > 5:
            score += self.weights["excessive_query_params"]
            reasons.append("Excessive query parameters")
        if features.get("has_brand_keywords") and not features.get("is_https"):
            score += self.weights["brand_impersonation"]
            reasons.append("Brand name in URL without HTTPS")

        score = min(score, 100)
        return score, reasons

    def classify_risk(self, score: int) -> str:
        """Classify risk level based on score."""
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 15:
            return "low"
        else:
            return "safe"

    def get_ml_prediction(self, url: str) -> Optional[Dict]:
        """Get ML model prediction for URL."""
        if not self.ml_classifier:
            return None
        try:
            result = self.ml_classifier.predict_url(url)
            return result
        except Exception as e:
            return {"error": str(e), "ml_available": False}

    def detect(self, url: str, use_ml: bool = None) -> Dict:
        """Detect phishing using hybrid heuristic + ML approach."""
        use_ml = use_ml if use_ml is not None else self.use_ml

        # Heuristic detection
        features = self.extract_features(url)
        score, reasons = self.calculate_risk_score(features)
        risk_level = self.classify_risk(score)
        is_phishing = risk_level in ["high", "medium"]

        result = {
            "url": url,
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "risk_score": score,
            "reasons": reasons,
            "features": features,
            "detection_method": "heuristic",
        }

        # ML detection
        if use_ml and self.ml_classifier:
            ml_result = self.get_ml_prediction(url)
            if ml_result and "error" not in ml_result:
                result["ml_prediction"] = ml_result
                result["ml_confidence"] = ml_result.get("confidence", 0)
                result["ml_is_phishing"] = ml_result.get("is_phishing", False)
                # Combine heuristic and ML
                if ml_result.get("is_phishing"):
                    result["is_phishing"] = True
                    if risk_level == "low":
                        result["risk_level"] = "medium"
                result["detection_method"] = "hybrid"

        return result

    def detect_batch(self, urls: List[str]) -> List[Dict]:
        """Detect phishing for multiple URLs."""
        return [self.detect(url) for url in urls]


detector = PhishingDetector()
