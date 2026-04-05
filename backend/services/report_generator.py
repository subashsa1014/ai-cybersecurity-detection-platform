"""Scan report generation service for creating detailed security reports."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4


class ReportGenerator:
    """Generates detailed security scan reports with recommendations."""

    URL_RECOMMENDATIONS = {
        "suspicious_tld": "Consider using a more trusted domain with a standard TLD like .com or .org.",
        "ip_address": "Avoid using IP addresses directly. Use a proper domain name with HTTPS.",
        "long_url": "Shorten the URL and remove unnecessary parameters.",
        "multiple_subdomains": "Reduce the number of subdomains to appear more legitimate.",
        "phishing_keywords": "Remove suspicious keywords that may indicate phishing intent.",
        "hex_encoding": "Avoid hex-encoded characters in URLs as they are commonly used in attacks.",
        "at_symbol": "The @ symbol is often used for credential harvesting. Remove it.",
        "suspicious_port": "Use standard ports (80 for HTTP, 443 for HTTPS).",
        "missing_https": "Enable HTTPS to encrypt data in transit.",
        "excessive_query_params": "Reduce the number of query parameters for better security.",
        "brand_impersonation": "Do not use brand names in URLs unless you own the domain.",
    }

    FILE_RECOMMENDATIONS = {
        "malicious_pattern": "Remove or quarantine files containing malicious code patterns.",
        "suspicious_extension": "Verify the file source before opening files with this extension.",
        "large_file": "Scan large files with additional tools for thorough analysis.",
        "empty_file": "Empty files may be placeholders for malicious content. Investigate further.",
    }

    def __init__(self):
        pass

    def generate_url_report(self, scan_result: Dict) -> Dict:
        report_id = str(uuid4())
        recommendations = []
        features = scan_result.get("features", {})

        for feature, value in features.items():
            if value and feature in self.URL_RECOMMENDATIONS:
                recommendations.append({
                    "issue": feature.replace("_", " ").title(),
                    "recommendation": self.URL_RECOMMENDATIONS[feature],
                })

        if not recommendations:
            recommendations.append({
                "issue": "No significant issues detected",
                "recommendation": "Continue following security best practices.",
            })

        return {
            "report_id": report_id,
            "report_type": "url_scan",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_result": scan_result,
            "summary": {
                "url": scan_result.get("url", ""),
                "risk_level": scan_result.get("risk_level", "unknown"),
                "risk_score": scan_result.get("risk_score", 0),
                "is_phishing": scan_result.get("is_phishing", False),
            },
            "recommendations": recommendations,
        }

    def generate_file_report(self, scan_result: Dict) -> Dict:
        report_id = str(uuid4())
        recommendations = []
        reasons = scan_result.get("reasons", [])

        for reason in reasons:
            if "pattern" in reason.lower():
                recommendations.append({
                    "issue": "Malicious code pattern detected",
                    "recommendation": self.FILE_RECOMMENDATIONS["malicious_pattern"],
                })
            elif "extension" in reason.lower():
                recommendations.append({
                    "issue": "Suspicious file extension",
                    "recommendation": self.FILE_RECOMMENDATIONS["suspicious_extension"],
                })
            elif "large" in reason.lower():
                recommendations.append({
                    "issue": "Large file size",
                    "recommendation": self.FILE_RECOMMENDATIONS["large_file"],
                })
            elif "empty" in reason.lower():
                recommendations.append({
                    "issue": "Empty file",
                    "recommendation": self.FILE_RECOMMENDATIONS["empty_file"],
                })

        if not recommendations:
            recommendations.append({
                "issue": "No significant issues detected",
                "recommendation": "File appears safe based on current analysis.",
            })

        return {
            "report_id": report_id,
            "report_type": "file_scan",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_result": scan_result,
            "summary": {
                "filename": scan_result.get("filename", ""),
                "risk_level": scan_result.get("risk_level", "unknown"),
                "risk_score": scan_result.get("risk_score", 0),
                "is_malicious": scan_result.get("is_malicious", False),
                "file_size": scan_result.get("file_size", 0),
            },
            "recommendations": recommendations,
        }

    def generate_dashboard_report(self, stats: Dict, recent_scans: List[Dict]) -> Dict:
        return {
            "report_id": str(uuid4()),
            "report_type": "dashboard",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "statistics": stats,
            "recent_scans": recent_scans[:10],
        }


generator = ReportGenerator()
