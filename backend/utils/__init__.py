"""Backend utilities package for AI Cybersecurity Detection Platform."""

from .url_feature_extractor import (
    extract_domain,
    extract_subdomains,
    count_special_characters,
    get_url_depth,
    has_suspicious_redirect,
    is_shortened_url,
    get_query_parameters,
    has_encoded_characters,
    get_tld,
    extract_all_features,
    decode_url,
)

from .url_analyzer import (
    calculate_url_risk_score,
    is_phishing_url,
    get_risk_level_description,
    generate_url_report,
    batch_analyze_urls,
    RiskLevel,
    URLRiskScore,
)

from .text_analyzer import (
    calculate_text_risk_score,
    analyze_email_content,
    analyze_webpage_text,
    batch_analyze_texts,
    extract_urls_from_text,
    extract_emails_from_text,
    count_phishing_keywords,
    detect_urgency_language,
    detect_sensitive_requests,
    TextRiskLevel,
    TextAnalysisResult,
)

__all__ = [
    # URL Feature Extraction
    "extract_domain",
    "extract_subdomains",
    "count_special_characters",
    "get_url_depth",
    "has_suspicious_redirect",
    "is_shortened_url",
    "get_query_parameters",
    "has_encoded_characters",
    "get_tld",
    "extract_all_features",
    "decode_url",
    # URL Analysis
    "calculate_url_risk_score",
    "is_phishing_url",
    "get_risk_level_description",
    "generate_url_report",
    "batch_analyze_urls",
    "RiskLevel",
    "URLRiskScore",
    # Text Analysis
    "calculate_text_risk_score",
    "analyze_email_content",
    "analyze_webpage_text",
    "batch_analyze_texts",
    "extract_urls_from_text",
    "extract_emails_from_text",
    "count_phishing_keywords",
    "detect_urgency_language",
    "detect_sensitive_requests",
    "TextRiskLevel",
    "TextAnalysisResult",
]
