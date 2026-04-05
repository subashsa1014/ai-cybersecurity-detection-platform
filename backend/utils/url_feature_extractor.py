"""URL feature extraction utilities for phishing detection."""

import re
from typing import Dict, List
from urllib.parse import urlparse, parse_qs, unquote


def extract_domain(url: str) -> str:
    """Extract the main domain from a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def extract_subdomains(url: str) -> List[str]:
    """Extract subdomains from a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) > 2:
        return parts[:-2]
    return []


def count_special_characters(url: str) -> int:
    """Count special characters in URL."""
    special_chars = "@#$%^&*()+=[]{}|;:'<>?,./~`!-"
    return sum(1 for char in url if char in special_chars)


def get_url_depth(url: str) -> int:
    """Calculate URL path depth."""
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return 0
    return path.count("/") + 1


def has_suspicious_redirect(url: str) -> bool:
    """Check for suspicious redirect patterns."""
    redirect_patterns = [
        r"redirect\s*=",
        r"goto\s*=",
        r"url\s*=",
        r"next\s*=",
        r"return\s*=",
        r"rurl\s*=",
        r"dest\s*=",
        r"destination\s*=",
        r"redir\s*=",
        r"returnUrl\s*=",
    ]
    return any(re.search(pattern, url, re.IGNORECASE) for pattern in redirect_patterns)


def is_shortened_url(url: str) -> bool:
    """Check if URL is from a known URL shortener."""
    shorteners = [
        "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
        "is.gd", "bit.do", "short.link", "cutt.ly", "rebrand.ly"
    ]
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return any(s in hostname for s in shorteners)


def get_query_parameters(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def has_encoded_characters(url: str) -> bool:
    """Check if URL contains encoded characters."""
    return "%" in url and len(re.findall(r"%[0-9a-fA-F]{2}", url)) > 0


def get_tld(url: str) -> str:
    """Extract TLD from URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    return parts[-1] if parts else ""


def extract_all_features(url: str) -> Dict:
    """Extract all URL features for analysis."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": extract_domain(url),
        "subdomains": extract_subdomains(url),
        "subdomain_count": len(extract_subdomains(url)),
        "tld": get_tld(url),
        "path": parsed.path,
        "path_depth": get_url_depth(url),
        "query_params": get_query_parameters(url),
        "query_param_count": len(get_query_parameters(url)),
        "fragment": parsed.fragment,
        "port": parsed.port,
        "has_credentials": "@" in url,
        "special_char_count": count_special_characters(url),
        "has_encoded_chars": has_encoded_characters(url),
        "has_redirect_param": has_suspicious_redirect(url),
        "is_shortened": is_shortened_url(url),
        "url_length": len(url),
    }


def decode_url(url: str) -> str:
    """Decode URL-encoded characters."""
    try:
        return unquote(url)
    except Exception:
        return url
