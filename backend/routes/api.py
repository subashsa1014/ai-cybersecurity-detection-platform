"""
API routes for URL and file scanning.
"""

from fastapi import APIRouter, HTTPException, status, UploadFile, File, Depends
from datetime import datetime
from typing import Dict, Any
import re

from schemas import (
    URLScanRequest, URLScanResponse, URLScanResult, URLFeatureAnalysis,
    FileScanResult, FileScanResponse,
    ThreatLevel, ScanType, ThreatStats, ScanHistoryItem, ScanHistoryResponse,
)
from database import get_collection
from config import settings

router = APIRouter()

STARTUP_TIME = datetime.now()


def calculate_risk_level(score: float) -> ThreatLevel:
    """Convert risk score to threat level."""
    if score >= 70:
        return ThreatLevel.DANGEROUS
    elif score >= 40:
        return ThreatLevel.SUSPICIOUS
    return ThreatLevel.SAFE


def extract_url_features(url: str) -> URLFeatureAnalysis:
    """Extract features from URL for phishing detection."""
    # Normalize URL
    url_lower = url.lower()

    features = URLFeatureAnalysis(
        has_https=url.startswith("https://"),
        url_length=len(url),
        has_suspicious_chars=any(c in url_lower for c in ["@", "//", "..", "%", "<", ">"]),
        has_ip_address=bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)),
        has_subdomain=url.count(".") > 2,
        has_double_dots=".." in url,
        has_at_symbol="@" in url,
        has_tinyurl=any(s in url_lower for s in ["bit.ly", "tinyurl", "goo.gl", "t.co"]),
        domain_entropy=0.0,
    )

    # Calculate domain entropy
    domain_match = re.search(r"//([^/]+)", url)
    if domain_match:
        domain = domain_match.group(1)
        char_freq = {}
        for c in domain:
            char_freq[c] = char_freq.get(c, 0) + 1
        total = len(domain)
        features.domain_entropy = sum(
            -((count / total) * (count / total)) for count in char_freq.values()
        )

    return features


def calculate_phishing_score(features: URLFeatureAnalysis) -> tuple[float, list[str]]:
    """Calculate phishing risk score and explanation."""
    score = 0.0
    explanation = []

    # No HTTPS
    if not features.has_https:
        score += 15
        explanation.append("URL does not use HTTPS encryption")

    # Long URL
    if features.url_length > 75:
        score += 10
        explanation.append(f"Unusually long URL ({features.url_length} characters)")

    # Suspicious characters
    if features.has_suspicious_chars:
        score += 20
        explanation.append("Contains suspicious characters")

    # IP address in URL
    if features.has_ip_address:
        score += 25
        explanation.append("URL contains an IP address instead of a domain name")

    # Subdomain
    if features.has_subdomain:
        score += 5
        explanation.append("Uses multiple subdomains")

    # Double dots
    if features.has_double_dots:
        score += 15
        explanation.append("Contains double dots (potential URL obfuscation)")

    # @ symbol
    if features.has_at_symbol:
        score += 20
        explanation.append("Contains @ symbol (credential phishing indicator)")

    # Tiny URL shorteners
    if features.has_tinyurl:
        score += 15
        explanation.append("Uses a URL shortening service")

    # High entropy domain
    if features.domain_entropy > 3.5:
        score += 10
        explanation.append("Domain has high character entropy (potential DGA)")

    # Short domain
    if features.url_length < 20 and not features.has_https:
        score += 10
        explanation.append("Very short URL without HTTPS")

    return min(score, 100.0), explanation


@router.get("/", summary="API Status")
async def api_status():
    """Get API status and version information."""
    return {
        "name": settings.APP_NAME,
        "version": "1.0.0",
        "status": "running",
        "uptime_seconds": (datetime.now() - STARTUP_TIME).total_seconds(),
    }


@router.post(
    "/scan-url",
    response_model=URLScanResponse,
    summary="Scan URL for Phishing",
    description="Analyze a URL and determine if it is a phishing attempt.",
)
async def scan_url(request: URLScanRequest):
    """Scan a URL for phishing threats."""
    url = request.url.strip()

    # Validate URL format
    url_pattern = re.compile(
        r"^(?:http|ftp)s?://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    if not url_pattern.match(url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format",
        )

    # Extract features
    features = extract_url_features(url)

    # Calculate score
    risk_score, explanation = calculate_phishing_score(features)

    # Determine threat level
    threat_level = calculate_risk_level(risk_score)
    is_phishing = threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS]

    # Model confidence (higher for extreme scores)
    confidence = 0.5 + (abs(50 - risk_score) / 100)

    result = URLScanResult(
        url=url,
        is_phishing=is_phishing,
        risk_score=risk_score,
        threat_level=threat_level,
        features=features,
        explanation=explanation if explanation else ["No phishing indicators detected"],
        model_confidence=confidence,
        timestamp=datetime.now(),
    )

    # Save scan history
    try:
        collection = get_collection("scan_history")
        collection.insert_one({
            "scan_type": ScanType.URL,
            "target": url,
            "threat_level": threat_level.value,
            "risk_score": risk_score,
            "is_threat": is_phishing,
            "timestamp": result.timestamp,
        })
    except Exception:
        pass  # Non-critical, continue

    return URLScanResponse(
        success=True,
        result=result,
        message="URL scan completed successfully",
    )


@router.post(
    "/scan-file",
    response_model=FileScanResponse,
    summary="Scan File for Malware",
    description="Upload a file to scan for malware and threats.",
)
async def scan_file(file: UploadFile = File(...)):
    """Scan an uploaded file for malware."""
    content = await file.read()
    file_size = len(content)

    if file_size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE // 1024 // 1024}MB",
        )

    # Calculate file hash (simple implementation)
    file_hash = hex(hash(content))[2:]

    # Basic malware detection (signature-based + heuristic)
    signatures_matched = []
    risk_score = 0.0
    explanation = []

    # Check for common malicious patterns
    content_str = content.decode("utf-8", errors="ignore").lower()

    # Suspicious strings
    suspicious_patterns = [
        ("powershell", 20),
        ("cmd.exe", 20),
        ("wscript", 15),
        ("eval(", 25),
        ("exec(", 25),
        ("base64", 15),
        ("shellcode", 30),
        ("xor decrypt", 25),
        ("http_download", 20),
        ("regedit", 15),
        ("startup", 10),
        ("hidden", 10),
    ]

    for pattern, score in suspicious_patterns:
        if pattern in content_str:
            signatures_matched.append(f"Pattern: {pattern}")
            risk_score += score
            explanation.append(f"Found suspicious pattern: {pattern}")

    # File extension check
    ext = file.filename.split(".")[-1].lower() if "." in file.filename else ""
    risky_extensions = ["exe", "dll", "scr", "bat", "cmd", "vbs", "ps1"]
    if ext in risky_extensions:
        risk_score += 15
        explanation.append(f"Executable file type: .{ext}")

    # Large file without known signature
    if file_size > 1024 * 1024 and not signatures_matched:  # >1MB
        risk_score += 5
        explanation.append("Large file with no identifiable signature")

    risk_score = min(risk_score, 100.0)
    threat_level = calculate_risk_level(risk_score)
    is_malicious = threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS]

    result = FileScanResult(
        filename=file.filename,
        file_size=file_size,
        file_hash=file_hash,
        is_malicious=is_malicious,
        risk_score=risk_score,
        threat_level=threat_level,
        signatures_matched=signatures_matched,
        ml_prediction={"model": "signature_based", "version": "1.0"},
        explanation=explanation if explanation else ["No malware signatures detected"],
        timestamp=datetime.now(),
    )

    # Save scan history
    try:
        collection = get_collection("scan_history")
        collection.insert_one({
            "scan_type": ScanType.FILE,
            "target": file.filename,
            "threat_level": threat_level.value,
            "risk_score": risk_score,
            "is_threat": is_malicious,
            "timestamp": result.timestamp,
        })
    except Exception:
        pass

    return FileScanResponse(
        success=True,
        result=result,
        message="File scan completed successfully",
    )


@router.get("/dashboard/threats", response_model=ThreatStats, summary="Get Threat Statistics")
async def get_threat_stats():
    """Get threat statistics for the dashboard."""
    try:
        collection = get_collection("scan_history")

        total_scans = collection.count_documents({})
        phishing = collection.count_documents({"scan_type": ScanType.URL, "is_threat": True})
        malware = collection.count_documents({"scan_type": ScanType.FILE, "is_threat": True})
        safe = collection.count_documents({"is_threat": False})

        # Risk distribution
        high_risk = collection.count_documents({"risk_score": {"$gte": 70}})
        medium_risk = collection.count_documents({"risk_score": {"$gte": 40, "$lt": 70}})
        low_risk = collection.count_documents({"risk_score": {"$lt": 40}})

        # Recent threats
        recent_cursor = collection.find({"is_threat": True}).sort("timestamp", -1).limit(5)
        recent_threats = [
            {
                "target": doc["target"],
                "type": doc["scan_type"],
                "risk_score": doc["risk_score"],
            }
            for doc in recent_cursor
        ]

        return ThreatStats(
            total_scans=total_scans,
            phishing_detected=phishing,
            malware_detected=malware,
            safe_scans=safe,
            risk_distribution={
                "high": high_risk,
                "medium": medium_risk,
                "low": low_risk,
            },
            recent_threats=recent_threats,
        )
    except Exception:
        return ThreatStats(
            total_scans=0,
            phishing_detected=0,
            malware_detected=0,
            safe_scans=0,
            risk_distribution={"high": 0, "medium": 0, "low": 0},
            recent_threats=[],
        )


@router.get("/dashboard/history", response_model=ScanHistoryResponse, summary="Get Scan History")
async def get_scan_history(limit: int = 20):
    """Get recent scan history."""
    try:
        collection = get_collection("scan_history")
        total = collection.count_documents({})

        cursor = collection.find().sort("timestamp", -1).limit(limit)
        scans = [
            ScanHistoryItem(
                id=str(doc.get("_id", "")),
                scan_type=doc["scan_type"],
                target=doc["target"],
                threat_level=ThreatLevel(doc["threat_level"]),
                risk_score=doc["risk_score"],
                is_threat=doc["is_threat"],
                timestamp=doc["timestamp"],
            )
            for doc in cursor
        ]

        return ScanHistoryResponse(total=total, scans=scans)
    except Exception:
        return ScanHistoryResponse(total=0, scans=[])
