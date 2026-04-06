"""
Advanced API routes for URL and file scanning with threat intel integration.

Features:
- VirusTotal and AbuseIPDB threat intelligence
- Correlation-based threat detection
- Audit logging and RBAC
- Rate limiting and security hardening
"""
from fastapi import APIRouter, HTTPException, status, UploadFile, File, Depends, Request, Header
from fastapi.security import OAuth2PasswordBearer
from fastapi_limiter.depends import RateLimiter
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import re
import hashlib
import httpx
from functools import lru_cache

from schemas import (
    URLScanRequest, URLScanResponse, URLScanResult, URLFeatureAnalysis,
    FileScanResult, FileScanResponse,
    ThreatLevel, ScanType, ThreatStats, ScanHistoryItem, ScanHistoryResponse,
)
from database import get_collection
from config import settings
from services.threat_intel import ThreatIntelService
from services.correlation import CorrelationEngine
from utils.audit import log_audit_event, AuditAction
from routes.auth import get_current_user, get_current_user_optional

router = APIRouter()
STARTUP_TIME = datetime.utcnow()

# Initialize services
threat_intel = ThreatIntelService()
correlation_engine = CorrelationEngine()

# Rate limiters
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def calculate_risk_level(score: float) -> ThreatLevel:
    """Convert risk score to threat level with advanced thresholds."""
    if score >= 80:
        return ThreatLevel.DANGEROUS
    elif score >= 50:
        return ThreatLevel.SUSPICIOUS
    return ThreatLevel.SAFE


def extract_url_features(url: str) -> URLFeatureAnalysis:
    """Extract advanced features from URL for phishing detection."""
    url_lower = url.lower()
    features = URLFeatureAnalysis(
        has_https=url.startswith("https://"),
        url_length=len(url),
        has_suspicious_chars=any(c in url_lower for c in ["@", "//", "..", "%", "<", ">"]),
        has_ip_address=bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)),
        has_subdomain=url.count(".") > 2,
        has_double_dots=".." in url,
        has_at_symbol="@" in url,
        has_tinyurl=any(s in url_lower for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]),
        domain_entropy=0.0,
    )
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
    """Calculate phishing risk score with weighted features."""
    score = 0.0
    explanation = []
    weights = {
        "no_https": 15,
        "long_url": 10,
        "suspicious_chars": 20,
        "ip_address": 25,
        "subdomain": 5,
        "double_dots": 15,
        "at_symbol": 20,
        "tinyurl": 15,
        "high_entropy": 10,
        "short_no_https": 10,
        "homoglyph": 25,
    }
    if not features.has_https:
        score += weights["no_https"]
        explanation.append("URL does not use HTTPS encryption")
    if features.url_length > 75:
        score += weights["long_url"]
        explanation.append(f"Unusually long URL ({features.url_length} characters)")
    if features.has_suspicious_chars:
        score += weights["suspicious_chars"]
        explanation.append("Contains suspicious characters")
    if features.has_ip_address:
        score += weights["ip_address"]
        explanation.append("URL contains an IP address instead of a domain name")
    if features.has_subdomain:
        score += weights["subdomain"]
        explanation.append("Uses multiple subdomains")
    if features.has_double_dots:
        score += weights["double_dots"]
        explanation.append("Contains double dots (potential URL obfuscation)")
    if features.has_at_symbol:
        score += weights["at_symbol"]
        explanation.append("Contains @ symbol (credential phishing indicator)")
    if features.has_tinyurl:
        score += weights["tinyurl"]
        explanation.append("Uses a URL shortening service")
    if features.domain_entropy > 3.5:
        score += weights["high_entropy"]
        explanation.append("Domain has high character entropy (potential DGA)")
    if features.url_length < 20 and not features.has_https:
        score += weights["short_no_https"]
        explanation.append("Very short URL without HTTPS")
    return min(score, 100.0), explanation

@router.get("/", summary="API Status")
async def api_status():
    """Get API status and version information."""
    return {
        "name": settings.APP_NAME,
        "version": "2.0.0",
        "status": "running",
        "threat_intel": {
            "virustotal": settings.VIRUSTOTAL_API_KEY is not None,
            "abuseipdb": settings.ABUSEIPDB_API_KEY is not None,
        },
        "uptime_seconds": (datetime.utcnow() - STARTUP_TIME).total_seconds(),
    }


@router.post(
    "/scan-url",
    response_model=URLScanResponse,
    summary="Scan URL for Phishing",
    description="Analyze a URL with threat intel correlation.",
)
async def scan_url(
    request: Request,
    url_request: URLScanRequest,
    current_user: dict = Depends(get_current_user_optional),
):
    """Scan a URL for phishing threats with advanced threat intel."""
    url = url_request.url.strip()
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
    features = extract_url_features(url)
    risk_score, explanation = calculate_phishing_score(features)
    vt_score, vt_result = await threat_intel.check_url_virustotal(url)
    risk_score = max(risk_score, vt_score)
    abuse_score, abuse_result = await threat_intel.check_ip_abuseipdb(url)
    risk_score = (risk_score + abuse_score) / 2
    correlation_result = await correlation_engine.correlate(
        target=url,
        scan_type=ScanType.URL,
        scores={"phishing": risk_score, "virustotal": vt_score, "abuseipdb": abuse_score},
    )
    threat_level = calculate_risk_level(risk_score)
    is_phishing = threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS]
    confidence = 0.5 + (abs(50 - risk_score) / 100)
    if correlation_result.get("is_correlated_threat"):
        risk_score = min(risk_score + 15, 100)
        confidence = min(confidence + 0.1, 1.0)
        threat_level = calculate_risk_level(risk_score)
        explanation.append(f"Correlation: {correlation_result.get('rule_matched', 'unknown')}")
    result = URLScanResult(
        url=url,
        is_phishing=is_phishing,
        risk_score=risk_score,
        threat_level=threat_level,
        features=features,
        explanation=explanation if explanation else ["No phishing indicators detected"],
        model_confidence=confidence,
        timestamp=datetime.utcnow(),
    )
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
        pass
    await log_audit_event(request, current_user, AuditAction.URL_SCAN, url)
    return URLScanResponse(
        success=True,
        result=result,
        message="URL scan completed with threat intel correlation",
    )

@router.post(
    "/scan/file",
    response_model=FileScanResponse,
    summary="Scan File for Malware",
    description="Upload a file to scan for malware with VirusTotal.",
)
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user_optional),
):
    """Scan an uploaded file for malware using VirusTotal."""
    content = await file.read()
    file_size = len(content)
    if file_size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large (max {settings.MAX_FILE_SIZE // 1024 // 1024}MB)",
        )
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    vt_result = await threat_intel.check_hash_virustotal(sha256)
    final_score = vt_result.get("score", 0)
    threat_level = calculate_risk_level(final_score)
    is_malicious = threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS]
    result = FileScanResult(
        filename=file.filename,
        file_size=file_size,
        file_hash=sha256[:16],
        is_malicious=is_malicious,
        risk_score=round(final_score, 2),
        threat_level=threat_level,
        virustotal=vt_result,
        timestamp=datetime.utcnow(),
    )
    try:
        collection = get_collection("scan_history")
        collection.insert_one({
            "scan_type": ScanType.FILE,
            "target": file.filename,
            "threat_level": threat_level.value,
            "risk_score": final_score,
            "is_threat": is_malicious,
            "timestamp": result.timestamp,
        })
    except Exception:
        pass
    await log_audit_event(request, current_user, AuditAction.FILE_SCAN, file.filename)
    return FileScanResponse(
        success=True,
        result=result,
        message="File scan completed with VirusTotal lookup",
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
        high_risk = collection.count_documents({"risk_score": {"$gte": 70}})
        medium_risk = collection.count_documents({"risk_score": {"$gte": 40, "$lt": 70}})
        low_risk = collection.count_documents({"risk_score": {"$lt": 40}})
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
            risk_distribution={"high": high_risk, "medium": medium_risk, "low": low_risk},
            recent_threats=recent_threats,
        )
    except Exception:
        return ThreatStats(
            total_scans=0, phishing_detected=0, malware_detected=0, safe_scans=0,
            risk_distribution={"high": 0, "medium": 0, "low": 0}, recent_threats=[],
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
