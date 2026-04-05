"""
Pydantic schemas for request/response validation.
"""

from pydantic import BaseModel, EmailStr, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class ScanType(str, Enum):
    URL = "url"
    FILE = "file"


# --- URL Scanning Schemas ---

class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to scan for phishing")

    @classmethod
    def example(cls):
        return {"url": "https://example.com/login"}


class URLFeatureAnalysis(BaseModel):
    has_https: bool
    url_length: int
    has_suspicious_chars: bool
    has_ip_address: bool
    domain_age_days: Optional[int] = None
    has_subdomain: bool
    has_double_dots: bool
    has_at_symbol: bool
    has_tinyurl: bool
    domain_entropy: float


class URLScanResult(BaseModel):
    url: str
    is_phishing: bool
    risk_score: float  # 0-100
    threat_level: ThreatLevel
    features: URLFeatureAnalysis
    explanation: List[str]
    model_confidence: float
    timestamp: datetime


class URLScanResponse(BaseModel):
    success: bool
    result: URLScanResult
    message: str


# --- File Scanning Schemas ---

class FileScanResult(BaseModel):
    filename: str
    file_size: int
    file_hash: str
    is_malicious: bool
    risk_score: float
    threat_level: ThreatLevel
    signatures_matched: List[str]
    ml_prediction: Dict[str, Any]
    explanation: List[str]
    timestamp: datetime


class FileScanResponse(BaseModel):
    success: bool
    result: FileScanResult
    message: str


# --- Authentication Schemas ---

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# --- Dashboard Schemas ---

class ThreatStats(BaseModel):
    total_scans: int
    phishing_detected: int
    malware_detected: int
    safe_scans: int
    risk_distribution: Dict[str, int]
    recent_threats: List[Dict[str, Any]]


class ScanHistoryItem(BaseModel):
    id: str
    scan_type: ScanType
    target: str
    threat_level: ThreatLevel
    risk_score: float
    is_threat: bool
    timestamp: datetime


class ScanHistoryResponse(BaseModel):
    total: int
    scans: List[ScanHistoryItem]


# --- API Response Schemas ---

class APIStatusResponse(BaseModel):
    status: str
    version: str
    uptime: float


class ErrorResponse(BaseModel):
    detail: str
    path: str
