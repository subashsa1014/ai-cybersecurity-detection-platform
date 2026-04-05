"""Pytest configuration and fixtures for AI Cybersecurity Detection Platform tests."""
import pytest
import asyncio
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app import app
from backend.database import mongodb_client, database
from backend.schemas import ThreatLevel, ScanType


# --- Test Fixtures ---

@pytest.fixture
def sample_phishing_url():
    """Return a sample phishing URL for testing."""
    return "https://secure-paypal-login.verify-account.tk/signin?user=test"


@pytest.fixture
def sample_safe_url():
    """Return a sample safe URL for testing."""
    return "https://www.google.com/search?q=python"


@pytest.fixture
def sample_malicious_content():
    """Return sample malicious file content for testing."""
    return b"<?php eval(base64_decode($_POST['cmd'])); ?>"


@pytest.fixture
def sample_safe_content():
    """Return sample safe file content for testing."""
    return b"<?php echo 'Hello World'; ?>"


@pytest.fixture
async def async_client():
    """Create an async test client for FastAPI app."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_mongodb():
    """Mock MongoDB connection for unit tests."""
    mock_client = AsyncMock()
    mock_db = AsyncMock()
    mock_collection = AsyncMock()
    
    mock_db.__getitem__.return_value = mock_collection
    mock_client.__getitem__.return_value = mock_db
    
    return mock_client, mock_db, mock_collection


@pytest.fixture
def mock_jwt_token():
    """Generate a mock JWT token for testing."""
    import jwt
    from datetime import datetime, timedelta
    
    payload = {
        "sub": "test@example.com",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, "test_secret", algorithm="HS256")


@pytest.fixture
def sample_user_data():
    """Return sample user registration data."""
    return {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "full_name": "Test User"
    }


@pytest.fixture
def sample_login_data():
    """Return sample login data."""
    return {
        "email": "test@example.com",
        "password": "SecurePass123!"
    }


@pytest.fixture
def sample_url_scan_request():
    """Return sample URL scan request data."""
    return {
        "url": "https://example.com/login"
    }


@pytest.fixture
def sample_threat_stats():
    """Return sample threat statistics."""
    return {
        "total_scans": 100,
        "threats_detected": 25,
        "safe_results": 75,
        "avg_risk_score": 35.5
    }


@pytest.fixture
def sample_scan_history():
    """Return sample scan history items."""
    return [
        {
            "id": "scan_001",
            "url": "https://suspicious-site.tk/login",
            "threat_level": "dangerous",
            "risk_score": 85.0,
            "timestamp": "2024-01-15T10:30:00Z"
        },
        {
            "id": "scan_002",
            "url": "https://google.com",
            "threat_level": "safe",
            "risk_score": 5.0,
            "timestamp": "2024-01-15T11:00:00Z"
        }
    ]


@pytest.fixture
def sample_file_scan_result():
    """Return sample file scan result."""
    return {
        "filename": "suspicious.php",
        "file_size": 1024,
        "file_type": "application/x-php",
        "threat_level": "dangerous",
        "risk_score": 92.5,
        "detected_patterns": ["eval(", "base64_decode("],
        "recommendations": ["Quarantine this file", "Scan system for infections"]
    }


@pytest.fixture
def sample_url_features():
    """Return sample extracted URL features."""
    return {
        "url_length": 85,
        "has_at_symbol": False,
        "has_ip_address": False,
        "subdomain_count": 2,
        "path_depth": 3,
        "has_https": True,
        "domain_age_days": 5,
        "tld": ".tk",
        "special_char_count": 4,
        "entropy": 4.2
    }


@pytest.fixture
def mock_phishing_detector():
    """Mock PhishingDetector service."""
    mock = MagicMock()
    mock.analyze_url.return_value = {
        "url": "https://example.com",
        "is_phishing": True,
        "risk_score": 75.0,
        "threat_level": "suspicious",
        "features": {"suspicious_tld": True, "ip_address": False},
        "reasons": ["Suspicious TLD detected", "High entropy URL"]
    }
    return mock


@pytest.fixture
def mock_file_scanner():
    """Mock FileScanner service."""
    mock = MagicMock()
    mock.scan_content.return_value = {
        "filename": "test.php",
        "is_malicious": True,
        "risk_score": 88.0,
        "threat_level": "dangerous",
        "detected_patterns": ["eval(", "exec("],
        "file_type": "application/x-php",
        "recommendations": ["Delete immediately", "Run full system scan"]
    }
    return mock
