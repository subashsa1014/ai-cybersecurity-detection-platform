import pytest
from fastapi.testclient import TestClient
import sys
sys.path.insert(0, 'backend')

from app import app

client = TestClient(app)


class TestHealthEndpoint:
    """Test API health and status endpoints."""

    def test_health_check(self):
        """Health endpoint should return healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        assert 'version' in data
        assert 'timestamp' in data

    def test_health_status_code(self):
        """Health endpoint should return 200."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_root_endpoint(self):
        """Root endpoint should return welcome message."""
        response = client.get("/")
        assert response.status_code == 200


class TestPhishingDetectionEndpoint:
    """Test phishing detection API endpoints."""

    def test_phishing_detect_valid_url(self):
        """POST /api/v1/phishing/detect with valid URL."""
        payload = {"url": "https://www.google.com"}
        response = client.post("/api/v1/phishing/detect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'is_phishing' in data
        assert 'confidence' in data
        assert 'features' in data

    def test_phishing_detect_empty_url(self):
        """POST /api/v1/phishing/detect with empty URL should return 422."""
        payload = {"url": ""}
        response = client.post("/api/v1/phishing/detect", json=payload)
        assert response.status_code == 422

    def test_phishing_detect_missing_url(self):
        """POST /api/v1/phishing/detect with missing URL should return 422."""
        payload = {}
        response = client.post("/api/v1/phishing/detect", json=payload)
        assert response.status_code == 422

    def test_phishing_detect_with_suspicious_url(self):
        """Test detection with a suspicious-looking URL."""
        payload = {"url": "http://g00gle-login.secure-account.com/signin"}
        response = client.post("/api/v1/phishing/detect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'is_phishing' in data

    def test_phishing_detect_batch(self):
        """POST /api/v1/phishing/detect-batch with multiple URLs."""
        payload = {
            "urls": [
                "https://www.google.com",
                "http://evil-phishing-site.com/login",
                "https://www.github.com"
            ]
        }
        response = client.post("/api/v1/phishing/detect-batch", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'results' in data
        assert len(data['results']) == 3

    def test_phishing_detect_batch_empty(self):
        """POST /api/v1/phishing/detect-batch with empty list."""
        payload = {"urls": []}
        response = client.post("/api/v1/phishing/detect-batch", json=payload)
        assert response.status_code == 422


class TestFileScannerEndpoint:
    """Test file scanner API endpoints."""

    def test_file_scan_valid_content(self):
        """POST /api/v1/file/scan with valid content."""
        payload = {
            "filename": "test.py",
            "content": "def hello():\n    print('Hello')"
        }
        response = client.post("/api/v1/file/scan", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'is_safe' in data
        assert 'threats' in data
        assert 'filename' in data

    def test_file_scan_malicious_content(self):
        """POST /api/v1/file/scan with malicious content."""
        payload = {
            "filename": "evil.py",
            "content": "import os\nexec('malicious')"
        }
        response = client.post("/api/v1/file/scan", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data['is_safe'] is False
        assert len(data['threats']) >= 1

    def test_file_scan_empty_filename(self):
        """POST /api/v1/file/scan with empty filename."""
        payload = {
            "filename": "",
            "content": "print('test')"
        }
        response = client.post("/api/v1/file/scan", json=payload)
        assert response.status_code == 422

    def test_file_scan_missing_content(self):
        """POST /api/v1/file/scan with missing content."""
        payload = {"filename": "test.py"}
        response = client.post("/api/v1/file/scan", json=payload)
        assert response.status_code == 422


class TestAnalysisEndpoint:
    """Test combined analysis endpoint."""

    def test_analyze_valid_input(self):
        """POST /api/v1/analyze with valid input."""
        payload = {
            "url": "https://www.example.com",
            "content": "print('hello')",
            "filename": "test.py"
        }
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'phishing_result' in data
        assert 'file_scan_result' in data
        assert 'overall_risk' in data


class TestAPIResponseFormat:
    """Test API response format and error handling."""

    def test_404_not_found(self):
        """Non-existent endpoint should return 404."""
        response = client.get("/nonexistent")
        assert response.status_code == 404

    def test_invalid_json_phishing(self):
        """Invalid JSON in phishing endpoint should return 422."""
        response = client.post("/api/v1/phishing/detect", data="not json")
        assert response.status_code == 422

    def test_invalid_json_file_scan(self):
        """Invalid JSON in file scan endpoint should return 422."""
        response = client.post("/api/v1/file/scan", data="not json")
        assert response.status_code == 422

    def test_method_not_allowed(self):
        """GET on POST endpoint should return 405."""
        response = client.get("/api/v1/phishing/detect")
        assert response.status_code == 405

    def test_phishing_response_fields(self):
        """Phishing response should have all required fields."""
        response = client.post("/api/v1/phishing/detect", json={"url": "https://example.com"})
        data = response.json()
        assert 'url' in data
        assert 'is_phishing' in data
        assert 'confidence' in data
        assert 'features' in data
        assert 'analysis' in data

    def test_file_scan_response_fields(self):
        """File scan response should have all required fields."""
        response = client.post("/api/v1/file/scan", json={"filename": "t.py", "content": "x=1"})
        data = response.json()
        assert 'filename' in data
        assert 'is_safe' in data
        assert 'threats' in data

    def test_confidence_range(self):
        """Phishing confidence should be between 0 and 1."""
        response = client.post("/api/v1/phishing/detect", json={"url": "https://example.com"})
        data = response.json()
        assert 0 <= data['confidence'] <= 1


class TestAPIErrorMessages:
    """Test API error messages."""

    def test_phishing_error_message(self):
        """Phishing endpoint error should be descriptive."""
        response = client.post("/api/v1/phishing/detect", json={})
        data = response.json()
        assert 'detail' in data

    def test_file_scan_error_message(self):
        """File scan endpoint error should be descriptive."""
        response = client.post("/api/v1/file/scan", json={})
        data = response.json()
        assert 'detail' in data
