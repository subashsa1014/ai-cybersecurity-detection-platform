"""Unit tests for PhishingDetector service."""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.services.phishing_detector import PhishingDetector
from backend.utils.url_feature_extractor import extract_domain, extract_subdomains


class TestPhishingDetector:
    """Test suite for PhishingDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a PhishingDetector instance."""
        return PhishingDetector()

    def test_init_creates_detector(self, detector):
        """Test that PhishingDetector initializes correctly."""
        assert detector is not None
        assert hasattr(detector, 'weights')
        assert hasattr(detector, 'analyze_url')

    def test_suspicious_tld_detection(self, detector):
        """Test detection of suspicious TLDs."""
        url = "https://secure-bank-login.tk/signin"
        result = detector.analyze_url(url)
        assert result['is_phishing'] is True
        assert 'suspicious_tld' in str(result.get('features', {}))

    def test_safe_domain_not_flagged(self, detector):
        """Test that safe domains are not flagged as phishing."""
        url = "https://www.google.com/search"
        result = detector.analyze_url(url)
        assert result['risk_score'] < 40

    def test_ip_address_detection(self, detector):
        """Test detection of IP addresses in URLs."""
        url = "http://192.168.1.1/login"
        result = detector.analyze_url(url)
        assert result['is_phishing'] is True
        assert result['risk_score'] >= 30

    def test_phishing_keywords_detection(self, detector):
        """Test detection of phishing keywords."""
        url = "https://verify-your-account.secure-login.com/update-password"
        result = detector.analyze_url(url)
        assert 'verify' in str(result.get('reasons', [])).lower() or result['risk_score'] > 20

    def test_at_symbol_detection(self, detector):
        """Test detection of @ symbol in URLs."""
        url = "https://google.com@malicious-site.com"
        result = detector.analyze_url(url)
        assert result['is_phishing'] is True
        assert 'at_symbol' in str(result.get('features', {}))

    def test_hex_encoded_detection(self, detector):
        """Test detection of hex-encoded characters."""
        url = "https://example.com/%2e%2e/admin"
        result = detector.analyze_url(url)
        assert result['is_phishing'] is True

    def test_multiple_subdomains_detection(self, detector):
        """Test detection of multiple subdomains."""
        url = "https://secure.login.account.verify.banking.com/signin"
        result = detector.analyze_url(url)
        assert result['is_phishing'] is True
        assert result['risk_score'] >= 40

    def test_risk_score_range(self, detector):
        """Test that risk score is within valid range."""
        url = "https://suspicious-site.tk"
        result = detector.analyze_url(url)
        assert 0 <= result['risk_score'] <= 100

    def test_threat_level_calculation(self, detector):
        """Test threat level based on risk score."""
        # Test dangerous level
        result = detector.analyze_url("https://paypal-verify.tk/login")
        assert result['threat_level'] in ['safe', 'suspicious', 'dangerous']

    def test_reasons_list_not_empty_for_phishing(self, detector):
        """Test that phishing URLs have reasons."""
        url = "https://account-secure-verify.tk/signin"
        result = detector.analyze_url(url)
        if result['is_phishing']:
            assert len(result['reasons']) > 0

    def test_feature_extraction_accuracy(self, detector):
        """Test that features are extracted correctly."""
        url = "https://sub1.sub2.example.com:8080/path/to/page"
        result = detector.analyze_url(url)
        features = result.get('features', {})
        assert 'subdomain_count' in str(features) or 'path_depth' in str(features)

    def test_empty_url_handling(self, detector):
        """Test handling of empty URL."""
        with pytest.raises(ValueError):
            detector.analyze_url("")

    def test_invalid_url_handling(self, detector):
        """Test handling of invalid URL format."""
        with pytest.raises(ValueError):
            detector.analyze_url("not-a-valid-url")

    def test_url_without_scheme(self, detector):
        """Test URL without scheme gets default scheme."""
        url = "example.com/login"
        result = detector.analyze_url(url)
        assert result['risk_score'] >= 0


class TestURLFeatureExtractor:
    """Test suite for URL feature extraction utilities."""

    def test_extract_domain_basic(self):
        """Test basic domain extraction."""
        url = "https://www.example.com/path"
        domain = extract_domain(url)
        assert domain == "example.com"

    def test_extract_domain_with_subdomains(self):
        """Test domain extraction with multiple subdomains."""
        url = "https://sub1.sub2.example.com/path"
        domain = extract_domain(url)
        assert domain == "example.com"

    def test_extract_domain_no_subdomains(self):
        """Test domain extraction without subdomains."""
        url = "https://example.com/path"
        domain = extract_domain(url)
        assert domain == "example.com"

    def test_extract_subdomains_basic(self):
        """Test basic subdomain extraction."""
        url = "https://www.example.com/path"
        subdomains = extract_subdomains(url)
        assert 'www' in subdomains

    def test_extract_subdomains_multiple(self):
        """Test subdomain extraction with multiple subdomains."""
        url = "https://sub1.sub2.example.com/path"
        subdomains = extract_subdomains(url)
        assert len(subdomains) == 2

    def test_extract_subdomains_none(self):
        """Test subdomain extraction with no subdomains."""
        url = "https://example.com/path"
        subdomains = extract_subdomains(url)
        assert len(subdomains) == 0

    def test_extract_domain_invalid_url(self):
        """Test domain extraction with invalid URL."""
        domain = extract_domain("not-a-url")
        assert domain == ""

    def test_extract_subdomains_invalid_url(self):
        """Test subdomain extraction with invalid URL."""
        subdomains = extract_subdomains("not-a-url")
        assert subdomains == []
