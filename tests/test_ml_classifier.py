"""Tests for ML Classifier service."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.ml_classifier import MLClassifier


class TestMLClassifier:
    """Test suite for MLClassifier."""

    @pytest.fixture
    def classifier(self):
        return MLClassifier()

    def test_classifier_initialization(self, classifier):
        """Test MLClassifier initializes correctly."""
        assert classifier is not None
        assert hasattr(classifier, "models")
        assert hasattr(classifier, "feature_names")
        assert hasattr(classifier, "scaler")

    def test_predict_url_phishing(self, classifier):
        """Test prediction on known phishing URL patterns."""
        result = classifier.predict_url("http://paypal-secure-login.tk/verify")
        assert result is not None
        assert "is_phishing" in result
        assert "confidence" in result
        assert result["confidence"] >= 0
        assert result["confidence"] <= 1

    def test_predict_url_safe(self, classifier):
        """Test prediction on known safe URL patterns."""
        result = classifier.predict_url("https://www.google.com/search")
        assert result is not None
        assert "is_phishing" in result
        assert "confidence" in result

    def test_predict_url_ip_address(self, classifier):
        """Test prediction on IP-based URL."""
        result = classifier.predict_url("http://192.168.1.1/login")
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_suspicious_tld(self, classifier):
        """Test prediction on suspicious TLD."""
        result = classifier.predict_url("http://microsoft-verify.ml/account")
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_long_url(self, classifier):
        """Test prediction on unusually long URL."""
        long_url = "http://example.com/" + "a" * 100 + "/login?param=" + "b" * 50
        result = classifier.predict_url(long_url)
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_with_port(self, classifier):
        """Test prediction on URL with suspicious port."""
        result = classifier.predict_url("http://bank-login.com:8080/secure")
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_hex_encoded(self, classifier):
        """Test prediction on hex-encoded URL."""
        result = classifier.predict_url("http://site.com/%61%64%6D%69%6E")
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_at_symbol(self, classifier):
        """Test prediction on URL with @ symbol."""
        result = classifier.predict_url("http://user@phishing.com/login")
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_subdomains(self, classifier):
        """Test prediction on URL with multiple subdomains."""
        result = classifier.predict_url("http://login.secure.paypal.verify.com/signin")
        assert result is not None
        assert "is_phishing" in result

    def test_extract_features(self, classifier):
        """Test feature extraction from URL."""
        url = "http://paypal-verify.tk/login?user=admin&pass=123"
        features = classifier.extract_features(url)
        assert isinstance(features, dict)
        assert len(features) > 0
        assert features["url_length"] > 0
        assert features["has_suspicious_tld"] is True
        assert features["is_ip_address"] is False

    def test_extract_features_ip(self, classifier):
        """Test feature extraction for IP-based URL."""
        url = "http://192.168.1.1:8080/admin"
        features = classifier.extract_features(url)
        assert features["is_ip_address"] is True
        assert features["has_suspicious_port"] is True

    def test_extract_features_https(self, classifier):
        """Test feature extraction for HTTPS URL."""
        url = "https://www.example.com/page"
        features = classifier.extract_features(url)
        assert features["is_https"] is True

    def test_extract_features_empty_url(self, classifier):
        """Test feature extraction for empty URL."""
        features = classifier.extract_features("")
        assert isinstance(features, dict)

    def test_predict_batch(self, classifier):
        """Test batch prediction."""
        urls = [
            "http://phishing-site.tk/login",
            "https://www.google.com",
            "http://192.168.1.1/admin",
        ]
        results = classifier.predict_batch(urls)
        assert isinstance(results, list)
        assert len(results) == 3
        for result in results:
            assert "is_phishing" in result
            assert "confidence" in result

    def test_get_model_info(self, classifier):
        """Test get_model_info method."""
        info = classifier.get_model_info()
        assert isinstance(info, dict)
        assert "ml_available" in info
        assert "num_models" in info
        assert "model_names" in info

    def test_get_feature_importance(self, classifier):
        """Test get_feature_importance method."""
        importance = classifier.get_feature_importance()
        assert isinstance(importance, dict)

    def test_predict_url_with_ml_disabled(self):
        """Test behavior when ML is not available."""
        # Simulate ML unavailable by checking ML_AVAILABLE flag
        classifier = MLClassifier()
        # The classifier should handle missing models gracefully
        result = classifier.predict_url("http://test.com")
        assert result is not None
        assert "is_phishing" in result

    def test_classifier_save_load(self, classifier, tmp_path):
        """Test save and load model functionality."""
        save_path = tmp_path / "test_model.pkl"
        classifier.save(str(save_path))
        assert save_path.exists()

        # Load into new classifier
        new_classifier = MLClassifier()
        new_classifier.load(str(save_path))
        assert new_classifier.models is not None

    def test_predict_url_missing_scheme(self, classifier):
        """Test prediction on URL without scheme."""
        result = classifier.predict_url("phishing-site.com/login")
        assert result is not None
        assert "is_phishing" in result

    def test_predict_url_special_characters(self, classifier):
        """Test prediction on URL with special characters."""
        result = classifier.predict_url("http://site.com/path?query=<script>alert(1)</script>")
        assert result is not None
        assert "is_phishing" in result
