"""ML-based phishing classifier using ensemble models."""

import pickle
import re
import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from xgboost import XGBClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


@dataclass
class MLFeatureVector:
    """Feature vector for ML classification."""
    url_length: float
    num_dots: float
    num_hyphens: float
    num_underscores: float
    num_digits: float
    tld_length: float
    has_at_symbol: float
    has_ip_address: float
    url_depth: float
    num_params: float
    has_suspicious_tld: float
    has_phishing_keyword: float
    has_hex_encoded: float
    avg_word_length: float
    entropy: float


class MLPhishingClassifier:
    """Ensemble ML classifier for phishing URL detection."""

    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.models = {}
        self.scaler = None
        self.feature_names = [
            'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_digits', 'tld_length', 'has_at_symbol', 'has_ip_address',
            'url_depth', 'num_params', 'has_suspicious_tld',
            'has_phishing_keyword', 'has_hex_encoded', 'avg_word_length', 'entropy'
        ]
        self._initialize_models()

    def _initialize_models(self):
        """Initialize ensemble models."""
        if not ML_AVAILABLE:
            return
        self.models = {
            'xgboost': XGBClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            )
        }
        self.scaler = StandardScaler()

    def extract_features(self, url: str, heuristic_features: Dict) -> np.ndarray:
        """Extract ML features from URL and heuristic analysis."""
        features = [
            heuristic_features.get('url_length', 0),
            heuristic_features.get('num_dots', 0),
            heuristic_features.get('num_hyphens', 0),
            heuristic_features.get('num_underscores', 0),
            heuristic_features.get('num_digits', 0),
            heuristic_features.get('tld_length', 0),
            heuristic_features.get('has_at_symbol', 0),
            heuristic_features.get('has_ip_address', 0),
            heuristic_features.get('url_depth', 0),
            heuristic_features.get('num_params', 0),
            heuristic_features.get('has_suspicious_tld', 0),
            heuristic_features.get('has_phishing_keyword', 0),
            heuristic_features.get('has_hex_encoded', 0),
            heuristic_features.get('avg_word_length', 0),
            heuristic_features.get('entropy', 0)
        ]
        return np.array(features).reshape(1, -1)

    def predict(self, features: np.ndarray) -> Tuple[bool, float, Dict]:
        """Predict phishing probability using ensemble voting."""
        if not ML_AVAILABLE or not self.models:
            return False, 0.0, {'error': 'ML not available'}

        scaled_features = self.scaler.fit_transform(features)
        predictions = {}
        probabilities = {}

        for name, model in self.models.items():
            try:
                pred = model.predict(scaled_features)[0]
                prob = model.predict_proba(scaled_features)[0][1]
                predictions[name] = bool(pred)
                probabilities[name] = float(prob)
            except Exception:
                predictions[name] = False
                probabilities[name] = 0.0

        is_phishing = sum(predictions.values()) >= 2
        avg_confidence = np.mean(list(probabilities.values()))

        return is_phishing, avg_confidence, {
            'ensemble_predictions': predictions,
            'ensemble_probabilities': probabilities,
            'voting_result': is_phishing
        }

    def train(self, X: np.ndarray, y: np.ndarray):
        """Train all models on provided data."""
        if not ML_AVAILABLE or not self.models:
            return

        X_scaled = self.scaler.fit_transform(X)

        for name, model in self.models.items():
            model.fit(X_scaled, y)

    def save_model(self, path: str = None):
        """Save trained models to disk."""
        if not ML_AVAILABLE:
            return

        save_path = path or self.model_path
        if not save_path:
            return

        with open(save_path, 'wb') as f:
            pickle.dump({
                'models': self.models,
                'scaler': self.scaler
            }, f)

    def load_model(self, path: str = None):
        """Load trained models from disk."""
        if not ML_AVAILABLE:
            return

        load_path = path or self.model_path
        if not load_path or not Path(load_path).exists():
            return

        with open(load_path, 'rb') as f:
            data = pickle.load(f)
            self.models = data.get('models', {})
            self.scaler = data.get('scaler', None)

    def get_feature_importance(self) -> Dict[str, List[float]]:
        """Get feature importance from all models."""
        importance = {}
        if not ML_AVAILABLE:
            return importance

        for name, model in self.models.items():
            try:
                if hasattr(model, 'feature_importances_'):
                    importance[name] = model.feature_importances_.tolist()
            except Exception:
                importance[name] = []

        return importance

    def get_model_info(self) -> Dict:
        """Get model information."""
        return {
            'ml_available': ML_AVAILABLE,
            'num_models': len(self.models),
            'model_names': list(self.models.keys()),
            'num_features': len(self.feature_names),
            'feature_names': self.feature_names
        }
            def predict_url(self, url: str) -> Dict:
        """Predict if a URL is phishing using ML ensemble."""
        if not ML_AVAILABLE:
            return {'is_phishing': False, 'confidence': 0.0, 'error': 'ML not available'}
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        heuristic = {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_digits': sum(c.isdigit() for c in url),
            'tld_length': len(url.split('.')[-1]) if '.' in url else 0,
            'has_at_symbol': 1.0 if '@' in url else 0.0,
            'has_ip_address': 1.0 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc) else 0.0,
            'url_depth': len(parsed.path.strip('/').split('/')) if parsed.path else 0,
            'num_params': len(parse_qs(parsed.query)),
            'has_suspicious_tld': 1.0 if url.split('.')[-1].lower() in {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'loan', 'zip', 'click', 'work', 'date', 'bid', 'gdn', 'stream', 'download'} else 0.0,
            'has_phishing_keyword': 1.0 if any(kw in url.lower() for kw in {'login', 'signin', 'account', 'verify', 'secure', 'update', 'password', 'banking', 'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'suspended', 'urgent', 'confirm', 'alert', 'warning', 'locked'}) else 0.0,
            'has_hex_encoded': 1.0 if re.search(r'%[0-9a-fA-F]{2}', url) else 0.0,
            'avg_word_length': np.mean([len(w) for w in re.findall(r'[a-zA-Z]+', url)]) if re.findall(r'[a-zA-Z]+', url) else 0.0,
            'entropy': 0.0,
        }
        features = self.extract_features(url, heuristic)
        is_phishing, confidence, details = self.predict(features)
        return {'is_phishing': is_phishing, 'confidence': float(confidence), 'details': details}

