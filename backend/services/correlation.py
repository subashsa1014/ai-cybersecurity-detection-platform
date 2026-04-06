"""
Correlation Engine for combining multiple threat signals into unified risk assessment.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from database import get_collection


class CorrelationRule:
    """Represents a correlation rule for threat detection."""

    def __init__(self, name: str, description: str, condition: callable, weight: float = 1.0):
        self.name = name
        self.description = description
        self.condition = condition
        self.weight = weight


class CorrelationEngine:
    """Engine for correlating multiple threat signals."""

    def __init__(self):
        self.rules = self._init_rules()
        self.lookback_hours = 24

    def _init_rules(self) -> List[CorrelationRule]:
        """Initialize correlation rules."""
        return [
            CorrelationRule(
                "multi_source_threat",
                "Multiple threat sources flag the same target",
                lambda s: sum(1 for v in s.values() if v > 50) >= 2,
                weight=1.5,
            ),
            CorrelationRule(
                "high_vt_abuse_correlation",
                "VirusTotal and AbuseIPDB both flag high risk",
                lambda s: s.get("virustotal", 0) > 50 and s.get("abuseipdb", 0) > 50,
                weight=1.3,
            ),
            CorrelationRule(
                "phishing_vt_correlation",
                "Phishing detection correlates with VirusTotal score",
                lambda s: s.get("phishing", 0) > 40 and s.get("virustotal", 0) > 30,
                weight=1.2,
            ),
            CorrelationRule(
                "escalating_threat",
                "Risk score is escalating across checks",
                lambda s: self._is_escalating(s),
                weight=1.1,
            ),
        ]

    def _is_escalating(self, scores: Dict[str, float]) -> bool:
        """Check if threat scores are escalating."""
        values = [v for v in scores.values() if v > 0]
        if len(values) < 2:
            return False
        return values[-1] > values[0] * 1.2

    async def correlate(
        self,
        target: str,
        scan_type: str,
        scores: Dict[str, float],
    ) -> Dict[str, Any]:
        """Correlate threat scores from multiple sources."""
        result = {
            "is_correlated_threat": False,
            "matched_rules": [],
            "rule_matched": None,
            "confidence_boost": 0.0,
            "final_score": max(scores.values()) if scores else 0,
        }
        for rule in self.rules:
            if rule.condition(scores):
                result["matched_rules"].append(rule.name)
                result["confidence_boost"] += rule.weight * 0.05
        if result["matched_rules"]:
            result["is_correlated_threat"] = True
            result["rule_matched"] = result["matched_rules"][0]
            result["final_score"] = min(
                max(scores.values()) * (1 + result["confidence_boost"]), 100
            )
        recent_threats = await self._get_recent_threats(target, scan_type)
        if recent_threats > 0:
            result["is_correlated_threat"] = True
            result["matched_rules"].append("recent_threat_pattern")
            result["final_score"] = min(result["final_score"] + 10, 100)
        return result

    async def _get_recent_threats(self, target: str, scan_type: str) -> int:
        """Count recent threats for the same target."""
        try:
            collection = get_collection("scan_history")
            cutoff = datetime.utcnow() - timedelta(hours=self.lookback_hours)
            query = {
                "target": {"$regex": target.split("//")[-1].split("/")[0], "$options": "i"},
                "is_threat": True,
                "timestamp": {"$gte": cutoff},
            }
            return collection.count_documents(query)
        except Exception:
            return 0
