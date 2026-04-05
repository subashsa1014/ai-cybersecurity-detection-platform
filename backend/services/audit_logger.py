"""Audit logging service for tracking security events and actions."""

import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque
from contextlib import contextmanager


class AuditLogger:
    """Comprehensive audit logging for security events."""

    EVENT_TYPES = {
        "AUTH": "authentication",
        "SCAN": "scan_operation",
        "DETECT": "detection_result",
        "ALERT": "security_alert",
        "SYSTEM": "system_event",
        "ACCESS": "access_control",
        "CONFIG": "configuration_change",
    }

    SEVERITY = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def __init__(self, max_entries: int = 10000):
        self.max_entries = max_entries
        self.logs: deque = deque(maxlen=max_entries)
        self.logger = logging.getLogger("audit")
        self._setup_logging()

    def _setup_logging(self):
        """Configure audit logger."""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s | AUDIT | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log(
        self,
        event_type: str,
        action: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[Dict] = None,
        severity: str = "INFO",
        result: Optional[str] = None,
    ) -> Dict:
        """Create and store an audit log entry."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "unix_time": time.time(),
            "event_type": self.EVENT_TYPES.get(event_type.upper(), event_type),
            "action": action,
            "user_id": user_id,
            "ip_address": ip_address,
            "resource": resource,
            "details": details or {},
            "severity": severity.upper(),
            "result": result,
        }

        self.logs.append(entry)

        # Log to file/console
        severity_level = self.SEVERITY.get(severity.upper(), 0)
        log_msg = f"[{severity}] {entry['event_type']}: {entry['action']}"
        if user_id:
            log_msg += f" | user={user_id}"
        if ip_address:
            log_msg += f" | ip={ip_address}"
        if result:
            log_msg += f" | result={result}"

        if severity_level >= 3:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)

        return entry

    def auth_success(self, user_id: str, ip_address: str, method: str = "login"):
        """Log successful authentication."""
        return self.log(
            event_type="AUTH",
            action=f"{method}_success",
            user_id=user_id,
            ip_address=ip_address,
            severity="INFO",
            result="success",
        )

    def auth_failure(self, user_id: str, ip_address: str, method: str = "login", reason: str = "invalid_credentials"):
        """Log failed authentication attempt."""
        return self.log(
            event_type="AUTH",
            action=f"{method}_failure",
            user_id=user_id,
            ip_address=ip_address,
            details={"reason": reason},
            severity="MEDIUM",
            result="failure",
        )

    def scan_performed(self, user_id: str, ip_address: str, scan_type: str, resource: str):
        """Log a scan operation."""
        return self.log(
            event_type="SCAN",
            action=f"{scan_type}_scan",
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            severity="INFO",
            result="completed",
        )

    def phishing_detected(self, url: str, risk_score: int, user_id: Optional[str] = None, ip_address: Optional[str] = None):
        """Log phishing URL detection."""
        severity = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM"
        return self.log(
            event_type="DETECT",
            action="phishing_url_detected",
            user_id=user_id,
            ip_address=ip_address,
            resource=url,
            details={"risk_score": risk_score},
            severity=severity,
            result="phishing",
        )

    def malware_detected(self, filename: str, threat_score: int, user_id: Optional[str] = None, ip_address: Optional[str] = None):
        """Log malware file detection."""
        severity = "CRITICAL" if threat_score >= 70 else "HIGH" if threat_score >= 40 else "MEDIUM"
        return self.log(
            event_type="DETECT",
            action="malware_file_detected",
            user_id=user_id,
            ip_address=ip_address,
            resource=filename,
            details={"threat_score": threat_score},
            severity=severity,
            result="malware",
        )

    def access_denied(self, user_id: str, ip_address: str, resource: str, reason: str):
        """Log access denied event."""
        return self.log(
            event_type="ACCESS",
            action="access_denied",
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            details={"reason": reason},
            severity="MEDIUM",
            result="denied",
        )

    def rate_limit_exceeded(self, ip_address: str, endpoint: str):
        """Log rate limit exceeded event."""
        return self.log(
            event_type="ALERT",
            action="rate_limit_exceeded",
            ip_address=ip_address,
            resource=endpoint,
            severity="LOW",
            result="throttled",
        )

    def get_logs(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[str] = None,
        start_time: Optional[float] = None,
    ) -> List[Dict]:
        """Retrieve filtered audit logs."""
        results = []
        for entry in reversed(self.logs):
            if event_type and entry["event_type"] != event_type:
                continue
            if severity and entry["severity"] != severity.upper():
                continue
            if user_id and entry["user_id"] != user_id:
                continue
            if start_time and entry["unix_time"] < start_time:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    def get_stats(self) -> Dict:
        """Get audit log statistics."""
        stats = {
            "total_entries": len(self.logs),
            "by_event_type": {},
            "by_severity": {},
            "by_result": {},
        }
        for entry in self.logs:
            # Count by event type
            et = entry["event_type"]
            stats["by_event_type"][et] = stats["by_event_type"].get(et, 0) + 1
            # Count by severity
            sev = entry["severity"]
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            # Count by result
            res = entry.get("result", "unknown")
            stats["by_result"][res] = stats["by_result"].get(res, 0) + 1
        return stats

    def export_logs(self, format: str = "json") -> str:
        """Export logs in specified format."""
        if format == "json":
            return json.dumps(list(self.logs), indent=2)
        elif format == "csv":
            if not self.logs:
                return ""
            headers = list(self.logs[0].keys())
            lines = [",".join(headers)]
            for entry in self.logs:
                values = [str(entry.get(h, "")) for h in headers]
                lines.append(",".join(values))
            return "\n".join(lines)
        return ""

    def clear_logs(self):
        """Clear all logs."""
        self.logs.clear()
        self.logger.info("Audit logs cleared")


# Singleton instance
audit_logger = AuditLogger()
