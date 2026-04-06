"""Audit logging utilities for security event tracking."""
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import Request
import logging

class AuditAction(str, Enum):
    """Security audit action types."""
    LOGIN = "login"
    LOGOUT = "logout"
    URL_SCAN = "url_scan"
    FILE_SCAN = "file_scan"
    PASSWORD_CHANGE = "password_change"
    TOKEN_REFRESH = "token_refresh"
    REGISTRATION = "registration"
    ACCESS_DENIED = "access_denied"
    RATE_LIMITED = "rate_limited"

class AuditEvent:
    """Represents a security audit event."""
    def __init__(
        self,
        action: AuditAction,
        user_id: Optional[str] = None,
        target: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ):
        self.action = action
        self.user_id = user_id
        self.target = target
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.status = status
        self.details = details or {}
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "user_id": self.user_id,
            "target": self.target,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "status": self.status,
            "details": self.details,
            "timestamp": self.timestamp,
        }

logger = logging.getLogger("audit")

async def log_audit_event(
    request: Request,
    user: Optional[Dict[str, Any]],
    action: AuditAction,
    target: Optional[str] = None,
    status: str = "success",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log a security audit event to the database and logger."""
    from database import get_collection

    user_id = user.get("sub") if user else None
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "unknown")

    event = AuditEvent(
        action=action,
        user_id=user_id,
        target=target,
        ip_address=ip_address,
        user_agent=user_agent,
        status=status,
        details=details,
    )

    try:
        collection = get_collection("audit_logs")
        collection.insert_one(event.to_dict())
    except Exception:
        pass

    log_msg = f"AUDIT: {action.value} | user={user_id} | target={target} | status={status} | ip={ip_address}"
    if status == "success":
        logger.info(log_msg)
    else:
        logger.warning(log_msg)

async def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    source_ip: Optional[str] = None,
    user_id: Optional[str] = None,
) -> None:
    """Log a security event (threat, anomaly, etc.)."""
    from database import get_collection

    event = {
        "event_type": event_type,
        "severity": severity,
        "description": description,
        "source_ip": source_ip,
        "user_id": user_id,
        "timestamp": datetime.utcnow(),
    }

    try:
        collection = get_collection("security_events")
        collection.insert_one(event)
    except Exception:
        pass

    logger.warning(f"SECURITY: [{severity}] {event_type} - {description}")
