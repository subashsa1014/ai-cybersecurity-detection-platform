"""
Configuration settings loaded from environment variables.
"""

import os
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Application
    APP_NAME: str = "AI Cybersecurity Detection Platform"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    API_PREFIX: str = "/api"

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "*",  # Allow all origins in development
    ]

    # JWT Settings
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "your-super-secret-jwt-key-change-in-production",
    )
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # MongoDB
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    DB_NAME: str = os.getenv("DB_NAME", "cybersecurity_platform")

    # Admin
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@example.com")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin123")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

    # File Upload
    MAX_FILE_SIZE: int = int(os.getenv("MAX_FILE_SIZE", "10485760"))  # 10MB
    ALLOWED_EXTENSIONS: List[str] = [".exe", ".dll", ".pdf", ".zip", ".rar", ".doc", ".docx"]

    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"
    THREAT_INTEL_ENABLED: bool = os.getenv("THREAT_INTEL_ENABLED", "true").lower() == "true"

    # Security Hardening
    AUDIT_LOG_ENABLED: bool = os.getenv("AUDIT_LOG_ENABLED", "true").lower() == "true"
    AUDIT_LOG_LEVEL: str = os.getenv("AUDIT_LOG_LEVEL", "INFO")
    AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))

    # RBAC Settings
    RBAC_ENABLED: bool = os.getenv("RBAC_ENABLED", "true").lower() == "true"
    DEFAULT_ROLE: str = os.getenv("DEFAULT_ROLE", "user")
    ADMIN_ROLE: str = os.getenv("ADMIN_ROLE", "admin")

    # Model & Benchmarking
    MODEL_VERSION: str = os.getenv("MODEL_VERSION", "v1.0")
    BENCHMARK_ENABLED: bool = os.getenv("BENCHMARK_ENABLED", "false").lower() == "true"


settings = Settings()


def get_settings():
    """Return the application settings instance."""
    return settings
