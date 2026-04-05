"""
Configuration settings loaded from environment variables.
"""

import os
from typing import List
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


settings = Settings()
