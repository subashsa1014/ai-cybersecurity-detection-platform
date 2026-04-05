"""
AI Cybersecurity Detection Platform - Backend
FastAPI application for detecting phishing URLs and malware files.
"""

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time

from config import settings
from database import connect_to_mongodb, close_mongodb_connection
from routes import api, auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("Starting AI Cybersecurity Detection Platform...")
    await connect_to_mongodb()
    print(f"Connected to MongoDB: {settings.MONGODB_URI}")
    yield
    # Shutdown
    await close_mongodb_connection()
    print("Disconnected from MongoDB")


app = FastAPI(
    title="AI Cybersecurity Detection Platform",
    description="""
## Overview

A comprehensive AI-powered system for detecting:
- **Phishing URLs** - Real-time URL analysis with risk scoring
- **Malware Files** - AI-based file threat detection
- **Threat Intelligence** - Dashboard with scan history and analytics

## Authentication

All scan endpoints require authentication via JWT token.
Use `/api/auth/register` and `/api/auth/login` to obtain access tokens.
    """,
    version="1.0.0",
    contact={
        "name": "Subashsa1014",
        "url": "https://github.com/subashsa1014/ai-cybersecurity-detection-platform",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom middleware for logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "AI Cybersecurity Detection Platform API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


# Health check endpoint
@app.get("/health", tags=["Root"])
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}


# Include routers
app.include_router(api.router, prefix="/api", tags=["Detection"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])


# Custom exception handler
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "path": str(request.url.path),
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )
