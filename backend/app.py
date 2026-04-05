""" 
AI Cybersecurity Detection Platform - Backend
FastAPI application for detecting phishing URLs and malware files.
"""
from fastapi import FastAPI, Request, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import logging
from config import settings
from database import connect_to_mongodb, close_mongodb_connection
from routes import api, auth

# Rate limiting using in-memory approach
from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests: dict = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = datetime.now()
        self.requests[client_ip] = [
            ts for ts in self.requests[client_ip]
            if now - ts < self.window
        ]
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        self.requests[client_ip].append(now)
        return True

    def get_remaining(self, client_ip: str) -> int:
        now = datetime.now()
        self.requests[client_ip] = [
            ts for ts in self.requests[client_ip]
            if now - ts < self.window
        ]
        return max(0, self.max_requests - len(self.requests[client_ip]))


rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


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
- **Phishing URLs** - Real-time URL analysis with risk scoring and ML
- **Malware Files** - AI-based file threat detection
- **Threat Intelligence** - Dashboard with scan history and analytics
- **Real-time Analysis** - WebSocket-based live scanning
## Authentication
All scan endpoints require authentication via JWT token.
Use `/api/auth/register` and `/api/auth/login` to obtain access tokens.
## Rate Limiting
API is rate-limited to 100 requests per minute per IP.
""",
    version="2.0.0",
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

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Too many requests",
                "retry_after": 60,
            },
        )
    response = await call_next(request)
    response.headers["X-RateLimit-Remaining"] = str(rate_limiter.get_remaining(client_ip))
    return response

# Custom middleware for logging and timing
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    client_ip = request.client.host if request.client else "unknown"
    logging.info(f"[{client_ip}] {request.method} {request.url.path}")
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# WebSocket connections tracking
active_connections: set = set()

@app.websocket("/ws/analysis")
async def websocket_analysis(websocket: WebSocket):
    """Real-time analysis WebSocket endpoint."""
    await websocket.accept()
    active_connections.add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back analysis result
            await websocket.send_json({
                "type": "analysis_result",
                "data": data,
                "timestamp": time.time(),
                "status": "analyzed",
            })
    except WebSocketDisconnect:
        active_connections.discard(websocket)

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """Real-time notifications WebSocket endpoint."""
    await websocket.accept()
    active_connections.add(websocket)
    try:
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to notification stream",
            "timestamp": time.time(),
        })
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({
                "type": "acknowledged",
                "data": data,
                "timestamp": time.time(),
            })
    except WebSocketDisconnect:
        active_connections.discard(websocket)

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "AI Cybersecurity Detection Platform API",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
        "features": ["phishing_detection", "malware_scanning", "ml_classifier", "rate_limiting", "websocket"],
    }

# Health check endpoint
@app.get("/health", tags=["Root"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "2.0.0",
        "active_websockets": len(active_connections),
    }

# Rate limit info endpoint
@app.get("/api/rate-limit", tags=["Root"])
async def rate_limit_info(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    return {
        "client_ip": client_ip,
        "remaining_requests": rate_limiter.get_remaining(client_ip),
        "limit": rate_limiter.max_requests,
        "window_seconds": rate_limiter.window.total_seconds(),
    }

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
