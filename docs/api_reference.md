# API Reference

## Base URL

```
http://localhost:8000
```

## Authentication

Most endpoints require a Bearer token. Include it in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

---

## Endpoints

### Health Check

**GET** `/health`

Returns the health status of the API.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

### URL Scanning

**POST** `/api/scan-url`

Scans a URL for phishing threats.

**Headers:**
- `Authorization: Bearer <token>` (required)
- `Content-Type: application/json`

**Request Body:**
```json
{
  "url": "https://suspicious-site.com/login"
}
```

**Response:**
```json
{
  "url": "https://suspicious-site.com/login",
  "scan_id": "abc123",
  "scan_time": "2025-01-15T10:30:00Z",
  "result": {
    "is_phishing": true,
    "risk_level": "high",
    "risk_score": 85,
    "threat_type": "phishing",
    "reasons": [
      "Suspicious TLD detected",
      "Phishing-related keywords found",
      "Not using HTTPS"
    ],
    "features": {
      "url_length": 45,
      "has_suspicious_tld": true,
      "is_ip_address": false,
      "subdomain_count": 2,
      "keyword_count": 3,
      "is_https": false
    }
  }
}
```

---

### File Scanning

**POST** `/api/scan-file`

Scans an uploaded file for malware.

**Headers:**
- `Authorization: Bearer <token>` (required)
- `Content-Type: multipart/form-data`

**Request Body:**
- `file`: Binary file data (max 50MB)

**Response:**
```json
{
  "filename": "sample.exe",
  "scan_id": "def456",
  "scan_time": "2025-01-15T10:31:00Z",
  "result": {
    "is_malicious": true,
    "threat_level": "dangerous",
    "threat_type": "trojan",
    "file_size": 1024000,
    "file_hash": "sha256:abc123...",
    "signatures_matched": [
      "Eval execution pattern",
      "Base64 decode pattern"
    ],
    "heuristics_score": 75,
    "recommendations": [
      "Quarantine file immediately",
      "Run full system scan",
      "Check for persistence mechanisms"
    ]
  }
}
```

---

### Dashboard Stats

**GET** `/api/dashboard/stats`

Returns aggregated threat statistics.

**Headers:**
- `Authorization: Bearer <token>` (required)

**Response:**
```json
{
  "total_scans": 150,
  "url_scans": 100,
  "file_scans": 50,
  "threats_detected": 35,
  "threat_breakdown": {
    "phishing": 25,
    "malware": 10
  },
  "risk_distribution": {
    "safe": 70,
    "suspicious": 20,
    "dangerous": 10
  }
}
```

---

### Scan History

**GET** `/api/history`

Retrieves scan history with pagination.

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)
- `scan_type`: Filter by type ("url" or "file")
- `threat_level`: Filter by level ("safe", "suspicious", "dangerous")

**Response:**
```json
{
  "total": 150,
  "page": 1,
  "limit": 10,
  "scans": [
    {
      "scan_id": "abc123",
      "scan_type": "url",
      "target": "https://suspicious-site.com",
      "threat_level": "dangerous",
      "timestamp": "2025-01-15T10:30:00Z"
    }
  ]
}
```

---

### Authentication

**POST** `/auth/login`

Logs in a user and returns a JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

**POST** `/auth/register`

Registers a new user.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "full_name": "John Doe"
}
```

---

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid input data"
}
```

### 401 Unauthorized
```json
{
  "detail": "Could not validate credentials"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 422 Validation Error
```json
{
  "detail": [
    {
      "loc": ["body", "url"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

## Rate Limiting

- Anonymous requests: 10 requests/minute
- Authenticated requests: 100 requests/minute
- File uploads: 5 files/minute

---

## Interactive API Docs

- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
- **OpenAPI JSON:** `http://localhost:8000/openapi.json`
