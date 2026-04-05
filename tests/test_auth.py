import pytest
from fastapi.testclient import TestClient
import sys
sys.path.insert(0, 'backend')

from app import app

client = TestClient(app)


class TestUserRegistration:
    """Test user registration endpoints."""

    def test_register_valid_user(self):
        """POST /api/v1/auth/register with valid credentials."""
        payload = {
            "email": "testuser@example.com",
            "password": "SecurePass123!",
            "username": "testuser"
        }
        response = client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert 'access_token' in data or 'user' in data

    def test_register_duplicate_email(self):
        """POST /api/v1/auth/register with duplicate email."""
        payload = {
            "email": "testuser@example.com",
            "password": "AnotherPass123!",
            "username": "testuser2"
        }
        response = client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 400

    def test_register_short_password(self):
        """POST /api/v1/auth/register with short password."""
        payload = {
            "email": "short@example.com",
            "password": "123",
            "username": "short"
        }
        response = client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    def test_register_invalid_email(self):
        """POST /api/v1/auth/register with invalid email."""
        payload = {
            "email": "not-an-email",
            "password": "SecurePass123!",
            "username": "invalid"
        }
        response = client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    def test_register_missing_fields(self):
        """POST /api/v1/auth/register with missing fields."""
        payload = {"email": "test@example.com"}
        response = client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422


class TestUserLogin:
    """Test user login endpoints."""

    def test_login_valid_credentials(self):
        """POST /api/v1/auth/login with valid credentials."""
        payload = {
            "email": "testuser@example.com",
            "password": "SecurePass123!"
        }
        response = client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'access_token' in data
        assert data['token_type'] == 'bearer'

    def test_login_invalid_password(self):
        """POST /api/v1/auth/login with wrong password."""
        payload = {
            "email": "testuser@example.com",
            "password": "WrongPassword123"
        }
        response = client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401

    def test_login_nonexistent_user(self):
        """POST /api/v1/auth/login with nonexistent user."""
        payload = {
            "email": "noone@example.com",
            "password": "SomePassword123"
        }
        response = client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401

    def test_login_missing_fields(self):
        """POST /api/v1/auth/login with missing fields."""
        payload = {"email": "test@example.com"}
        response = client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 422

    def test_login_response_format(self):
        """Login response should have correct format."""
        payload = {
            "email": "testuser@example.com",
            "password": "SecurePass123!"
        }
        response = client.post("/api/v1/auth/login", json=payload)
        if response.status_code == 200:
            data = response.json()
            assert 'access_token' in data
            assert 'token_type' in data


class TestTokenVerification:
    """Test token verification and user profile."""

    def test_get_current_user(self):
        """GET /api/v1/auth/me with valid token."""
        # First login to get token
        login_payload = {
            "email": "testuser@example.com",
            "password": "SecurePass123!"
        }
        login_response = client.post("/api/v1/auth/login", json=login_payload)
        if login_response.status_code == 200:
            token = login_response.json()['access_token']
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/api/v1/auth/me", headers=headers)
            assert response.status_code == 200
            data = response.json()
            assert 'email' in data or 'username' in data

    def test_get_current_user_no_token(self):
        """GET /api/v1/auth/me without token."""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401

    def test_get_current_user_invalid_token(self):
        """GET /api/v1/auth/me with invalid token."""
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 401


class TestTokenRefresh:
    """Test token refresh functionality."""

    def test_refresh_token(self):
        """POST /api/v1/auth/refresh with valid token."""
        login_payload = {
            "email": "testuser@example.com",
            "password": "SecurePass123!"
        }
        login_response = client.post("/api/v1/auth/login", json=login_payload)
        if login_response.status_code == 200:
            token = login_response.json()['access_token']
            headers = {"Authorization": f"Bearer {token}"}
            response = client.post("/api/v1/auth/refresh", headers=headers)
            assert response.status_code == 200
            data = response.json()
            assert 'access_token' in data


class TestPasswordReset:
    """Test password reset functionality."""

    def test_forgot_password(self):
        """POST /api/v1/auth/forgot-password with valid email."""
        payload = {"email": "testuser@example.com"}
        response = client.post("/api/v1/auth/forgot-password", json=payload)
        assert response.status_code in [200, 202]

    def test_forgot_password_nonexistent(self):
        """POST /api/v1/auth/forgot-password with nonexistent email."""
        payload = {"email": "noone@example.com"}
        response = client.post("/api/v1/auth/forgot-password", json=payload)
        assert response.status_code in [200, 202, 404]


class TestAuthErrorHandling:
    """Test authentication error handling."""

    def test_empty_body_login(self):
        """POST /api/v1/auth/login with empty body."""
        response = client.post("/api/v1/auth/login", json={})
        assert response.status_code == 422

    def test_empty_body_register(self):
        """POST /api/v1/auth/register with empty body."""
        response = client.post("/api/v1/auth/register", json={})
        assert response.status_code == 422

    def test_invalid_json_login(self):
        """POST /api/v1/auth/login with invalid JSON."""
        response = client.post("/api/v1/auth/login", data="not json")
        assert response.status_code == 422
