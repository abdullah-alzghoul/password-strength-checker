"""Tests for the FastAPI wrapper."""

from fastapi.testclient import TestClient

from src.api import app

client = TestClient(app)


class TestHealthEndpoint:
    def test_returns_ok(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAnalyzeEndpoint:
    def test_analyzes_strong_password(self):
        response = client.post(
            "/analyze",
            json={"password": "Xk9$mQ2vL7!p", "check_breaches": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["strength"] in ("Strong", "Very Strong")

    def test_analyzes_weak_password(self):
        response = client.post(
            "/analyze",
            json={"password": "password", "check_breaches": False},
        )
        assert response.status_code == 200
        assert len(response.json()["warnings"]) > 0

    def test_empty_password_returns_422(self):
        response = client.post("/analyze", json={"password": ""})
        assert response.status_code == 422

    def test_username_context_applied(self):
        response = client.post(
            "/analyze",
            json={
                "password": "abdullah2026!",
                "username": "abdullah",
                "check_breaches": False,
            },
        )
        data = response.json()
        assert data["pattern_detail"]["has_personal_info"] is True

    def test_missing_password_returns_422(self):
        response = client.post("/analyze", json={})
        assert response.status_code == 422


class TestGenerateEndpoint:
    def test_generates_default_word_count(self):
        response = client.post("/generate", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["word_count"] == 6

    def test_generates_custom_word_count(self):
        response = client.post("/generate", json={"word_count": 4})
        assert response.json()["word_count"] == 4

    def test_word_count_zero_rejected(self):
        response = client.post("/generate", json={"word_count": 0})
        assert response.status_code == 422

    def test_word_count_too_high_rejected(self):
        response = client.post("/generate", json={"word_count": 100})
        assert response.status_code == 422
