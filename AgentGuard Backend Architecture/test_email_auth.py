"""Regression tests for SMTP event notifications and OTP password reset."""
from __future__ import annotations

from pathlib import Path
import uuid

import pytest
from fastapi.testclient import TestClient

import main
import saas_store

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def isolate_email_auth(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("AGENTGUARD_APP_DB_PATH", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("AGENTGUARD_AUTH_SECRET", "test-secret-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AGENTGUARD_EMAIL_NOTIFICATIONS_ENABLED", "false")
    for limiter_name in ("AUTH_RATE_LIMIT_STORE", "RATE_LIMIT_STORE"):
        limiter = getattr(main, limiter_name, None)
        if hasattr(limiter, "clear"):
            limiter.clear()


def signup(email: str | None = None):
    address = email or f"{uuid.uuid4().hex}@example.test"
    response = client.post("/api/auth/signup", json={
        "name": "Email Test User", "email": address, "password": "Original-password-123"
    })
    assert response.status_code == 201, response.text
    return response, address


def test_signup_and_login_send_email_notifications(monkeypatch: pytest.MonkeyPatch):
    events = []
    monkeypatch.setattr(main.email_service, "send_registration_notice", lambda email, name, ip: events.append(("register", email)) or "sent")
    monkeypatch.setattr(main.email_service, "send_login_notice", lambda email, name, ip, provider: events.append(("login", email, provider)) or "sent")
    created, email = signup()
    assert created.json()["email_notification"] == "sent"
    login = client.post("/api/auth/login", json={"email": email, "password": "Original-password-123"})
    assert login.status_code == 200, login.text
    assert login.json()["email_notification"] == "sent"
    assert events[0] == ("register", email)
    assert events[1] == ("login", email, "email")


def test_password_reset_otp_resets_password_and_revokes_sessions(monkeypatch: pytest.MonkeyPatch):
    sent_codes = []
    monkeypatch.setattr(main.email_service, "notifications_enabled", lambda: True)
    monkeypatch.setattr(main.email_service, "send_password_reset_otp", lambda email, otp: sent_codes.append((email, otp)) or True)
    monkeypatch.setattr(main.email_service, "send_password_changed_notice", lambda email, name: "sent")
    created, email = signup()
    old_token = created.json()["access_token"]

    requested = client.post("/api/auth/password-reset/request", json={"email": email})
    assert requested.status_code == 202, requested.text
    assert requested.json()["status"] == "ACCEPTED"
    assert len(sent_codes) == 1 and sent_codes[0][0] == email
    otp = sent_codes[0][1]
    # OTP must not be returned by the API response.
    assert otp not in requested.text

    reset = client.post("/api/auth/password-reset/confirm", json={
        "email": email, "otp": otp, "new_password": "New-password-456"
    })
    assert reset.status_code == 200, reset.text
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": email, "password": "Original-password-123"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": email, "password": "New-password-456"}).status_code == 200


def test_unknown_email_receives_generic_reset_response_and_no_mail(monkeypatch: pytest.MonkeyPatch):
    sent_codes = []
    monkeypatch.setattr(main.email_service, "notifications_enabled", lambda: True)
    monkeypatch.setattr(main.email_service, "send_password_reset_otp", lambda email, otp: sent_codes.append((email, otp)) or True)
    response = client.post("/api/auth/password-reset/request", json={"email": "unknown@example.test"})
    assert response.status_code == 202
    assert response.json()["message"].startswith("If this address belongs")
    assert sent_codes == []


def test_reset_endpoint_fails_clearly_if_smtp_is_not_configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(main.email_service, "notifications_enabled", lambda: False)
    response = client.post("/api/auth/password-reset/request", json={"email": "user@example.test"})
    assert response.status_code == 503
    assert "SMTP" in response.json()["detail"]


def test_wrong_otp_attempts_exhaust_challenge(monkeypatch: pytest.MonkeyPatch):
    sent_codes = []
    monkeypatch.setattr(main.email_service, "notifications_enabled", lambda: True)
    monkeypatch.setattr(main.email_service, "send_password_reset_otp", lambda email, otp: sent_codes.append(otp) or True)
    _, email = signup()
    response = client.post("/api/auth/password-reset/request", json={"email": email})
    assert response.status_code == 202
    real_otp = sent_codes[0]
    for _ in range(5):
        wrong = client.post("/api/auth/password-reset/confirm", json={
            "email": email, "otp": "999999" if real_otp != "999999" else "888888",
            "new_password": "Another-password-123",
        })
        assert wrong.status_code == 400
    expired = client.post("/api/auth/password-reset/confirm", json={
        "email": email, "otp": real_otp, "new_password": "Another-password-123",
    })
    assert expired.status_code == 400


def test_reset_code_is_not_stored_in_plaintext(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(main.email_service, "notifications_enabled", lambda: True)
    sent_codes = []
    monkeypatch.setattr(main.email_service, "send_password_reset_otp", lambda email, otp: sent_codes.append(otp) or True)
    _, email = signup()
    response = client.post("/api/auth/password-reset/request", json={"email": email})
    assert response.status_code == 202
    conn = saas_store._connect()
    try:
        rows = conn.execute("SELECT otp_hash FROM app_password_reset_otps").fetchall()
        assert len(rows) == 1
        assert sent_codes[0] not in rows[0]["otp_hash"]
        assert len(rows[0]["otp_hash"]) == 64
    finally:
        conn.close()
