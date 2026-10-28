"""Regression tests for local account auth, history, preferences, sessions, and API keys."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
import saas_store

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def isolate_account_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("AGENTGUARD_APP_DB_PATH", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("AGENTGUARD_AUTH_SECRET", "test-secret-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AGENTGUARD_EMAIL_NOTIFICATIONS_ENABLED", "false")
    # Avoid cross-test effects across backend versions that use either
    # a dedicated auth limiter or the shared request limiter.
    for limiter_name in ("AUTH_RATE_LIMIT_STORE", "RATE_LIMIT_STORE"):
        limiter = getattr(main, limiter_name, None)
        if hasattr(limiter, "clear"):
            limiter.clear()


def signup(name: str = "Test Analyst", email: str | None = None):
    import uuid
    account_email = email or f"{uuid.uuid4().hex}@example.test"
    response = client.post(
        "/api/auth/signup",
        json={"email": account_email, "password": "Strong-password-123", "name": name},
    )
    return response, account_email


def headers_for(response):
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_signup_login_me_and_logout_revokes_token():
    created, email = signup()
    assert created.status_code == 201, created.text
    bearer = headers_for(created)
    assert client.get("/api/auth/me", headers=bearer).status_code == 200

    login = client.post("/api/auth/login", json={"email": email, "password": "Strong-password-123"})
    assert login.status_code == 200, login.text
    login_bearer = headers_for(login)
    assert client.get("/api/auth/me", headers=login_bearer).json()["user"]["email"] == email

    logout = client.post("/api/auth/logout", headers=login_bearer)
    assert logout.status_code == 200
    assert client.get("/api/auth/me", headers=login_bearer).status_code == 401
    # The original signup session remains independently valid.
    assert client.get("/api/auth/me", headers=bearer).status_code == 200


def test_duplicate_signup_and_wrong_password_are_rejected():
    created, email = signup()
    assert created.status_code == 201
    duplicate = client.post(
        "/api/auth/signup",
        json={"email": email, "password": "Another-password-123", "name": "Duplicate"},
    )
    assert duplicate.status_code == 409
    wrong = client.post("/api/auth/login", json={"email": email, "password": "incorrect"})
    assert wrong.status_code == 401


def test_cookie_marker_alone_never_authenticates_api_requests():
    response = client.get("/api/auth/me", cookies={"agentguard_auth_token": "active"})
    assert response.status_code == 401


def test_preferences_api_key_create_list_authentication_and_revoke():
    created, _ = signup()
    bearer = headers_for(created)

    settings = client.get("/api/account/settings", headers=bearer)
    assert settings.status_code == 200
    assert settings.json()["preferences"]["theme"] == "system"
    updated = client.patch("/api/account/settings", headers=bearer, json={"theme": "dark", "reduceMotion": True})
    assert updated.status_code == 200
    assert updated.json()["preferences"]["theme"] == "dark"
    bad = client.patch("/api/account/settings", headers=bearer, json={"theme": "invisible"})
    assert bad.status_code == 422

    key_response = client.post("/api/account/api-keys", headers=bearer, json={"name": "Test automation"})
    assert key_response.status_code == 201, key_response.text
    key = key_response.json()["api_key"]
    assert key["secret"].startswith("ag_sec_live_")
    api_bearer = {"Authorization": f"Bearer {key['secret']}"}
    assert client.get("/api/account/settings", headers=api_bearer).status_code == 200

    listed = client.get("/api/account/api-keys", headers=bearer).json()["api_keys"]
    assert len(listed) == 1
    assert "secret" not in listed[0]
    revoked = client.delete(f"/api/account/api-keys/{key['id']}", headers=bearer)
    assert revoked.status_code == 200
    assert client.get("/api/account/settings", headers=api_bearer).status_code == 401


def test_history_is_persisted_scoped_and_deletable():
    created, _ = signup("Primary Analyst")
    headers = headers_for(created)
    user_id = created.json()["user"]["id"]

    item = saas_store.save_history_analysis(
        user_id=user_id,
        client_session_id="session-history-01",
        mode="deep_audit",
        prompt="Review the authentication boundary.",
        filename=None,
        content="Actual test response.",
        evidence={"pagesAnalyzed": 0},
        telemetry={"executionTime": "20ms"},
    )
    assert item["sessionId"] == "session-history-01"
    history = client.get("/api/history", headers=headers)
    assert history.status_code == 200
    assert history.json()["sessions"][0]["messages"][-1]["content"] == "Actual test response."

    another, _ = signup("Different Analyst")
    assert client.get("/api/history", headers=headers_for(another)).json()["sessions"] == []

    deleted = client.delete("/api/history/session-history-01", headers=headers)
    assert deleted.status_code == 200
    assert client.get("/api/history", headers=headers).json()["sessions"] == []


def test_sessions_revocation_and_oauth_not_falsely_successful():
    first, _ = signup()
    second_login = client.post(
        "/api/auth/login",
        json={"email": first.json()["user"]["email"], "password": "Strong-password-123"},
    )
    assert second_login.status_code == 200
    headers = headers_for(second_login)
    sessions = client.get("/api/account/sessions", headers=headers).json()["sessions"]
    assert len(sessions) == 2
    assert sum(1 for session in sessions if session["isCurrent"]) == 1

    revoked = client.delete("/api/account/sessions/revoke-others", headers=headers)
    assert revoked.status_code == 200
    active_sessions = client.get("/api/account/sessions", headers=headers).json()["sessions"]
    assert len(active_sessions) == 1 and active_sessions[0]["isCurrent"] is True

    oauth = client.post("/api/auth/oauth/google", json={})
    assert oauth.status_code == 501


def test_dependency_scan_response_is_persisted_to_user_history(monkeypatch):
    import asyncio

    created, _ = signup("Manifest Analyst")
    bearer = headers_for(created)

    async def fake_scan(filename, raw):
        assert filename == "requirements.txt"
        assert b"fastapi==" in raw
        return {
            "status": "FINDINGS",
            "source": "OSV.dev",
            "sourceName": filename,
            "scannedPackages": [{"name": "fastapi", "version": "0.1.0", "ecosystem": "PyPI", "status": "advisories_found"}],
            "findings": [{"advisoryId": "GHSA-test", "summary": "Test advisory", "package": "fastapi", "installedVersion": "0.1.0", "ecosystem": "PyPI", "cveIds": ["CVE-2025-00001"], "references": ["https://osv.dev/vulnerability/GHSA-test"]}],
            "skipped": [],
            "limitations": ["Provider test fixture."],
        }

    monkeypatch.setattr(main, "scan_dependency_manifest", fake_scan)
    response = client.post(
        "/api/v1/security/dependency-scan",
        headers=bearer,
        data={"sessionId": "session-dep-test-001"},
        files={"file": ("requirements.txt", b"fastapi==0.1.0\n", "text/plain")},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "FINDINGS"
    assert payload["findings"][0]["advisoryId"] == "GHSA-test"
    assert "CVE-2025-00001" in payload["reportMarkdown"]
    assert payload["history"]["sessionId"] == "session-dep-test-001"

    history = client.get("/api/history", headers=bearer)
    assert history.status_code == 200
    saved = history.json()["sessions"]
    assert saved and saved[0]["id"] == "session-dep-test-001"
    assert "Test advisory" in saved[0]["messages"][-1]["content"]


def test_staged_upload_history_metadata_is_persisted():
    created, _ = signup()
    headers = headers_for(created)
    response = client.post(
        "/api/history",
        headers=headers,
        json={"sessionId": "session-upload-01", "title": "Audit: architecture.pdf", "mode": "deep_audit"},
    )
    assert response.status_code == 201, response.text
    item = response.json()["history"]
    assert item["sessionId"] == "session-upload-01"
    history = client.get("/api/history", headers=headers).json()["sessions"]
    assert any(row["id"] == "session-upload-01" and row["messages"] == [] for row in history)


def test_staged_upload_history_rejects_invalid_mode():
    created, _ = signup()
    response = client.post(
        "/api/history",
        headers=headers_for(created),
        json={"sessionId": "session-upload-02", "title": "Invalid", "mode": "admin_override"},
    )
    assert response.status_code == 422


def test_session_last_active_is_recorded():
    created, _ = signup()
    headers = headers_for(created)
    sessions = client.get("/api/account/sessions", headers=headers)
    assert sessions.status_code == 200
    session = sessions.json()["sessions"][0]
    assert isinstance(session["lastActive"], int)
    assert session["lastActive"] >= session["createdAt"]
    assert session["isCurrent"] is True

