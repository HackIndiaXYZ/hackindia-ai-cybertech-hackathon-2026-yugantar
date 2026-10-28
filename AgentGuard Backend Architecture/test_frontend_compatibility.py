"""Regression tests for the Next.js frontend's future FastAPI adapter.

The tests use a stubbed AgentGuard response and do not call the live LLM or
start a Temporal worker.
"""

import os
import tempfile
from pathlib import Path

# Keep test persistence isolated from the developer's local audit database.
_TEST_DB_DIRECTORY = tempfile.TemporaryDirectory(prefix="agentguard-frontend-tests-")
os.environ["AGENTGUARD_DB_PATH"] = str(Path(_TEST_DB_DIRECTORY.name) / "test_audit.db")
os.environ["AGENTGUARD_APP_DB_PATH"] = str(Path(_TEST_DB_DIRECTORY.name) / "test_app.db")
os.environ["AGENTGUARD_AUTH_SECRET"] = "test-auth-secret-value-with-more-than-32-chars"
os.environ["GROQ_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from agent_logic import AnalysisResponse  # noqa: E402

client = TestClient(main.app)


def _auth_headers():
    import uuid
    email = f"frontend-test-{uuid.uuid4().hex}@example.test"
    response = client.post("/api/auth/signup", json={
        "email": email, "password": "A-strong-test-password-123", "name": "Frontend Test User"
    })
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _fake_response(**kwargs):
    return AnalysisResponse(
        mode="research",
        status="SUCCESS",
        summary="A test-only source-grounded summary.",
        extracted_claims=[],
        **kwargs,
    )


def test_frontend_compatibility_requires_a_valid_bearer_session():
    response = client.post(
        "/api/v1/security/temporal-stream",
        data={"prompt": "Review the security boundary.", "analysisMode": "deep_audit"},
    )
    assert response.status_code == 401


def test_frontend_compatibility_accepts_camel_case_mode(monkeypatch):
    captured = {}

    def fake_analyze_document(**kwargs):
        captured.update(kwargs)
        return _fake_response()

    monkeypatch.setattr(main.agent, "analyze_document", fake_analyze_document)

    auth_headers = _auth_headers()
    response = client.post(
        "/api/v1/security/temporal-stream",
        data={"prompt": "Review the system boundary.", "analysisMode": "deep_audit", "sessionId": "session-test-0001"},
        headers=auth_headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["analysisMode"] == "deep_audit"
    assert "content" in body and "evidence" in body and "telemetry" in body
    assert body["temporalWorkflowId"].startswith("ag-local-")
    assert body["executionTimeMs"] >= 1
    assert "source-grounded security analysis" in captured["prompt"].lower()
    assert body["capabilities"]["temporal_workflow_execution"] is False
    assert body["capabilities"]["cve_database_scan"] is False
    # Static text triage is real and labelled heuristic; it does not invent CVEs.
    assert body["evidence"]["detectedFindings"] == 0
    assert body["evidence"]["findingMethod"] == "heuristic text-pattern triage"
    assert body["capabilities"]["static_text_pattern_scan"] is True
    assert "cveCount" not in body["evidence"]
    assert "confidenceScore" not in body["telemetry"]
    history = client.get("/api/history?limit=50", headers=auth_headers)
    assert history.status_code == 200
    saved = next(item for item in history.json()["sessions"] if item["id"] == "session-test-0001")
    assert saved["messages"][-1]["content"] == body["content"]


def test_frontend_compatibility_accepts_snake_case_mode(monkeypatch):
    monkeypatch.setattr(main.agent, "analyze_document", lambda **kwargs: _fake_response())

    response = client.post(
        "/api/v1/security/temporal-stream",
        data={"prompt": "Review control statements.", "analysis_mode": "policy_check", "sessionId": "session-test-0002"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200, response.text
    assert response.json()["analysisMode"] == "policy_check"


def test_frontend_compatibility_rejects_unknown_mode():
    response = client.post(
        "/api/v1/security/temporal-stream",
        data={"prompt": "Run a review.", "analysisMode": "unknown_mode"},
        headers=_auth_headers(),
    )
    assert response.status_code == 422


def test_frontend_compatibility_requires_prompt_or_file():
    response = client.post(
        "/api/v1/security/temporal-stream",
        data={"prompt": "  ", "analysisMode": "deep_audit"},
        headers=_auth_headers(),
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_frontend_compatibility_reuses_pdf_route(monkeypatch):
    captured = {}

    async def fake_upload_and_analyze(req, file, user_prompt):
        captured["filename"] = file.filename
        captured["prompt"] = user_prompt
        req.state.agentguard_input_kind = "pdf"
        req.state.agentguard_pages_analyzed = 3
        return _fake_response()

    monkeypatch.setattr(main, "upload_and_analyze", fake_upload_and_analyze)

    response = client.post(
        "/api/v1/security/temporal-stream",
        data={"prompt": "Review this uploaded architecture.", "analysisMode": "quick_scan"},
        files={"file": ("architecture.pdf", b"%PDF-test", "application/pdf")},
        headers=_auth_headers(),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert captured["filename"] == "architecture.pdf"
    assert "Quick Scan" in captured["prompt"]
    assert body["evidence"]["pagesAnalyzed"] == 3
    assert body["telemetry"]["pagesParsed"] == 3
    assert body["capabilities"]["pdf_prompt_injection_detection"] is True

