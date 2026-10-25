"""Regression tests for root routing, health readiness, and audit semantics."""

from fastapi.testclient import TestClient

import main
from agent_logic import AnalysisResponse

client = TestClient(main.app)


def test_root_redirects_to_real_health_endpoint():
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/health"

    followed = client.get("/")
    assert followed.status_code == 200
    assert followed.json()["service"] == "AgentGuard Security Control Plane"


def test_health_reports_degraded_when_policy_cannot_load(monkeypatch):
    def fail_policy():
        raise RuntimeError("test-only policy failure")

    monkeypatch.setattr(main.policy_engine, "load_policy", fail_policy)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["policy_ready"] is False


def test_analysis_without_tool_action_is_not_a_fake_allow(monkeypatch):
    captured = {}

    def record(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(main.audit_logger, "log_evaluation", record)
    response = AnalysisResponse(
        mode="live_llm",
        status="SUCCESS",
        summary="Text-only summary; no action authorized.",
        mode_reason="Text-only summarization completed.",
    )
    main._write_audit(response, prompt="Summarize this", file_name="direct_input")
    assert captured["verdict"] == "ANALYSIS_ONLY"


def test_audit_normalization_preserves_analysis_only():
    from database import _normalize_verdict

    assert _normalize_verdict("ANALYSIS_ONLY") == "ANALYSIS_ONLY"
    assert _normalize_verdict("unrecognized-audit-value") == "BLOCK"
