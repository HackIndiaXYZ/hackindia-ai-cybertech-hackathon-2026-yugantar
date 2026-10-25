from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import main
from fastapi.testclient import TestClient

client = TestClient(main.app)

from security_scanner import (
    _cvss_v3_base_score,
    assess_policy_evidence,
    parse_dependency_manifest,
    scan_text,
    scan_dependency_manifest,
)


def test_text_scanner_finds_and_redacts_aws_access_identifier():
    report = scan_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "notes.txt")
    assert report["findingCount"] == 1
    finding = report["findings"][0]
    assert finding["ruleId"] == "AG-SECRET-AWS-ACCESS-ID"
    assert "AKIA1234567890ABCDEF" not in finding["evidence"]
    assert finding["verified"] is False
    assert "textLine" in finding and "page" not in finding


def test_text_scanner_does_not_invent_findings_for_neutral_text():
    report = scan_text("TLS verification is enabled. Debug mode is disabled.")
    assert report["findingCount"] == 0
    assert report["riskLevel"] is None


def test_policy_evidence_is_not_a_compliance_score():
    result = assess_policy_evidence("Service uses TLS 1.3 and stores audit logs.")
    assert result["observedCount"] >= 1
    assert "disclaimer" in result
    assert "score" not in result
    assert any(item["status"] == "not_found_in_supplied_text" for item in result["controls"])


def test_requirements_parser_only_queries_exact_pins():
    result = parse_dependency_manifest("requirements.txt", b"fastapi==0.115.0\nhttpx>=0.27\n# comment\n")
    assert result["packages"] == [{"name": "fastapi", "version": "0.115.0", "ecosystem": "PyPI"}]
    assert len(result["skipped"]) == 1


def test_npm_lock_parser_reads_exact_installed_versions():
    raw = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/next": {"version": "14.2.15"}}}).encode()
    result = parse_dependency_manifest("package-lock.json", raw)
    assert result["packages"] == [{"name": "next", "version": "14.2.15", "ecosystem": "npm"}]


def test_cvss_v31_vector_calculates_known_base_score():
    assert _cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _cvss_v3_base_score("not-a-vector") is None


class _FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"results": [{"vulns": [{
            "id": "GHSA-test-1234",
            "aliases": ["CVE-2025-12345"],
            "summary": "Test advisory from fake provider fixture",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "references": [{"url": "https://osv.dev/vulnerability/GHSA-test-1234"}],
        }]}]}


class _FakeClient:
    async def post(self, *args, **kwargs):
        return _FakeResponse()


@pytest.mark.anyio
async def test_osv_report_preserves_provider_source_and_computed_cvss():
    result = await scan_dependency_manifest("requirements.txt", b"sample-package==1.2.3\n", client=_FakeClient())
    assert result["status"] == "FINDINGS"
    assert result["findings"][0]["cveIds"] == ["CVE-2025-12345"]
    assert result["findings"][0]["cvssV3BaseScore"] == 9.8
    assert result["findings"][0]["source"] == "https://osv.dev/"
    assert result["findings"][0]["verifiedFromProvider"] is True


def test_api_key_authenticates_and_revocation_is_honored(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_APP_DB_PATH", str(tmp_path / "api-key.db"))
    monkeypatch.setenv("AGENTGUARD_AUTH_SECRET", "test-secret-with-at-least-thirty-two-characters")
    main.AUTH_RATE_LIMIT_STORE.clear()
    created = client.post("/api/auth/signup", json={"name": "API Key Tester", "email": "key-test@example.com", "password": "Strong-password-123"})
    assert created.status_code == 201, created.text
    token = created.json()["access_token"]
    key_resp = client.post("/api/account/api-keys", headers={"Authorization": f"Bearer {token}"}, json={"name": "CI test"})
    assert key_resp.status_code == 201, key_resp.text
    key = key_resp.json()["api_key"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {key['secret']}"})
    assert me.status_code == 200, me.text
    revoke = client.delete(f"/api/account/api-keys/{key['id']}", headers={"Authorization": f"Bearer {token}"})
    assert revoke.status_code == 200
    after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {key['secret']}"})
    assert after.status_code == 401


def test_oauth_provider_list_only_enables_configured_providers(monkeypatch):
    for name in ("OAUTH_GOOGLE_CLIENT_ID", "OAUTH_GOOGLE_CLIENT_SECRET", "OAUTH_GOOGLE_REDIRECT_URI", "OAUTH_GITHUB_CLIENT_ID", "OAUTH_GITHUB_CLIENT_SECRET", "OAUTH_GITHUB_REDIRECT_URI"):
        monkeypatch.delenv(name, raising=False)
    response = client.get("/api/auth/oauth/providers")
    assert response.status_code == 200
    assert response.json()["providers"] == []
