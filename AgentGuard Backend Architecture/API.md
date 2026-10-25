Backend setup and frontend integration
This backend exposes a FastAPI service. Start it from this directory:
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --reload --host 127.0.0.1 --port 8000
The service normally listens at http://127.0.0.1:8000; on this Windows setup, use 8010 if port 8000 is denied by Windows. Interactive API documentation is available at /docs, and the OpenAPI schema is at /openapi.json. Check GET /health before connecting a frontend.
Configuration
- CORS_ORIGINS: comma-separated frontend origins. The local defaults allow
  http://localhost:3000 and http://127.0.0.1:3000. Set the exact deployed
  frontend origins for production.
- GROQ_API_KEY: optional; without it, local analysis is used.
- REVIEWER_TOKEN: optional for analysis, but required for reviewer endpoints. Use a unique value of at least 32 characters. Never put this secret in browser-side code; send reviewer requests through a frontend server-side route that adds the X-Reviewer-Token header.
- AGENTGUARD_AUTH_SECRET: optional. If blank, local development creates .agentguard_auth_secret next to the backend. Keep that file private and stable while local accounts exist.
- AGENTGUARD_APP_DB_PATH: optional path to the separate SQLite account/session/history/API-key store. It is separate from agentguard_audit.db.
- FRONTEND_BASE_URL: frontend origin for OAuth callback redirects.
- OAUTH_GOOGLE_CLIENT_ID, OAUTH_GOOGLE_CLIENT_SECRET, OAUTH_GOOGLE_REDIRECT_URI and the corresponding OAUTH_GITHUB_* settings enable provider login only when each provider's credentials and redirect URL are configured.
- AGENTGUARD_DB_PATH: optional SQLite database path. By default, audit and
  approval data is stored in agentguard_audit.db next to the backend code.
The legacy /api/analyze and /api/upload_and_analyze routes are retained for compatibility and do not require an end-user account. The /api/v1/security/temporal-stream, /api/v1/security/dependency-scan, account, and history endpoints require a valid backend-issued Bearer session or a non-revoked AgentGuard API key. The local auth/history store is single-process development storage; review deployment controls before production use. The built-in in-memory rate limiter allows 30 requests per client IP per rolling minute and is not shared across workers.
Endpoints
GET /health
Returns service and configuration readiness indicators. A healthy HTTP response
does not mean optional LLM or reviewer authentication is configured; inspect
policy_ready, llm_configured, and reviewer_auth_configured.
POST /api/analyze
Send JSON:
{
  "prompt": "Summarize the supplied research text.",
  "document_text": "Optional document text",
  "scenario_id": null,
  "force_provenance": null
}
prompt is required (1-4,000 characters). document_text is optional (up to
200,000 characters). scenario_id is optional and supports the scripted
demonstrations safe_search, malicious_export, user_export, and
mixed_context. force_provenance is retained for compatibility and does not
grant trust or authorization.

The JSON response includes status, mode, summary, extracted_claims,
security_decision, action_lineage, approval_id, and approval_hash.
Research-related responses may also include research_sources,
research_claims, and claim_evidence_reviews. Treat status and
security_decision as authoritative; an HTTP 200 response does not mean a
proposed action was allowed.
POST /api/upload_and_analyze
Send multipart/form-data with:
- file: a PDF file.
- user_prompt: optional analysis instructions.
Limits are 10 MB per PDF, 50 pages, 200,000 extracted characters, and 4,000
characters for the prompt. Scanned PDFs requiring OCR are not supported.
Account and application endpoints
- POST /api/auth/signup, POST /api/auth/login, GET /api/auth/me, POST /api/auth/logout manage real local accounts and backend-validated sessions.
- GET /api/auth/oauth/providers returns only configured OAuth providers. For Google/GitHub, configure all three provider environment values, then begin at GET /api/auth/oauth/{provider}/start. The registered callback must exactly match OAUTH_*_REDIRECT_URI. OAuth is unavailable until configured.
- GET/PATCH /api/account/settings reads/writes allowed preferences.
- GET/POST /api/account/api-keys, DELETE /api/account/api-keys/{key_id} manage API keys. The plaintext key is returned only once; the database stores a SHA-256 hash. Revoked keys cannot authenticate.
- GET /api/account/sessions, DELETE /api/account/sessions/revoke-others, DELETE /api/account/sessions/{session_id} manage sessions.
- GET /api/history, DELETE /api/history, DELETE /api/history/{session_id} manage per-user report history. Original PDF bytes are not stored in history; extracted report text and telemetry are stored.
Frontend analysis endpoint
POST /api/v1/security/temporal-stream accepts multipart prompt, optional PDF file, analysisMode (or analysis_mode) and sessionId. The modes are deep_audit, quick_scan, and policy_check. The response includes the real engine response, static text-pattern triage, and policy evidence mentions where applicable. It does not run a Temporal worker or make a formal compliance claim. The temporalWorkflowId field is retained for frontend compatibility and is only a correlation ID.
Dependency advisory lookup
POST /api/v1/security/dependency-scan requires authentication and multipart/form-data with file and optional sessionId. Supported manifests are exact-version requirements*.txt, package.json, package-lock.json, and npm-shrinkwrap.json up to 2 MB. Exact versions are queried against OSV.dev. A provider/network failure returns UNAVAILABLE, not a fabricated clean result. If the upstream record includes a CVSS v3 vector, its base score is calculated from that vector and attributed to OSV.
Reviewer endpoints
All these endpoints require X-Reviewer-Token:
- GET /api/audit_logs?limit=50 — limit must be between 1 and 100.
- GET /api/pending_approvals — returns active approval requests and their
  args_hash.
- POST /api/approve — approves or rejects a pending action.
Approval request body:
{
  "approval_id": "appr-...",
  "approve": true,
  "expected_hash": "hash-returned-by-the-pending-approvals-endpoint"
}
The hash is required when approve is true; the gateway verifies it and
re-evaluates policy before processing. To reject, set approve to false.
Approval requests expire after 10 minutes and can only be processed once.
Frontend request examples
For local development, browser calls can use the API origin directly as long
as it is included in CORS_ORIGINS:
const response = await fetch("http://127.0.0.1:8000/api/analyze", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    prompt: "Summarize this research text.",
    document_text: text
  })
});

const result = await response.json();
if (!response.ok) {
  throw new Error(result.message ?? "Backend request failed");
}
For PDF upload, use FormData and let the browser set the multipart boundary:
const form = new FormData();
form.append("file", file);
form.append("user_prompt", "Extract source-grounded claims.");

const response = await fetch(
  "http://127.0.0.1:8000/api/upload_and_analyze",
  { method: "POST", body: form }
);
Errors use a JSON response with status, error_type, message, detail,
and path. Common HTTP statuses are 400/422 for invalid input, 401/503 for
reviewer authentication failures, 413 for size limits, 429 for rate limiting,
and 500 for unexpected server errors.

POST /api/history creates a metadata-only history entry for a staged upload using { "sessionId": "...", "title": "...", "mode": "deep_audit" }. It does not upload or persist file bytes. A completed analysis appends its user/agent messages to that same session.
Email notifications and password reset
POST /api/auth/signup and POST /api/auth/login attempt a registration/login notification when SMTP email notifications are explicitly enabled. Responses include email_notification (sent, failed, or not_configured).

POST /api/auth/password-reset/request accepts { "email": "user@example.com" }. When SMTP is configured, it sends a six-digit, single-use OTP that expires in 10 minutes. Its response is generic regardless of whether an account exists. POST /api/auth/password-reset/confirm accepts { "email": "user@example.com", "otp": "123456", "new_password": "a-longer-password" }. A successful reset revokes existing sessions. The aliases /api/auth/forgot-password and /api/auth/reset-password are available.

Configure SMTP only in the backend .env; see EMAIL_OTP_SETUP.md.