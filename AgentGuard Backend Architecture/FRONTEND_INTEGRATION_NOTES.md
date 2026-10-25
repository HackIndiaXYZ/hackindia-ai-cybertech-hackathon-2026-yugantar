AgentGuard — Frontend Integration Notes
Frontend and backend remain in separate folders. The Next.js frontend reads NEXT_PUBLIC_AGENTGUARD_API_BASE_URL (default http://127.0.0.1:8010) and calls FastAPI with a backend-issued Bearer token. Default backend CORS supports local frontend ports 3000 and 3001.
Integrated endpoints
- POST /api/v1/security/temporal-stream: real multipart text/PDF analysis that reuses existing AgentGuard analysis, PDF parsing, prompt-injection checks, policy and audit logic; request fields prompt, optional file, analysisMode, optional sessionId. This path persists the response in the authenticated user's server-side history.
- POST /api/v1/security/dependency-scan: authenticated exact-version requirements/npm manifest lookup against OSV.dev. Results are also persisted to the signed-in user's history. Network failure is shown as UNAVAILABLE, not as a clean scan.
- POST /api/auth/signup, POST /api/auth/login, GET /api/auth/me, POST /api/auth/logout: server-side account/session flow; credentials are not fabricated in Next.js.
- GET /api/history, DELETE /api/history, DELETE /api/history/{session_id}: per-user server-side history.
- GET/PATCH /api/account/settings: persistent preferences (theme).
- GET/POST /api/account/api-keys, DELETE /api/account/api-keys/{key_id}: API key lifecycle, plaintext shown only once.
- GET /api/account/sessions, DELETE /api/account/sessions/revoke-others, DELETE /api/account/sessions/{session_id}: server-side session listing/revocation.
The frontend API service no longer generates mock analysis reports. Its loader displays response status and returned lineage after the request completes; it does not stream a Temporal worker.
Features with configuration or implementation limits (do not overstate)
- Google/GitHub OAuth is implemented as a provider redirect/callback flow but remains unavailable until provider IDs, secrets, and exact callback URLs are configured. It has not been end-to-end tested against real provider credentials in this workspace.
- Temporal: no server or worker is included; temporalWorkflowId is only a request correlation ID. The UI labels actual FastAPI health instead of claiming a Temporal worker is active.
- Dependency advisory lookup is available through /api/v1/security/dependency-scan for supported exact-version manifests. It uses OSV.dev; it is not a full source-code, binary, container, or runtime scanner. CVSS v3 is shown only when an upstream advisory provides a supported vector.
- quick_scan on text/PDF uses narrow heuristic secret/configuration patterns. policy_check reports control-topic mentions, not a compliance score or certification.
- Original uploaded PDF storage: disabled. The report is persisted, but the file's bytes are not; reattach PDFs to preview/download them in a later session. Page counts are shown only when returned by the parser.
Local smoke-test checklist
1. Start backend: python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000; check /health and /docs.
2. In the frontend folder, copy .env.local.example to .env.local, confirm NEXT_PUBLIC_AGENTGUARD_API_BASE_URL=http://127.0.0.1:8010, run npm ci, then npm run dev. The frontend ZIP contains the package lock file; run npm commands in the frontend directory, not the project root.
3. Sign up with a unique email and a password at least 8 characters long. Refresh and confirm the session is revalidated by /api/auth/me.
4. Submit text-only analysis, attach a non-sensitive real PDF, and optionally use the adjacent manifest-scan button for an exact-version requirements.txt or npm lock manifest. The dependency scan requires access to OSV.dev and does not treat an unavailable service as clean.
5. Refresh dashboard and select saved history; clear/delete a history item and verify it is deleted server-side.
6. Change theme, create an API key, copy it once, close/reopen Settings (plaintext should be gone), revoke the key and confirm a Bearer call with it receives 401.
7. Verify logout revokes the session when backend is online; OAuth buttons should honestly report not configured.
The account/history store is a local SQLite, single-process development implementation. Do not expose the development server publicly or use real confidential data until production authentication, storage, TLS, CSRF, rate limiting, logging and deployment controls are designed and reviewed.
- Staging a PDF creates a metadata-only server history row via POST /api/history; original PDF bytes remain in the browser unless the user starts analysis.