AgentGuard

A zero-trust action control plane and research-security workspace for AI agents.

AgentGuard is designed to inspect untrusted inputs, evaluate proposed tool actions against explicit security policies, preserve audit evidence, and support human review before a sensitive action is allowed. Its research workspace can analyze supplied text or PDF documents and return source-grounded candidate claims, security decisions, and analysis telemetry.

Project status: Active development. Local automated tests have passed in the working development environment, but the complete Next.js build, real provider OAuth callbacks, SMTP delivery, and all browser-based end-to-end flows must be verified in the target environment before production use.

Contents

Core capabilities

Architecture

Technology stack

Repository layout

Local development setup

Configuration

API overview

Optional integrations

Security model and limitations

Tests and troubleshooting

Core capabilities

Zero-trust action control

Evaluates proposed actions through the policy/security gateway.

Uses explicit ALLOW, REVIEW, and BLOCK decisions rather than treating an LLM response as authorization.

Supports reviewer-authenticated audit logs, pending approvals, and hash-bound approval decisions.

Keeps mock email/export tool demonstrations separate from real external actions.

Research-agent workflow

Accepts a text prompt and optional PDF document.

Extracts document text and produces a structured analysis response.

Can use the configured OpenAI-compatible Groq endpoint for text-only summaries; local fallback behavior is available when the LLM is not configured.

Supports research-source retrieval through the existing research/RAG pipeline where configured.

Returns candidate claims, source metadata, evidence reviews, decision information, and action lineage where applicable.

Research findings should be treated as evidence-grounded candidates, not as proof that a scientific claim has been independently verified. Search relevance or an abstract alone is not equivalent to full-paper review.

Security scanning and assessment

Dependency advisories: supports exact-version dependency manifests such as requirements*.txt, package.json, package-lock.json, and npm-shrinkwrap.json; queries OSV.dev for advisory records.

Codebase triage: scans a bounded ZIP archive for supported source/configuration patterns and supported dependency manifests.

CVSS v3.1: calculates a base score from a complete canonical CVSS v3.1 vector. If an OSV record supplies a vector, the derived score is attributed to that source.

Compliance evidence: assesses documented evidence against supported checklists, including an AgentGuard-defined baseline. This is evidence coverage/self-assessment—not a certification or an official universal NIST compliance percentage.

Failure reporting: unavailable advisory-provider responses are reported as unavailable; they are not silently treated as a clean scan.

Accounts and application state

Local signup, password login, backend-validated sessions, and logout/session revocation.

Per-user saved history and supported history deletion operations.

Account preferences, API-key management, and session management.

Google and GitHub OAuth routes are configuration-dependent and are unavailable until credentials and redirect URLs are configured.

Optional workflow orchestration

Temporal workflow definitions, activities, and a worker entry point are provided in the advanced backend update. Temporal is disabled by default. A real Temporal execution requires a running Temporal service and the AgentGuard worker; a correlation ID from synchronous mode is not a Temporal workflow execution.

Architecture

The frontend and backend run as separate applications and communicate over HTTP:

Browser
  |
  v
Next.js frontend (default: http://localhost:3000)
  |
  | JSON / multipart requests + backend-issued Bearer token
  v
FastAPI backend (default: http://127.0.0.1:8000)
  |
  +--> Authentication and account/session store (SQLite)
  +--> Research agent and PDF/RAG pipeline
  +--> Prompt-injection detectors and policy/security gateway
  +--> Audit log and human-approval workflow
  +--> OSV.dev dependency-advisory lookup
  +--> Optional Temporal workflow/worker

The account/session/history store is separate from the audit/approval database. Keep both local database files private and back them up before making storage or schema changes.

Technology stack

Backend: Python, FastAPI, Pydantic, Uvicorn

Research/AI integration: OpenAI-compatible client configured for Groq (optional)

PDF processing: pypdf

Policy and security: YAML policy configuration, prompt-injection detection, audit logging, human approval checks

Persistence: SQLite for local account/session/history data and audit/approval data

Dependency intelligence: OSV.dev API

Optional orchestration: Temporal Python SDK

Frontend: Next.js, React, TypeScript, Zustand, Radix/shadcn-style UI components

Repository layout

Keep the frontend and backend in separate directories. The exact folder names may differ between your local setup and GitHub repository.

AgentGuard/
├── AgentGuard Backend Architecture/
│   ├── main.py
│   ├── agent_logic.py
│   ├── rag_engine.py
│   ├── mcp_gateway.py
│   ├── detectors.py
│   ├── database.py
│   ├── saas_store.py
│   ├── security_scanner.py
│   ├── codebase_scanner.py
│   ├── temporal_workflows.py
│   ├── temporal_activities.py
│   ├── temporal_worker.py
│   ├── policy.yaml
│   └── requirements.txt
└── AgentGuard Frontend Architecture/
    ├── package.json
    ├── middleware.ts
    └── src/
        ├── app/
        ├── components/
        ├── lib/
        ├── services/
        └── store/

Some files (for example security_scanner.py, codebase_scanner.py, or temporal_*.py) are part of the advanced feature update. Make sure the matching files and backend main.py version are present before using their endpoints.

Local development setup

1. Start the backend

Open PowerShell in the backend folder. Example path:

cd "C:\Users\aryan\OneDrive\Desktop\agent\AgentGuard\AgentGuard Backend Architecture"

Create and activate the virtual environment, then install dependencies:

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

If a .env file does not exist, create one locally. Do not overwrite an existing .env with a template, and never commit secrets.

Start FastAPI:

python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

Check these URLs in a browser:

Health: http://127.0.0.1:8000/health

Interactive API documentation: http://127.0.0.1:8000/docs

OpenAPI schema: http://127.0.0.1:8000/openapi.json

If Windows reports WinError 10013 for port 8000, try another allowed local port such as 8010 and update the frontend API URL to match. Do not delete Windows port reservations blindly.

2. Start the frontend

Open a second terminal in the frontend folder:

cd "C:\Users\aryan\OneDrive\Desktop\agent\AgentGuard\AgentGuard Frontend Architecture"

Configure .env.local with the API URL matching the running backend. For example:

NEXT_PUBLIC_AGENTGUARD_API_BASE_URL=http://127.0.0.1:8000

Install dependencies and start Next.js:

npm install
npm run dev

Open http://localhost:3000.

React 19 dependency note: if npm reports a peer-dependency conflict between React 19 and next-themes@0.3.0, update next-themes to a React-19-compatible 0.4.x release (for example, npm install next-themes@^0.4.6) and then run npm install again. Do not start with --force; first resolve the incompatible package range. Commit the regenerated package lock after validating the build.

3. Verify tests and production build

Backend tests:

python -m py_compile main.py agent_logic.py rag_engine.py mcp_gateway.py database.py detectors.py
python -m pytest -q

If the advanced modules are present, include them in the syntax check:

python -m py_compile security_scanner.py codebase_scanner.py temporal_workflows.py temporal_activities.py temporal_worker.py

Frontend build:

npm run build

Passing unit tests does not replace browser-level verification. Test registration, login/logout, PDF upload, text analysis, history, settings, and reviewer approval with a local test account before using real data.

Configuration

Keep secrets in the backend .env file, never in NEXT_PUBLIC_* variables or committed files.

Common backend settings (set only the ones you need):

# Frontend origin(s), comma-separated
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
FRONTEND_BASE_URL=http://localhost:3000

# Optional LLM integration
GROQ_API_KEY=
GROQ_MODEL=openai/gpt-oss-120b

# Required by reviewer-only APIs
REVIEWER_TOKEN=

# Optional stable auth secret; use a private, long random value
AGENTGUARD_AUTH_SECRET=

# Optional local database paths
AGENTGUARD_APP_DB_PATH=
AGENTGUARD_DB_PATH=

# OAuth: configure each provider completely to enable it
OAUTH_GOOGLE_CLIENT_ID=
OAUTH_GOOGLE_CLIENT_SECRET=
OAUTH_GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/auth/oauth/google/callback
OAUTH_GITHUB_CLIENT_ID=
OAUTH_GITHUB_CLIENT_SECRET=
OAUTH_GITHUB_REDIRECT_URI=http://127.0.0.1:8000/api/auth/oauth/github/callback

# Temporal is optional and disabled unless explicitly enabled
AGENTGUARD_TEMPORAL_ENABLED=false
TEMPORAL_ADDRESS=127.0.0.1:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=agentguard-analysis
TEMPORAL_API_KEY=
TEMPORAL_TLS=false
TEMPORAL_RESULT_TIMEOUT_SECONDS=180

The redirect URI registered with Google/GitHub must exactly match the configured callback URI. Provider login has not been verified without real provider credentials and browser callbacks.

Optional email OTP/password reset

Email-based registration notifications, login alerts, and password-reset OTP require the separate Email OTP extension to be merged into the backend (email_service.py, the matching main.py/saas_store.py changes) and the matching frontend screens to be installed. If that extension is not present in your active working folder, these endpoints are not enabled just because this README mentions them.

When the extension is installed, configure SMTP in the backend .env using your provider's SMTP host, port, username, and an app-specific password. Never commit SMTP credentials. OTP expiry, attempt limits, generic reset-request responses, and session revocation should be verified by running the corresponding tests and using a test inbox.

API overview

The exact endpoints available in a given local copy depend on whether the advanced feature files and optional email extension have been applied. Check /docs on the running backend for the definitive OpenAPI contract.

Core analysis

GET /health

POST /api/analyze — JSON text/document analysis

POST /api/upload_and_analyze — PDF upload and analysis

POST /api/v1/security/temporal-stream — frontend-compatible authenticated analysis; can run synchronously if Temporal is disabled

Authentication and account

POST /api/auth/signup

POST /api/auth/login

GET /api/auth/me

POST /api/auth/logout

GET /api/auth/oauth/providers

GET /api/auth/oauth/{provider}/start

GET /api/auth/oauth/{provider}/callback

GET/PATCH /api/account/settings

GET/POST /api/account/api-keys

DELETE /api/account/api-keys/{key_id}

GET /api/account/sessions

DELETE /api/account/sessions/{session_id}

DELETE /api/account/sessions/revoke-others

GET/POST /api/history

DELETE /api/history and DELETE /api/history/{session_id}

Advanced security

POST /api/v1/security/dependency-scan — exact-version manifest advisory lookup

POST /api/v1/security/codebase-scan — bounded ZIP source/configuration triage and supported dependency checks

POST /api/v1/security/cvss — CVSS v3.1 Base Score from a complete vector

POST /api/v1/security/compliance-assessment — documentation/evidence coverage

POST /api/v1/security/compliance-score — AgentGuard Baseline self-assessment scoring

GET /api/v1/security/workflows/{workflow_id} — inspect real Temporal execution when enabled

GET /api/audit_logs and GET /api/pending_approvals — reviewer-authenticated audit/approval endpoints

POST /api/approve — reviewer approval/rejection; action approval is revalidated by the gateway

Reviewer endpoints require X-Reviewer-Token and should be called server-side, not with a secret embedded in browser JavaScript. User account endpoints require a backend-issued Bearer session or a supported non-revoked AgentGuard API key.

Optional integrations

Google/GitHub OAuth

Create an OAuth application with the provider.

Register the exact callback URL from the backend .env.

Add the provider client ID and secret to the backend .env.

Restart FastAPI and check GET /api/auth/oauth/providers.

Test the full browser redirect and callback flow locally.

Do not expose the OAuth client secret in frontend environment variables.

Temporal

Temporal mode is off by default. To enable it:

Install requirements.

Start a Temporal service and confirm the configured address/namespace.

Set AGENTGUARD_TEMPORAL_ENABLED=true and matching TEMPORAL_* values in the backend .env.

Start python temporal_worker.py in a separate backend terminal.

Start/restart FastAPI and test a real workflow request.

If the service/worker is unavailable, a Temporal request should return an error rather than claim the workflow succeeded. Synchronous analysis does not count as a Temporal workflow.

Security model and limitations

Treat uploaded documents, dependency manifests, source files, and retrieved content as untrusted input.

A successful HTTP response does not itself mean the security decision is ALLOW; inspect security_decision and the returned report status.

The PDF pipeline supports text-based PDFs. Scanned PDFs requiring OCR are not supported by the documented default pipeline.

PDF upload defaults: up to 10 MB, 50 pages, 200,000 extracted characters, and a 4,000-character prompt.

Codebase scanning is bounded source-pattern/configuration triage, not exhaustive semantic SAST, malware scanning, binary/container analysis, or reachability analysis.

A lack of OSV results does not prove a dependency is secure; advisory coverage depends on upstream data and exact version/package parsing.

CVSS endpoint calculates a Base Score from a canonical v3.1 vector; it does not infer missing metrics or calculate Environmental/Temporal metrics.

Compliance outputs describe documented evidence/self-assessment. They do not certify compliance.

Email/export actions in the research-agent demonstration are mock tools; they do not send real customer exports or perform real external actions. Auth-related SMTP notification features only send messages if the separate Email OTP extension is installed and SMTP is configured.

Local SQLite stores and in-memory rate limits are suitable for development, not a multi-worker production deployment. Review authentication, secret rotation, persistence, backups, TLS, logging, rate-limiting, and deployment configuration before production.

Tests and troubleshooting

Symptom

What to check

WinError 10013 on Uvicorn

Try another allowed local port (such as 8010), then update the frontend API URL to that same port. Do not delete Windows excluded-port ranges blindly.

Frontend reports backend unreachable

Confirm Uvicorn is running and that NEXT_PUBLIC_AGENTGUARD_API_BASE_URL matches the exact host/port.

CORS error

Add the exact frontend origin to CORS_ORIGINS, then restart FastAPI.

401 Unauthorized on analysis/settings/history

Log in first and confirm the request sends a valid backend-issued Authorization: Bearer <token> header.

OAuth provider is not listed

Confirm all required provider settings are present, restart the backend, and verify the callback URI is exact.

Temporal returns 503/502/504

Confirm Temporal service, address/namespace/TLS settings, task queue, and temporal_worker.py are running.

npm ERESOLVE with React 19

Check next-themes peer compatibility; update from 0.3.x to a React-19-compatible 0.4.x release rather than forcing an invalid tree.

Email OTP does not arrive

Confirm the Email OTP extension is applied, SMTP is configured, provider credentials are valid, and check backend logs without exposing secrets.

License

No license is specified in this README. Add a license file before publishing the project if you intend to grant others reuse rights.