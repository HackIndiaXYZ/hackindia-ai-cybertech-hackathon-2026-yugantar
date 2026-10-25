"""
AgentGuard — FastAPI Application
=================================

Main API entry point for the AgentGuard zero-trust
security control plane.

Responsibilities:
- Health checks
- Research-agent analysis
- PDF upload and analysis
- Audit-log retrieval
- Pending human approvals
- Approval/rejection workflow
- Request validation
- CORS configuration
- Rate limiting
- Reviewer authentication
- Fail-closed error handling

All source files are kept directly inside the backend folder.
"""

from __future__ import annotations

import asyncio
import hmac
import hashlib
import logging
import os
import secrets
import time
import re

from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from uuid import uuid4
from typing import Any, Deque, Dict, Optional, Literal
from urllib.parse import quote, urlencode

from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Depends,
    Query,
    Request,
    UploadFile,
    status,
)

from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from pydantic import BaseModel, ConfigDict, Field

from starlette.concurrency import run_in_threadpool
import httpx
from starlette.exceptions import HTTPException as StarletteHTTPException

try:
    from . import saas_store, email_service
    from .security_scanner import scan_text, assess_policy_evidence, scan_dependency_manifest, MAX_MANIFEST_BYTES, assess_compliance_evidence, calculate_cvss_v31, score_agentguard_baseline
    from .codebase_scanner import scan_codebase_archive, MAX_CODEBASE_ARCHIVE_BYTES
except ImportError:
    import saas_store
    import email_service
    from security_scanner import scan_text, assess_policy_evidence, scan_dependency_manifest, MAX_MANIFEST_BYTES, assess_compliance_evidence, calculate_cvss_v31, score_agentguard_baseline
    from codebase_scanner import scan_codebase_archive, MAX_CODEBASE_ARCHIVE_BYTES


# ============================================================
# 1. Environment Configuration
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent

# Load the backend-local environment first.
load_dotenv(
    BACKEND_DIR / ".env",
    override=False,
)

# Also support a project-level .env during final integration.
load_dotenv(
    PROJECT_ROOT / ".env",
    override=False,
)


# ============================================================
# 2. Imports — Support Both Launch Locations
# ============================================================

if __package__:
    from .agent_logic import (
        AnalysisRequest,
        AnalysisResponse,
        LineageNode,
        ResearchAgent,
        SecurityDecisionType,
    )

    from .detectors import PromptInjectionDetector

    from .mcp_gateway import (
        audit_logger,
        mcp_gateway,
        policy_engine,
    )

    from .rag_engine import (
        MAX_PDF_BYTES,
        MAX_PDF_PAGES,
        MAX_TEXT_CHARS,
        RAGPipeline,
    )

else:
    from agent_logic import (
        AnalysisRequest,
        AnalysisResponse,
        LineageNode,
        ResearchAgent,
        SecurityDecisionType,
    )

    from detectors import PromptInjectionDetector

    from mcp_gateway import (
        audit_logger,
        mcp_gateway,
        policy_engine,
    )

    from rag_engine import (
        MAX_PDF_BYTES,
        MAX_PDF_PAGES,
        MAX_TEXT_CHARS,
        RAGPipeline,
    )


# ============================================================
# 3. Logging
# ============================================================

logging.basicConfig(
    level=os.getenv(
        "LOG_LEVEL",
        "INFO",
    ).upper(),
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    ),
)

logger = logging.getLogger(
    "agentguard.api"
)


# ============================================================
# 4. Application Limits
# ============================================================

MAX_UPLOAD_BYTES = MAX_PDF_BYTES

RATE_LIMIT_WINDOW_SECONDS = 60

RATE_LIMIT_MAX_REQUESTS = 30

RATE_LIMIT_STORE: Dict[
    str,
    Deque[float],
] = defaultdict(deque)

_RATE_LIMIT_LOCK = Lock()


# ============================================================
# 5. FastAPI Application
# ============================================================

app = FastAPI(
    title="AgentGuard Security Control Plane API",
    version="1.0.0",
    description=(
        "A zero-trust action control plane for autonomous AI agents. "
        "Evaluates proposed actions, inspects untrusted documents, "
        "and supports human-reviewed security workflows."
    ),
)


# The root URL redirects to the real health endpoint. This avoids a 404 at `/`
# without returning a hard-coded or simulated success payload.
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/health", status_code=307)


# ============================================================
# 6. CORS Configuration
# ============================================================

DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000,"
    "http://127.0.0.1:3000,"
    "http://localhost:3001,"
    "http://127.0.0.1:3001"
)

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        DEFAULT_CORS_ORIGINS,
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Reviewer-Token",
        "X-Request-Id",
    ],
)


# ============================================================
# 7. Shared Services
# ============================================================

agent = ResearchAgent()

rag = RAGPipeline()

# Temporal client is created lazily only when AGENTGUARD_TEMPORAL_ENABLED=true.
_TEMPORAL_CLIENT = None
_TEMPORAL_CLIENT_LOCK = asyncio.Lock()


# ============================================================
# 8. Approval Request Schema
# ============================================================

class ApprovalDecisionRequest(BaseModel):
    """
    Request sent by the frontend's server-side approval proxy.

    The frontend submits:
        approval_id
        expected_hash
        approve

    canonical_args is retained for compatibility with the
    gateway interface, but must match the original action hash.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    approval_id: str = Field(
        min_length=8,
        max_length=100,
    )

    approve: bool

    expected_hash: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
    )

    canonical_args: Optional[Dict] = None


class AuthSignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=190)
    password: str = Field(min_length=8, max_length=256)
    name: str = Field(min_length=1, max_length=100)
    # Role assignment is intentionally not client-controlled.
    role: Optional[str] = Field(default=None, max_length=100)


class AuthLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=190)
    password: str = Field(min_length=1, max_length=256)


class PasswordResetStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=190)


class PasswordResetConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=190)
    otp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    new_password: str = Field(min_length=8, max_length=256)


class PreferencesPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    theme: Optional[str] = None
    reduceMotion: Optional[bool] = None
    autoSplitView: Optional[bool] = None


class ApiKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)


class HistoryCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sessionId: str = Field(min_length=8, max_length=100)
    title: str = Field(default="Security Audit", min_length=1, max_length=255)
    mode: str = Field(default="deep_audit", min_length=1, max_length=32)


class ComplianceAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    evidence_text: str = Field(alias="evidenceText", min_length=1, max_length=200_000)
    framework: str = Field(default="nist_csf_2_0", min_length=1, max_length=64)
    sessionId: Optional[str] = Field(default=None, min_length=8, max_length=100)
    session_id: Optional[str] = Field(default=None, min_length=8, max_length=100)


class CvssVectorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vector: str = Field(min_length=12, max_length=200)
    sessionId: Optional[str] = Field(default=None, min_length=8, max_length=100)


class ComplianceControlStatusInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    controlId: str = Field(min_length=3, max_length=32)
    status: Literal["implemented", "partially_implemented", "not_implemented", "not_assessed", "not_applicable"] = "not_assessed"
    rationale: Optional[str] = Field(default=None, max_length=1000)
    evidenceNote: Optional[str] = Field(default=None, max_length=1000)


class ComplianceScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessments: list[ComplianceControlStatusInput] = Field(default_factory=list, max_length=100)
    sessionId: Optional[str] = Field(default=None, min_length=8, max_length=100)


# ============================================================
# 9. Client Identification
# ============================================================

def _get_client_ip(
    request: Request,
) -> str:
    """
    Read the direct client address.

    Forwarded headers are not trusted because no trusted
    reverse-proxy configuration is assumed.
    """

    if request.client:
        return request.client.host

    return "unknown"


# ============================================================
# 10. Rate Limiting
# ============================================================

def enforce_rate_limit(
    client_ip: str,
) -> None:
    """
    Basic in-process request rate limiter.

    Limit: 30 requests per IP per rolling minute.

    For a multi-worker or production deployment, use a
    shared limiter and an appropriate trusted proxy setup.
    """

    now = time.monotonic()

    with _RATE_LIMIT_LOCK:

        recent = RATE_LIMIT_STORE[
            client_ip
        ]

        while (
            recent
            and now - recent[0]
            >= RATE_LIMIT_WINDOW_SECONDS
        ):
            recent.popleft()

        if len(recent) >= RATE_LIMIT_MAX_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail=(
                    "Rate limit exceeded. "
                    "Try again in a minute."
                ),
                headers={
                    "Retry-After": "60",
                },
            )

        recent.append(now)

        # Prevent the in-memory client map growing indefinitely.
        if len(RATE_LIMIT_STORE) > 5_000:

            expired_keys = [
                key
                for key, values in RATE_LIMIT_STORE.items()
                if (
                    not values
                    or now - values[-1] > 120
                )
            ]

            for key in expired_keys:
                RATE_LIMIT_STORE.pop(
                    key,
                    None,
                )


# ============================================================
# 10A. Authentication Rate Limiting and Current User Dependency
# ============================================================

AUTH_RATE_LIMIT_MAX_REQUESTS = 10
AUTH_RATE_LIMIT_STORE: Dict[str, Deque[float]] = defaultdict(deque)
_AUTH_RATE_LIMIT_LOCK = Lock()

def enforce_auth_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    with _AUTH_RATE_LIMIT_LOCK:
        recent = AUTH_RATE_LIMIT_STORE[client_ip]
        while recent and now - recent[0] >= RATE_LIMIT_WINDOW_SECONDS:
            recent.popleft()
        if len(recent) >= AUTH_RATE_LIMIT_MAX_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail="Authentication rate limit exceeded. Try again in a minute.",
                headers={"Retry-After": "60"},
            )
        recent.append(now)

def require_current_user(
    req: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> Dict:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    # The frontend's middleware cookie is only a route-guard marker, not a credential.
    # Never accept a JavaScript-readable marker cookie as API authentication.
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required. Send a valid Bearer token.")
    try:
        user = saas_store.validate_access_token(token)
        if not user:
            # User-created API keys are a separate credential type; only their
            # SHA-256 digest is stored. Revoked keys are rejected by the store.
            user = saas_store.validate_api_key(token)
    except (RuntimeError, OSError) as exc:
        logger.exception("AgentGuard auth key configuration failed.")
        raise HTTPException(status_code=503, detail="Authentication service is not configured correctly.") from exc
    if not user:
        raise HTTPException(status_code=401, detail="Session is invalid, expired, or revoked. Please sign in again.")
    return user


# ============================================================
# 11. Reviewer Authentication
# ============================================================

def _expected_reviewer_token() -> str:
    """
    Return a configured reviewer token only when it satisfies
    the minimum configuration requirements.
    """

    token = os.getenv(
        "REVIEWER_TOKEN",
        "",
    ).strip()

    invalid_prefixes = (
        "replace_with",
        "change_me",
        "your_",
    )

    if (
        len(token) < 32
        or token.lower().startswith(invalid_prefixes)
    ):
        return ""

    return token


def _require_reviewer_token(
    provided_token: Optional[str],
) -> None:
    """
    Protect approval-management and audit endpoints.

    The frontend should call these endpoints through a
    server-side proxy when a secret reviewer token is required.
    """

    expected = _expected_reviewer_token()

    if not expected:
        raise HTTPException(
            status_code=503,
            detail=(
                "Reviewer authentication is not configured. "
                "Configure REVIEWER_TOKEN in the backend environment."
            ),
        )

    if (
        not provided_token
        or not hmac.compare_digest(
            provided_token,
            expected,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized reviewer token.",
        )


# ============================================================
# 12. Audit Helper
# ============================================================

def _write_audit(
    response: AnalysisResponse,
    prompt: str,
    file_name: str,
) -> None:
    """
    Record the final analysis/security outcome.

    Raw document contents are not copied into the audit reason.
    The database layer bounds the size of stored prompt fields.
    """

    decision = response.security_decision

    if decision is not None:

        verdict = decision.decision.value

        reason = decision.reason

    elif (
        response.status.upper() in {
            "BLOCKED",
            "ERROR",
        }
        or response.mode == "blocked"
    ):

        verdict = "BLOCK"

        reason = response.summary

    elif response.status.upper() in {
        "REVIEW",
        "REVIEW_REQUIRED",
    }:

        verdict = "REVIEW"

        reason = response.summary

    else:

        # Do not label ordinary analysis as an authorization decision.
        # For research retrieval, preserve an actual gateway decision from
        # the per-claim reviews; fail closed in the audit label if mixed.
        gateway_decisions = {
            str(getattr(item, "gateway_decision", "")).strip().upper()
            for item in response.claim_evidence_reviews
        }
        if "BLOCK" in gateway_decisions:
            verdict = "BLOCK"
        elif "REVIEW" in gateway_decisions:
            verdict = "REVIEW"
        elif "ALLOW" in gateway_decisions:
            verdict = "ALLOW"
        else:
            verdict = "ANALYSIS_ONLY"

        reason = (
            response.mode_reason
            or (
                "Analysis completed without authorizing or executing "
                "an external action."
            )
        )

    audit_logger.log_evaluation(
        verdict=verdict,
        reason=reason,
        user_prompt=prompt,
        file_name=file_name,
    )


# ============================================================
# 13. Queue Human Review
# ============================================================

def _queue_review_if_required(
    response: AnalysisResponse,
) -> AnalysisResponse:
    """
    Create a persistent approval record only for REVIEW decisions.

    The action is not executed when the approval record is created.
    """

    decision = response.security_decision

    if (
        decision is None
        or decision.decision
        != SecurityDecisionType.REVIEW
    ):
        return response

    approval = mcp_gateway.queue_for_human_review(
        tool_name=decision.tool_name,
        tool_args=decision.tool_args,
        reason=decision.reason,
        risk_level=decision.risk_level,
        provenance_source=decision.provenance_source,
    )

    response.approval_id = (
        approval.approval_id
    )

    response.approval_hash = (
        approval.args_hash
    )

    # Keep top-level and nested approval metadata consistent.
    if response.security_decision is not None:
        response.security_decision.approval_id = (
            response.approval_id
        )
        response.security_decision.approval_hash = (
            response.approval_hash
        )

    response.summary += (
        " Human review is required before this action "
        f"can proceed. Approval ID: {approval.approval_id}."
    )

    return response


# ============================================================
# 14. HTTP Exception Handler
# ============================================================

@app.exception_handler(
    StarletteHTTPException
)
async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
):
    detail = exc.detail

    message = (
        detail
        if isinstance(detail, str)
        else "The request could not be completed."
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "ERROR",
            "error_type": "HTTPException",
            "message": message,
            "detail": detail,
            "path": request.url.path,
        },
        headers=exc.headers,
    )


# ============================================================
# 15. Request Validation Error Handler
# ============================================================

@app.exception_handler(
    RequestValidationError
)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    """
    Return a consistent validation-error format.

    Invalid field values are not echoed back because they
    could contain sensitive user input.
    """

    safe_errors = [
        {
            "loc": list(item.get("loc", [])),
            "msg": item.get(
                "msg",
                "Invalid value",
            ),
            "type": item.get(
                "type",
                "value_error",
            ),
        }
        for item in exc.errors()
    ]

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "ERROR",
            "error_type": "ValidationError",
            "message": (
                "Invalid request schema or payload parameters."
            ),
            "detail": safe_errors,
            "path": request.url.path,
        },
    )


# ============================================================
# 16. Unhandled Exception Handler
# ============================================================

@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.error(
        "Unhandled exception on %s %s (%s)",
        request.method,
        request.url.path,
        type(exc).__name__,
        exc_info=True,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "ERROR",
            "error_type": "InternalServerError",
            "message": (
                "AgentGuard encountered an internal error. "
                "Check the server log for details."
            ),
            "path": request.url.path,
        },
    )


# ============================================================
# 17. Health Check
# ============================================================

@app.get(
    "/health",
    summary="Health Check",
)
async def health_check():
    """
    Health endpoint used by Ayush's frontend.

    This endpoint does not expose secret values.
    """

    policy_ready = True

    try:
        policy_engine.load_policy()

    except Exception:
        policy_ready = False

        logger.warning(
            "AgentGuard policy is not ready.",
        )

    payload = {
        # A broken policy is not reported as healthy. Optional LLM and
        # reviewer auth are reported separately because text-only analysis
        # can run without them, while reviewer endpoints cannot.
        "status": "ok" if policy_ready else "degraded",
        "service": "AgentGuard Security Control Plane",
        "version": app.version,
        "policy_ready": policy_ready,
        "reviewer_auth_configured": bool(
            _expected_reviewer_token()
        ),
        "llm_configured": bool(
            os.getenv(
                "GROQ_API_KEY",
                "",
            ).strip()
        ),
    }
    return JSONResponse(
        status_code=(
            status.HTTP_200_OK
            if policy_ready
            else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        content=payload,
    )


# ============================================================
# 18. Analyze Text / Research Request
# ============================================================

@app.post(
    "/api/analyze",
    response_model=AnalysisResponse,
    summary="Analyze text and evaluate proposed actions",
)
def analyze_document(
    request: AnalysisRequest,
    req: Request,
):
    """
    Frontend contract:

    POST /api/analyze

    JSON request:
    {
        "prompt": "...",
        "document_text": "...",
        "scenario_id": "safe_search",
        "force_provenance": null
    }
    """

    enforce_rate_limit(
        _get_client_ip(req)
    )

    try:

        response = agent.analyze_document(
            prompt=request.prompt,
            document_text=request.document_text,
            scenario_id=request.scenario_id,
            force_provenance=request.force_provenance,
        )

        response = _queue_review_if_required(
            response
        )

        _write_audit(
            response=response,
            prompt=request.prompt,
            file_name="direct_input",
        )

        return response

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        logger.exception(
            "Analysis request failed.",
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Document analysis failed. "
                "Check the server log."
            ),
        ) from exc


# ============================================================
# 19. Upload and Analyze PDF
# ============================================================

@app.post(
    "/api/upload_and_analyze",
    response_model=AnalysisResponse,
    summary="Upload and inspect a PDF",
)
async def upload_and_analyze(
    req: Request,
    file: UploadFile = File(...),
    user_prompt: str = Form(
        "Analyze this research paper and extract source-grounded claims."
    ),
):
    """
    Frontend contract:

    POST /api/upload_and_analyze

    Content-Type: multipart/form-data

    Fields:
        file        = actual PDF file
        user_prompt = requested research analysis

    Limits:
        PDF bytes: 10 MB
        Pages:     50
        Text:      200,000 characters
    """

    enforce_rate_limit(
        _get_client_ip(req)
    )

    filename = Path(
        file.filename or "document.pdf"
    ).name[:255]

    if not isinstance(user_prompt, str):
        raise HTTPException(
            status_code=400,
            detail="The user prompt must be text.",
        )

    user_prompt = user_prompt.strip()

    if len(user_prompt) > 4_000:
        raise HTTPException(
            status_code=413,
            detail="The analysis prompt exceeds 4,000 characters.",
        )

    if not user_prompt:
        user_prompt = (
            "Analyze this research paper and extract source-grounded claims."
        )

    buffers: list[bytes] = []

    total_bytes = 0

    try:

        # Stream the uploaded file in bounded chunks.
        while True:

            part = await file.read(
                64 * 1024
            )

            if not part:
                break

            total_bytes += len(part)

            if total_bytes > MAX_UPLOAD_BYTES:

                try:
                    await run_in_threadpool(
                        audit_logger.log_evaluation,
                        verdict="BLOCK",
                        reason=(
                            "PDF upload rejected because it "
                            "exceeded the configured byte limit."
                        ),
                        user_prompt=user_prompt,
                        file_name=filename,
                    )
                except Exception:
                    logger.exception(
                        "Unable to persist upload rejection audit."
                    )

                raise HTTPException(
                    status_code=413,
                    detail=(
                        "PDF size exceeds the "
                        "10 MB upload limit."
                    ),
                )

            buffers.append(part)

    finally:
        await file.close()

    content = b"".join(
        buffers
    )

    # Check the PDF header rather than trusting its filename
    # or the browser's Content-Type.
    if not content.startswith(b"%PDF-"):

        try:
            await run_in_threadpool(
                audit_logger.log_evaluation,
                verdict="BLOCK",
                reason=(
                    "PDF upload rejected because the file "
                    "did not contain a valid PDF header."
                ),
                user_prompt=user_prompt,
                file_name=filename,
            )
        except Exception:
            logger.exception(
                "Unable to persist invalid-upload audit."
            )

        raise HTTPException(
            status_code=400,
            detail="The uploaded file is not a valid PDF.",
        )

    # --------------------------------------------------------
    # Parse PDF
    # --------------------------------------------------------

    try:

        chunks = await run_in_threadpool(
            rag.parse_pdf_bytes,
            content,
            filename=filename,
            max_pages=MAX_PDF_PAGES,
        )

    except ValueError as exc:

        try:
            await run_in_threadpool(
                audit_logger.log_evaluation,
                verdict="BLOCK",
                reason=(
                    "PDF ingestion failed validation: "
                    f"{str(exc)[:500]}"
                ),
                user_prompt=user_prompt,
                file_name=filename,
            )
        except Exception:
            logger.exception(
                "Unable to persist PDF validation audit."
            )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # Persist request-local metadata for the frontend compatibility adapter.
    # Request.state is per request and does not affect the existing API response.
    req.state.agentguard_filename = filename
    req.state.agentguard_pages_analyzed = len({chunk.page_number for chunk in chunks})
    req.state.agentguard_input_kind = "pdf"

    # --------------------------------------------------------
    # Combine extracted text
    # --------------------------------------------------------

    full_text = "\n\n".join(
        chunk.text
        for chunk in chunks
    )
    # Request-local only: enables the front-end adapter to report evidence-based
    # text-pattern findings without persisting the raw PDF body in audit logs.
    req.state.agentguard_extracted_text = full_text

    if len(full_text) > MAX_TEXT_CHARS:
        raise HTTPException(
            status_code=413,
            detail=(
                "Extracted PDF text exceeds the "
                "200,000-character processing limit."
            ),
        )

    if not full_text.strip():

        try:
            await run_in_threadpool(
                audit_logger.log_evaluation,
                verdict="BLOCK",
                reason=(
                    "No selectable text was found in the PDF. "
                    "OCR is not implemented."
                ),
                user_prompt=user_prompt,
                file_name=filename,
            )
        except Exception:
            logger.exception(
                "Unable to persist empty-PDF audit."
            )

        raise HTTPException(
            status_code=422,
            detail=(
                "No selectable text was found in this PDF. "
                "Scanned-image OCR is not implemented yet."
            ),
        )

    # --------------------------------------------------------
    # Inspect the complete PDF before LLM processing
    # --------------------------------------------------------

    detection = PromptInjectionDetector.detect(
        full_text
    )

    if detection.is_injection:

        reason_text = (
            "; ".join(detection.reasons[:5])
            or "Suspicious instruction pattern detected."
        )

        response = AnalysisResponse(
            mode="blocked",
            mode_reason=(
                "Pre-LLM document inspection blocked "
                "potential prompt injection."
            ),
            tool_call_source=None,
            status="BLOCKED",
            extracted_claims=[
                (
                    "[NOT_ENOUGH_EVIDENCE] Claim extraction "
                    "was skipped because the uploaded PDF "
                    "was flagged for security review."
                )
            ],
            summary=(
                "AgentGuard detected prompt-injection indicators "
                "in the uploaded PDF. The document was not passed "
                "to the optional LLM summarizer, and no external "
                "tool was invoked. "
                f"Detection signals: {reason_text}"
            ),
            tool_call_attempted=None,
            tool_execution_result="NO TOOL EXECUTED",
            security_decision=None,
            action_lineage=[
                LineageNode(
                    id="node-upload",
                    type="DOCUMENT",
                    label="1. Uploaded PDF",
                    details=(
                        f"{filename}: {len(full_text)} extracted "
                        "characters; treated as untrusted."
                    ),
                    is_tainted=True,
                ),
                LineageNode(
                    id="node-detector",
                    type="INSTRUCTION",
                    label="2. Prompt-Injection Detector",
                    details=reason_text,
                    is_tainted=True,
                ),
                LineageNode(
                    id="node-block",
                    type="SECURITY_DECISION",
                    label="3. AgentGuard Pre-LLM BLOCK",
                    details=(
                        "No optional LLM summarization or external "
                        "tool execution was permitted for this upload."
                    ),
                    is_tainted=True,
                ),
            ],
        )

        await run_in_threadpool(
            _write_audit,
            response=response,
            prompt=user_prompt,
            file_name=filename,
        )

        return response

    # --------------------------------------------------------
    # Analyze accepted PDF text
    # --------------------------------------------------------

    try:

        response = await run_in_threadpool(
            agent.analyze_document,
            prompt=user_prompt,
            document_text=full_text,
        )

        response = await run_in_threadpool(
            _queue_review_if_required,
            response
        )

        await run_in_threadpool(
            _write_audit,
            response=response,
            prompt=user_prompt,
            file_name=filename,
        )

        return response

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        logger.exception(
            "Uploaded PDF analysis failed.",
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "PDF analysis failed. "
                "Check the server log."
            ),
        ) from exc


# ============================================================
# 20. Frontend Compatibility Adapter (Next.js AgentGuard UI)
# ============================================================

_FRONTEND_MODE_GUIDANCE = {
    "deep_audit": (
        "Provide a thorough, source-grounded security analysis. "
        "Do not invent vulnerabilities, CVEs, line numbers, or severity scores."
    ),
    "quick_scan": (
        "Provide a concise first-pass triage based only on available evidence. "
        "Do not invent vulnerabilities, CVEs, or counts."
    ),
    "policy_check": (
        "Review explicit policy and control statements in the supplied material. "
        "Do not claim formal compliance certification or invent compliance scores."
    ),
}


def _format_frontend_report(
    backend_response: AnalysisResponse,
    mode: str,
    static_scan: Optional[dict] = None,
    policy_evidence: Optional[dict] = None,
) -> str:
    """Render only information actually returned by the AgentGuard engine."""

    data = backend_response.model_dump(mode="json")
    status_value = str(data.get("status") or "UNKNOWN")
    summary = str(data.get("summary") or "No summary was returned by AgentGuard.")

    lines = [
        f"# AgentGuard {mode.replace('_', ' ').title()} Report",
        "",
        f"**Result status:** `{status_value}`",
        "",
        "## Summary",
        summary,
    ]

    if data.get("mode_reason"):
        lines.extend(["", "## Processing Note", str(data["mode_reason"])])

    decision = data.get("security_decision")
    if isinstance(decision, dict):
        lines.extend([
            "",
            "## Tool-Action Security Decision",
            f"- **Decision:** `{decision.get('decision', 'UNKNOWN')}`",
            f"- **Verdict:** `{decision.get('verdict', 'UNSPECIFIED')}`",
            f"- **Tool:** `{decision.get('tool_name', 'unspecified')}`",
            f"- **Reason:** {decision.get('reason') or 'No reason was supplied.'}",
            "",
            "> This decision governs the proposed tool action. It is not a document vulnerability severity score.",
        ])

    claims = data.get("research_claims") or []
    if claims:
        lines.extend(["", "## Extracted Research Claims"])
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            statement = str(claim.get("statement") or "Claim text unavailable.")
            verdict = str(claim.get("verdict") or "NOT_ENOUGH_EVIDENCE")
            lines.append(f"- **{verdict}:** {statement}")
            evidence_text = claim.get("evidence_text")
            if evidence_text:
                lines.append(f"  - Evidence text: {evidence_text}")

    reviews = data.get("claim_evidence_reviews") or []
    if reviews:
        lines.extend(["", "## Preliminary Evidence Review"])
        for review in reviews:
            if not isinstance(review, dict):
                continue
            statement = str(review.get("claim_statement") or "Claim unavailable.")
            verdict = str(review.get("verdict") or "NOT_ENOUGH_EVIDENCE")
            rationale = str(review.get("rationale") or "No rationale was returned.")
            lines.extend([f"### {verdict}", statement, "", rationale])
            for assessment in (review.get("source_assessments") or []):
                if not isinstance(assessment, dict):
                    continue
                title = str(assessment.get("source_title") or "Untitled source")
                url = str(assessment.get("source_url") or "")
                source_verdict = str(assessment.get("assessment") or "NOT_ENOUGH_EVIDENCE")
                lines.append(f"- **Source:** {title} — `{source_verdict}`")
                if url:
                    lines.append(f"  - URL: {url}")
                quote = assessment.get("evidence_quote")
                if quote:
                    validation = "validated" if assessment.get("quote_validated") else "not validated"
                    lines.append(f"  - Evidence quote ({validation}): “{quote}”")

    sources = data.get("research_sources") or []
    if sources:
        lines.extend(["", "## Retrieved Research Sources"])
        for source in sources:
            if not isinstance(source, dict):
                continue
            title = str(source.get("title") or "Untitled source")
            url = str(source.get("url") or "")
            published = source.get("published")
            item = f"- {title}"
            if published:
                item += f" (published: {published})"
            lines.append(item)
            if url:
                lines.append(f"  - URL: {url}")
            if source.get("abstract"):
                abstract = str(source["abstract"])
                if len(abstract) > 1_000:
                    abstract = abstract[:1_000].rstrip() + "… [excerpt truncated]"
                lines.append(f"  - Abstract excerpt: {abstract}")

    lineage = data.get("action_lineage") or []
    if lineage:
        lines.extend(["", "## AgentGuard Processing Lineage"])
        for node in lineage:
            if isinstance(node, dict):
                label = str(node.get("label") or node.get("type") or "Step")
                details = str(node.get("details") or "")
                taint = " — marked untrusted/tainted" if node.get("is_tainted") else ""
                lines.append(f"- **{label}:** {details}{taint}")

    if static_scan is not None:
        lines.extend(["", "## Local Security Triage", ""])
        lines.append(f"Static text-pattern findings: **{static_scan.get('findingCount', 0)}**. These are heuristic matches for human validation, not confirmed exploitable vulnerabilities.")
        for finding in static_scan.get("findings", []):
            lines.extend([
                "",
                f"### {finding.get('severity', 'Unrated')}: {finding.get('title', 'Security signal')}",
                f"- Rule: `{finding.get('ruleId', 'unknown')}` | CWE: `{finding.get('cwe', 'not mapped')}` | extracted-text line: {finding.get('textLine', 'n/a')}",
                f"- Redacted evidence: `{finding.get('evidence', '')}`",
                f"- Remediation: {finding.get('remediation', 'Review in context.')}",
            ])
        lines.extend(["", "Scanner scope: heuristic text-pattern triage only; it is not a binary/runtime scanner and does not infer PDF page locations from extracted line numbers."])

    if policy_evidence is not None:
        lines.extend(["", "## Policy Evidence Signals", "", f"Mentioned control topics: {policy_evidence.get('observedCount', 0)} of {policy_evidence.get('controlCount', 0)}. This is not a compliance score."])
        for control in policy_evidence.get("controls", []):
            status_text = "Mention found" if control.get("status") == "evidence_mention_found" else "Not found in supplied text"
            lines.append(f"- **{control.get('label', control.get('controlId'))}:** {status_text}")
            if control.get("excerpt"):
                lines.append(f"  - Evidence excerpt: `{control['excerpt']}`")
        lines.extend(["", policy_evidence.get("disclaimer", "Mentions are not proof of implementation.")])

    lines.extend([
        "",
        "## Scope and Metrics",
        "The existing AgentGuard engine evaluates untrusted inputs, prompt-injection patterns, research claims, and proposed tool actions where applicable. Local static findings in this report are based only on patterns actually found in supplied text.",
        "Codebase source-pattern triage and exact-version OSV dependency advisory scanning are available as separate authenticated endpoints. CVSS v3.1 scores are calculated only from a valid base vector or an OSV-supplied vector. Compliance reports show documented-evidence coverage, not certification. Temporal execution is claimed only when a real Temporal workflow completed.",
    ])
    return "\n".join(lines)


def _frontend_compatibility_payload(
    backend_response: AnalysisResponse,
    mode: str,
    execution_time_ms: int,
    correlation_id: str,
    req: Request,
    temporal_workflow_id: Optional[str] = None,
) -> dict:
    """Map the existing API response to the Next.js UI's expected shape."""

    duration = f"{execution_time_ms / 1000:.3f}s"
    pages = int(getattr(req.state, "agentguard_pages_analyzed", 0) or 0)
    kind = getattr(req.state, "agentguard_input_kind", "text")
    seconds = max(execution_time_ms / 1000, 0.001)
    scan_target = getattr(req.state, "agentguard_extracted_text", None)
    if scan_target is None:
        scan_target = getattr(req.state, "agentguard_scan_text", "")
    source_name = getattr(req.state, "agentguard_filename", None) or "supplied_text"
    static_scan = scan_text(str(scan_target or ""), source_name=source_name)
    policy_evidence = assess_policy_evidence(str(scan_target or "")) if mode == "policy_check" else None

    steps = []
    if kind == "pdf":
        steps.append(f"PDF parser validated and extracted text from {pages} page(s).")
    else:
        steps.append("Text-only request routed through the existing AgentGuard analysis engine.")

    raw_response = backend_response.model_dump(mode="json")
    lineage = raw_response.get("action_lineage") or []
    for node in lineage:
        if isinstance(node, dict):
            label = str(node.get("label") or node.get("type") or "AgentGuard stage")
            if label not in steps:
                steps.append(label)
    steps.append("Structured report built from the actual AgentGuard response.")

    evidence = {
        "summary": (
            f"AgentGuard returned {backend_response.status} in {duration}; "
            + (f"{pages} PDF page(s) parsed." if kind == "pdf" else "text-only input; no PDF pages parsed.")
        ),
        "duration": duration,
        "pagesAnalyzed": pages,
        "steps": steps,
        "detectedVulnerabilities": static_scan["findingCount"],
        "detectedFindings": static_scan["findingCount"],
        "findingMethod": "heuristic text-pattern triage",
    }
    if static_scan.get("riskLevel"):
        evidence["riskLevel"] = static_scan["riskLevel"]
    if pages > 0:
        evidence["scanSpeed"] = f"{pages / seconds:.2f} pages/sec"

    telemetry = {
        "executionTime": duration,
        "pagesParsed": pages,
        "findingCount": static_scan["findingCount"],
    }
    if static_scan.get("riskLevel"):
        telemetry["severity"] = static_scan["riskLevel"]

    capabilities = {
        "pdf_prompt_injection_detection": kind == "pdf",
        "research_claim_review": bool(raw_response.get("claim_evidence_reviews")),
        "tool_action_policy_decision": bool(raw_response.get("security_decision")),
        "static_text_pattern_scan": True,
        "policy_evidence_signals": mode == "policy_check",
        "dependency_advisory_scan": True,
        "codebase_archive_scan": True,
        "cve_database_scan": False,  # True only in an actual codebase-scan response.
        "cvss_v31_base_score": True,
        "compliance_evidence_coverage": True,
        "formal_compliance_certification": False,
        "temporal_workflow_execution": bool(temporal_workflow_id),
    }

    return {
        "content": _format_frontend_report(backend_response, mode, static_scan, policy_evidence),
        "evidence": evidence,
        "telemetry": telemetry,
        "securityFindings": static_scan["findings"],
        "staticScan": static_scan,
        "policyEvidence": policy_evidence,
        # Only return a real Temporal workflow ID when a workflow actually ran.
        "temporalWorkflowId": temporal_workflow_id or correlation_id,
        "correlationId": correlation_id,
        "workflowExecution": ({"engine": "Temporal", "status": "COMPLETED", "workflowId": temporal_workflow_id} if temporal_workflow_id else {"engine": "synchronous", "status": "COMPLETED", "workflowId": None}),
        "executionTimeMs": execution_time_ms,
        "analysisMode": mode,
        "capabilities": capabilities,
        "agentguard": raw_response,
    }


def _temporal_enabled() -> bool:
    return os.getenv("AGENTGUARD_TEMPORAL_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


async def _get_temporal_client():
    """Return a lazily initialized Temporal client; never fake a running workflow."""
    global _TEMPORAL_CLIENT
    if _TEMPORAL_CLIENT is not None:
        return _TEMPORAL_CLIENT
    async with _TEMPORAL_CLIENT_LOCK:
        if _TEMPORAL_CLIENT is not None:
            return _TEMPORAL_CLIENT
        try:
            from temporalio.client import Client
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="Temporal mode is enabled but the temporalio SDK is not installed. Install backend requirements first.") from exc
        address = os.getenv("TEMPORAL_ADDRESS", "127.0.0.1:7233").strip() or "127.0.0.1:7233"
        namespace = os.getenv("TEMPORAL_NAMESPACE", "default").strip() or "default"
        api_key = os.getenv("TEMPORAL_API_KEY", "").strip()
        tls_enabled = os.getenv("TEMPORAL_TLS", "true" if api_key else "false").strip().lower() in {"1", "true", "yes", "on"}
        options: Dict[str, Any] = {"namespace": namespace}
        if api_key:
            options["api_key"] = api_key
        if tls_enabled:
            options["tls"] = True
        try:
            _TEMPORAL_CLIENT = await Client.connect(address, **options)
        except Exception as exc:
            logger.warning("Could not connect to Temporal at %s (%s).", address, type(exc).__name__)
            raise HTTPException(status_code=503, detail="Temporal service is unavailable. Verify TEMPORAL_ADDRESS, namespace/TLS settings, and start the Temporal service before enabling Temporal mode.") from exc
    return _TEMPORAL_CLIENT


async def _run_temporal_analysis(payload: Dict[str, Any]) -> tuple[AnalysisResponse, str]:
    client = await _get_temporal_client()
    from temporal_workflows import AgentGuardAnalysisWorkflow
    workflow_id = "agentguard-analysis-" + uuid4().hex
    task_queue = os.getenv("TEMPORAL_TASK_QUEUE", "agentguard-analysis").strip() or "agentguard-analysis"
    try:
        handle = await client.start_workflow(
            AgentGuardAnalysisWorkflow.run,
            payload,
            id=workflow_id,
            task_queue=task_queue,
        )
        timeout_seconds = max(15, min(int(os.getenv("TEMPORAL_RESULT_TIMEOUT_SECONDS", "180")), 600))
        result = await asyncio.wait_for(handle.result(), timeout=timeout_seconds)
        return AnalysisResponse.model_validate(result), workflow_id
    except asyncio.TimeoutError as exc:
        logger.warning("Temporal workflow %s did not finish within %s seconds.", workflow_id, timeout_seconds)
        raise HTTPException(status_code=504, detail="Temporal workflow was started but no completed result arrived before the configured timeout. Verify that temporal_worker.py is running on the matching task queue.") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Temporal analysis workflow %s failed.", workflow_id)
        raise HTTPException(status_code=502, detail="Temporal workflow failed. Check the Temporal server and worker logs; no synchronous fallback was run.") from exc


async def _extract_pdf_text_for_temporal(req: Request, file: UploadFile) -> str:
    filename = Path(file.filename or "document.pdf").name[:255]
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="PDF size exceeds the 10 MB upload limit.")
    if not content.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="The uploaded file is not a valid PDF.")
    try:
        chunks = await run_in_threadpool(rag.parse_pdf_bytes, content, filename=filename, max_pages=MAX_PDF_PAGES)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    text = "\n\n".join(chunk.text for chunk in chunks)
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=413, detail="Extracted PDF text exceeds the 200,000-character processing limit.")
    if not text.strip():
        raise HTTPException(status_code=422, detail="No selectable text was found in the PDF. Scanned-image OCR is not implemented.")
    req.state.agentguard_filename = filename
    req.state.agentguard_pages_analyzed = len({chunk.page_number for chunk in chunks})
    req.state.agentguard_input_kind = "pdf"
    req.state.agentguard_extracted_text = text
    return text


@app.post(
    "/api/v1/security/temporal-stream",
    summary="Frontend-compatible multipart AgentGuard analysis",
)
async def frontend_temporal_stream(
    req: Request,
    current_user: Dict = Depends(require_current_user),
    prompt: str = Form(default=""),
    file: Optional[UploadFile] = File(default=None),
    analysisMode: Optional[str] = Form(default=None),
    analysis_mode: Optional[str] = Form(default=None),
    sessionId: Optional[str] = Form(default=None),
    session_id: Optional[str] = Form(default=None),
):
    """Compatibility endpoint for the current Next.js frontend.

    Accepts multipart fields `prompt`, optional `file`, and either
    `analysisMode` (current frontend code) or `analysis_mode` (README naming).
    Existing `/api/analyze` and `/api/upload_and_analyze` routes remain intact.
    """

    started = time.perf_counter()
    mode = (analysisMode or analysis_mode or "deep_audit").strip().lower()
    if mode not in _FRONTEND_MODE_GUIDANCE:
        raise HTTPException(
            status_code=422,
            detail="analysisMode must be deep_audit, quick_scan, or policy_check.",
        )

    if not isinstance(prompt, str):
        raise HTTPException(status_code=400, detail="The prompt must be text.")
    prompt = prompt.strip()
    if len(prompt) > 3_500:
        raise HTTPException(status_code=413, detail="The prompt exceeds 3,500 characters.")
    if not prompt and file is None:
        raise HTTPException(
            status_code=422,
            detail="Provide a prompt or attach a PDF file to begin analysis.",
        )

    mode_prefix = f"Requested UI mode: {mode.replace('_', ' ').title()}. "
    guidance = _FRONTEND_MODE_GUIDANCE[mode]
    user_prompt = prompt or "Analyze this PDF for source-grounded security and policy observations."
    combined_prompt = f"{mode_prefix}{guidance}\n\nUser request: {user_prompt}"
    if len(combined_prompt) > 4_000:
        raise HTTPException(
            status_code=413,
            detail="The prompt plus mode instructions exceeds 4,000 characters; shorten the prompt.",
        )

    correlation_id = f"ag-local-{uuid4().hex}"
    temporal_workflow_id: Optional[str] = None
    try:
        if _temporal_enabled():
            document_text = await _extract_pdf_text_for_temporal(req, file) if file is not None else ""
            if file is None:
                req.state.agentguard_input_kind = "text"
                req.state.agentguard_pages_analyzed = 0
                req.state.agentguard_scan_text = prompt
            temporal_payload = {
                "prompt": combined_prompt,
                "document_text": document_text,
                "source_name": Path(file.filename or "document.pdf").name[:255] if file is not None else "direct_input",
                "analysis_mode": mode,
                "user_id": current_user["user_id"],
            }
            backend_response, temporal_workflow_id = await _run_temporal_analysis(temporal_payload)
        elif file is not None:
            # Preserve the mature synchronous ingestion, injection checks,
            # policy gateway, reviewer queue, and audit logging when Temporal is disabled.
            backend_response = await upload_and_analyze(req=req, file=file, user_prompt=combined_prompt)
        else:
            req.state.agentguard_input_kind = "text"
            req.state.agentguard_pages_analyzed = 0
            req.state.agentguard_scan_text = prompt
            backend_response = analyze_document(request=AnalysisRequest(prompt=combined_prompt), req=req)
    except HTTPException:
        raise

    elapsed_ms = max(1, round((time.perf_counter() - started) * 1000))
    payload = _frontend_compatibility_payload(
        backend_response=backend_response,
        mode=mode,
        execution_time_ms=elapsed_ms,
        correlation_id=correlation_id,
        req=req,
        temporal_workflow_id=temporal_workflow_id,
    )
    try:
        history_record = saas_store.save_history_analysis(
            user_id=current_user["user_id"],
            client_session_id=sessionId or session_id,
            mode=mode,
            prompt=prompt,
            filename=(file.filename if file is not None else None),
            content=payload["content"],
            evidence=payload["evidence"],
            telemetry=payload["telemetry"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    payload["sessionId"] = history_record["sessionId"]
    payload["history"] = {
        "sessionId": history_record["sessionId"],
        "title": history_record["title"],
        "createdAt": history_record["createdAt"],
        "updatedAt": history_record["updatedAt"],
    }
    return payload


@app.post(
    "/api/v1/security/dependency-scan",
    summary="Query OSV advisories for exact dependency versions",
)
async def dependency_security_scan(
    req: Request,
    file: UploadFile = File(...),
    sessionId: Optional[str] = Form(default=None),
    session_id: Optional[str] = Form(default=None),
    current_user: Dict = Depends(require_current_user),
):
    """Scan an exact-version requirements/npm lock manifest using OSV.dev.

    Supported files: pinned requirements.txt, exact-version package.json,
    package-lock.json, and npm-shrinkwrap.json. A provider/network failure returns
    UNAVAILABLE, never a fake clean result. The uploaded manifest is not persisted.
    """
    started = time.perf_counter()
    enforce_rate_limit(_get_client_ip(req))
    filename = Path(file.filename or "").name
    try:
        raw = await file.read(MAX_MANIFEST_BYTES + 1)
    finally:
        await file.close()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise HTTPException(status_code=413, detail="Dependency manifest exceeds the 2 MB upload limit.")
    if not filename:
        raise HTTPException(status_code=422, detail="A manifest filename is required.")
    try:
        report = await scan_dependency_manifest(filename, raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["requestId"] = "ag-scan-" + uuid4().hex
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    packages = report.get("scannedPackages") if isinstance(report.get("scannedPackages"), list) else []
    lines = [
        "# Dependency Advisory Scan",
        "",
        f"**Status:** `{report.get('status', 'UNKNOWN')}`",
        f"**Source:** {report.get('source', 'OSV.dev exact-version lookup')} ",
        f"**Packages checked:** {len(packages)}",
        f"**Advisories returned:** {len(findings)}",
        "",
        "This is a dependency advisory lookup, not a general source-code scanner. A result with no returned advisories does not prove that a dependency is secure.",
    ]
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("summary") or finding.get("advisoryId") or "OSV advisory")
        lines.extend([
            "",
            f"## {title[:300]}",
            f"- Package: `{finding.get('package', 'unknown')}@{finding.get('installedVersion', 'unknown')}` ({finding.get('ecosystem', 'unknown')})",
            f"- Advisory: `{finding.get('advisoryId', 'unknown')}`",
        ])
        cves = finding.get("cveIds") or []
        if cves:
            lines.append(f"- CVE aliases: {', '.join(str(x) for x in cves[:12])}")
        if finding.get("cvssV3BaseScore") is not None:
            lines.append(f"- CVSS v3 base score: {finding['cvssV3BaseScore']} (derived from OSV's vector)")
        for ref in (finding.get("references") or [])[:5]:
            if isinstance(ref, str) and ref.startswith(("https://", "http://")):
                lines.append(f"- Reference: {ref}")
    if report.get("error"):
        lines.extend(["", f"**Provider note:** {report['error']}"])
    if report.get("skipped"):
        lines.extend(["", "## Skipped manifest entries"])
        for item in report["skipped"][:30]:
            if isinstance(item, dict):
                lines.append(f"- Line {item.get('line', '?')}: {item.get('reason', 'Entry skipped.')}")
    if report.get("limitations"):
        lines.extend(["", "## Limitations"])
        lines.extend(f"- {item}" for item in report["limitations"] if isinstance(item, str))

    elapsed_ms = max(1, round((time.perf_counter() - started) * 1000))
    try:
        history_record = saas_store.save_history_analysis(
            user_id=current_user["user_id"],
            client_session_id=sessionId or session_id,
            mode="quick_scan",
            prompt=f"Dependency manifest advisory lookup: {filename}",
            filename=filename,
            content="\n".join(lines),
            evidence={
                "summary": f"OSV.dev returned {len(findings)} advisory finding(s) for {len(packages)} exact-version package(s). Status: {report.get('status', 'UNKNOWN')}.",
                "duration": f"{elapsed_ms / 1000:.3f}s",
                "pagesAnalyzed": 0,
                "detectedFindings": len(findings),
                "findingMethod": "OSV.dev exact-version advisory lookup",
            },
            telemetry={"executionTime": f"{elapsed_ms / 1000:.3f}s", "pagesParsed": 0, "findingCount": len(findings)},
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["history"] = history_record
    report["sessionId"] = history_record["sessionId"]
    report["reportMarkdown"] = "\n".join(lines)
    return report


@app.post("/api/v1/security/codebase-scan", summary="Scan a codebase ZIP for source-pattern signals and dependency advisories")
async def codebase_security_scan(
    req: Request,
    file: UploadFile = File(...),
    sessionId: Optional[str] = Form(default=None),
    session_id: Optional[str] = Form(default=None),
    current_user: Dict = Depends(require_current_user),
):
    started = time.perf_counter()
    enforce_rate_limit(_get_client_ip(req))
    filename = Path(file.filename or "codebase.zip").name
    try:
        raw = await file.read(MAX_CODEBASE_ARCHIVE_BYTES + 1)
    finally:
        await file.close()
    if len(raw) > MAX_CODEBASE_ARCHIVE_BYTES:
        raise HTTPException(status_code=413, detail="Codebase ZIP exceeds the 25 MB upload limit.")
    try:
        report = await scan_codebase_archive(filename, raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["requestId"] = "ag-codebase-" + uuid4().hex
    source_findings = report.get("sourceCodeFindings", []) if isinstance(report.get("sourceCodeFindings"), list) else []
    dependency_findings = report.get("dependencyFindings", []) if isinstance(report.get("dependencyFindings"), list) else []
    lines = [
        "# AgentGuard Codebase Security Scan", "",
        f"**Overall status:** `{report.get('status', 'UNKNOWN')}`",
        f"**Archive entries:** {report.get('archiveEntries', 0)}",
        f"**Source/config files scanned:** {report.get('sourceFilesScanned', 0)}",
        f"**Dependency manifests:** {report.get('manifestCount', 0)}",
        f"**Exact-version packages queried:** {report.get('packagesQueried', 0)}",
        f"**Heuristic source signals:** {len(source_findings)}",
        f"**OSV dependency advisories:** {len(dependency_findings)}", "",
        "This scan inspects supported source/config text and queries OSV.dev for exact dependency versions. It is not a semantic SAST, malware/runtime scanner, reachability analysis, or certification.",
    ]
    for finding in dependency_findings[:200]:
        lines.extend(["", f"## Dependency advisory: {str(finding.get('summary') or finding.get('advisoryId') or 'OSV advisory')[:200]}",
                      f"- Package: `{finding.get('package')}@{finding.get('installedVersion')}` ({finding.get('ecosystem')})",
                      f"- Advisory: `{finding.get('advisoryId')}`",
                      f"- CVE aliases: {', '.join(finding.get('cveIds') or []) or 'None supplied by OSV'}",
                      f"- CVSS v3.1 base score: {finding.get('cvssV3BaseScore') if finding.get('cvssV3BaseScore') is not None else 'No valid CVSS v3.1 vector supplied'}",
                      f"- Severity: {finding.get('cvssSeverity') or 'Unscored'}"])
        for reference in (finding.get("references") or [])[:3]:
            if isinstance(reference, str) and reference.startswith("https://"):
                lines.append(f"- Reference: {reference}")
    for finding in source_findings[:100]:
        lines.extend(["", f"## Source signal: {finding.get('title', finding.get('ruleId'))}",
                      f"- File: `{finding.get('sourcePath')}` line {finding.get('textLine')}",
                      f"- Heuristic severity: {finding.get('severity')}; CWE: {finding.get('cwe')}",
                      f"- Redacted evidence: `{finding.get('evidence', '')}`",
                      f"- Remediation: {finding.get('remediation', 'Review manually.')}"])
    lines.extend(["", "## Limitations", *[f"- {item}" for item in report.get("limitations", [])]])
    elapsed_ms = max(1, round((time.perf_counter() - started) * 1000))
    try:
        history = saas_store.save_history_analysis(
            user_id=current_user["user_id"], client_session_id=sessionId or session_id, mode="quick_scan",
            prompt=f"Codebase scan: {filename}", filename=filename, content="\n".join(lines),
            evidence={"summary": f"Codebase scan {report.get('status')}: {report.get('findingCount', 0)} combined findings.",
                      "duration": f"{elapsed_ms / 1000:.3f}s", "pagesAnalyzed": 0,
                      "detectedFindings": report.get("findingCount", 0), "findingMethod": "Source heuristics + OSV exact-version advisories"},
            telemetry={"executionTime": f"{elapsed_ms / 1000:.3f}s", "pagesParsed": 0, "findingCount": report.get("findingCount", 0)},
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["reportMarkdown"] = "\n".join(lines)
    report["history"] = history
    report["sessionId"] = history["sessionId"]
    report["executionTimeMs"] = elapsed_ms
    return report


@app.post("/api/v1/security/compliance-assessment", summary="Assess structured control evidence in supplied text")
def compliance_evidence_assessment(
    body: ComplianceAssessmentRequest,
    current_user: Dict = Depends(require_current_user),
):
    try:
        report = assess_compliance_evidence(body.evidence_text, body.framework)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["requestId"] = "ag-compliance-" + uuid4().hex
    lines = ["# AgentGuard Control Evidence Assessment", "", f"**Framework:** {report['framework']}",
             f"**Documented evidence coverage:** {report['evidenceCoveragePercent']}%", 
             f"**Evidence mentions:** {report['evidenceMentionedCount']}/{report['controlCount']}",
             f"**Explicit gaps detected:** {report['explicitGapCount']}",
             f"**Not evidenced:** {report['notEvidencedCount']}", "",
             "This is an evidence-coverage metric, not a formal compliance score, audit opinion, legal attestation, or certification."]
    for control in report["controls"]:
        lines.extend(["", f"## {control['controlId']} — {control['label']}", f"- Function: {control['function']}", f"- Status: {control['status']}"])
        if control.get("evidenceExcerpt"):
            lines.append(f"- Evidence excerpt: `{control['evidenceExcerpt']}`")
    lines.extend(["", "## Limitations", *[f"- {item}" for item in report["limitations"]]])
    try:
        history = saas_store.save_history_analysis(
            user_id=current_user["user_id"], client_session_id=body.sessionId or body.session_id, mode="policy_check",
            prompt=f"Control evidence assessment: {report['frameworkId']}", filename=None, content="\n".join(lines),
            evidence={"summary": f"Documented evidence coverage {report['evidenceCoveragePercent']}%; explicit gaps={report['explicitGapCount']}.",
                      "duration": "deterministic", "pagesAnalyzed": 0, "detectedFindings": report['explicitGapCount'], "findingMethod": "structured keyword-context evidence checklist"},
            telemetry={"executionTime": "deterministic", "pagesParsed": 0, "findingCount": report['explicitGapCount']},
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["reportMarkdown"] = "\n".join(lines)
    report["history"] = history
    report["sessionId"] = history["sessionId"]
    return report


@app.post("/api/v1/security/compliance-score", summary="Score an explicit self-assessment against the fixed AgentGuard Baseline v1")
def compliance_baseline_score(
    body: ComplianceScoreRequest,
    current_user: Dict = Depends(require_current_user),
):
    """Return an auditable baseline score; do not imply official certification."""
    raw_assessments = [item.model_dump() for item in body.assessments]
    try:
        report = score_agentguard_baseline(raw_assessments)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["requestId"] = "ag-baseline-" + uuid4().hex
    score_text = "Not scorable" if report["scorePercent"] is None else f"{report['scorePercent']}%"
    lines = [
        "# AgentGuard Baseline v1 — Self-Assessed Implementation Score", "",
        f"**Score:** {score_text}", f"**Assessment band:** {report['scoreBand']}",
        f"**Points:** {report['pointsEarned']} / {report['maximumPoints']}",
        f"**In-scope controls:** {report['inScopeControlCount']} / {report['controlCount']}",
        "", "## Scoring method",
        "Implemented=1.0; partially implemented=0.5; not implemented=0; not assessed=0; N/A excluded only with a rationale. Controls are equally weighted.",
    ]
    for control in report["controls"]:
        points = "excluded (N/A)" if control["excludedFromDenominator"] else str(control["pointsEarned"])
        lines.extend(["", f"## {control['controlId']} — {control['label']}", f"- Status: {control['status']}", f"- Points: {points}"])
        if control.get("rationale"):
            lines.append(f"- N/A rationale: `{control['rationale']}`")
        if control.get("evidenceNote"):
            lines.append(f"- User evidence note: `{control['evidenceNote']}`")
    lines.extend(["", "## Limitations", *[f"- {item}" for item in report["limitations"]]])
    try:
        history = saas_store.save_history_analysis(
            user_id=current_user["user_id"], client_session_id=body.sessionId, mode="policy_check",
            prompt="AgentGuard Baseline v1 self-assessed implementation score", filename=None, content="\n".join(lines),
            evidence={"summary": f"AgentGuard Baseline score={score_text}; this is a user self-assessment.", "duration": "deterministic", "pagesAnalyzed": 0, "detectedFindings": report["statusCounts"].get("not_implemented", 0), "findingMethod": "fixed equal-weight AgentGuard Baseline v1 rubric"},
            telemetry={"executionTime": "deterministic", "pagesParsed": 0, "findingCount": report["statusCounts"].get("not_implemented", 0)},
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["reportMarkdown"] = "\n".join(lines)
    report["history"] = history
    report["sessionId"] = history["sessionId"]
    return report


@app.post("/api/v1/security/cvss", summary="Calculate a CVSS v3.1 base score from a canonical vector")
def cvss_base_score(
    body: CvssVectorRequest,
    current_user: Dict = Depends(require_current_user),
):
    try:
        report = calculate_cvss_v31(body.vector)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["requestId"] = "ag-cvss-" + uuid4().hex
    lines = ["# CVSS v3.1 Base Score", "", f"**Vector:** `{report['vector']}`", f"**Base score:** {report['baseScore']}/10", f"**Severity:** {report['severity']}", "", *[f"- {item}" for item in report["limitations"]]]
    try:
        history = saas_store.save_history_analysis(
            user_id=current_user["user_id"], client_session_id=body.sessionId, mode="quick_scan",
            prompt=f"CVSS v3.1 score for {report['vector']}", filename=None, content="\n".join(lines),
            evidence={"summary": f"CVSS v3.1 base score={report['baseScore']} ({report['severity']}).", "duration": "deterministic", "pagesAnalyzed": 0, "detectedFindings": 1 if report['baseScore'] >= 7 else 0, "findingMethod": "FIRST CVSS v3.1 base-score formula"},
            telemetry={"executionTime": "deterministic", "pagesParsed": 0, "findingCount": 1},
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["reportMarkdown"] = "\n".join(lines)
    report["history"] = history
    return report


@app.get("/api/v1/security/workflows/{workflow_id}", summary="Inspect a Temporal workflow execution")
async def temporal_workflow_status(workflow_id: str, current_user: Dict = Depends(require_current_user)):
    if not _temporal_enabled():
        raise HTTPException(status_code=503, detail="Temporal execution is disabled. Set AGENTGUARD_TEMPORAL_ENABLED=true and configure a Temporal service.")
    if not re.fullmatch(r"agentguard-analysis-[a-f0-9]{32}", workflow_id):
        raise HTTPException(status_code=422, detail="Invalid AgentGuard workflow ID.")
    client = await _get_temporal_client()
    try:
        description = await client.get_workflow_handle(workflow_id).describe()
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Temporal workflow was not found.") from exc
    status_value = getattr(description, "status", None)
    status_name = getattr(status_value, "name", str(status_value or "UNKNOWN"))
    return {"workflowId": workflow_id, "status": status_name, "taskQueue": os.getenv("TEMPORAL_TASK_QUEUE", "agentguard-analysis"), "engine": "Temporal"}


# ============================================================
# 21. Retrieve Security Audit Logs
# ============================================================

@app.get(
    "/api/audit_logs",
    summary="Retrieve recent security audit logs",
)
def get_audit_logs(
    req: Request,
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    x_reviewer_token: Optional[str] = Header(
        default=None,
        alias="X-Reviewer-Token",
    ),
):
    """
    Reviewer-authenticated audit-log endpoint.
    """

    enforce_rate_limit(
        _get_client_ip(req)
    )

    _require_reviewer_token(
        x_reviewer_token
    )

    logs = audit_logger.get_recent_logs(
        limit=limit
    )

    return {
        "status": "SUCCESS",
        "count": len(logs),
        "audit_logs": logs,
    }


# ============================================================
# 22. Retrieve Pending Human Approvals
# ============================================================

@app.get(
    "/api/pending_approvals",
    summary="Retrieve pending human approvals",
)
def get_pending_approvals(
    req: Request,
    x_reviewer_token: Optional[str] = Header(
        default=None,
        alias="X-Reviewer-Token",
    ),
):
    """
    Reviewer-authenticated approval queue.

    Returns only approvals that are still pending and have
    not exceeded the configured approval lifetime.
    """

    enforce_rate_limit(
        _get_client_ip(req)
    )

    _require_reviewer_token(
        x_reviewer_token
    )

    approvals = mcp_gateway.get_pending_list()

    return {
        "pending": [
            {
                "approval_id": item.approval_id,
                "tool_name": item.tool_name,
                "tool_args": item.tool_args,
                "args_hash": item.args_hash,
                "reason": item.reason,
                "risk_level": item.risk_level.value,
                "provenance_source": item.provenance_source,
                "created_at": item.created_at,
                "status": item.status,
            }
            for item in approvals
        ]
    }


# ============================================================
# 23. Approve or Reject a Proposed Tool Action
# ============================================================

@app.post(
    "/api/approve",
    summary="Approve or reject a pending tool action",
)
def approve_tool_call(
    request: ApprovalDecisionRequest,
    req: Request,
    x_reviewer_token: Optional[str] = Header(
        default=None,
        alias="X-Reviewer-Token",
    ),
):
    """
    Protected human approval endpoint.

    The frontend should call its own server-side /api/approve
    proxy. That proxy adds X-Reviewer-Token and forwards
    the request to this backend route.
    """

    enforce_rate_limit(
        _get_client_ip(req)
    )

    _require_reviewer_token(
        x_reviewer_token
    )

    try:

        if request.approve:

            # The gateway independently verifies the exact
            # action hash and re-evaluates the policy.
            result = mcp_gateway.approve_tool_call(
                approval_id=request.approval_id,
                expected_hash=request.expected_hash,
                canonical_args=request.canonical_args,
            )

        else:

            result = mcp_gateway.reject_tool_call(
                request.approval_id
            )

        return {
            "status": "SUCCESS",
            "decision": result,
        }

    except KeyError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except HTTPException:
        raise

    except Exception as exc:

        logger.exception(
            "Approval workflow failed.",
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Approval processing failed. "
                "Check the server log."
            ),
        ) from exc


# ============================================================
# 24. Application Authentication, History, Settings, and API Keys
# ============================================================

@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED, summary="Create a real AgentGuard account")
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def auth_signup(body: AuthSignupRequest, req: Request):
    enforce_auth_rate_limit(_get_client_ip(req))
    try:
        user = saas_store.create_account(body.email, body.password, body.name)
        issued = saas_store.issue_session(
            user["id"], _get_client_ip(req), req.headers.get("user-agent", "")
        )
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        logger.exception("Could not initialize account authentication.")
        raise HTTPException(status_code=503, detail="Authentication service is not ready.") from exc

    # Email delivery is best-effort; an SMTP outage must not create a failed
    # registration after the account and session have already been committed.
    notification_status = await asyncio.to_thread(
        email_service.send_registration_notice,
        user["email"], user["name"], _get_client_ip(req),
    )
    return {**issued, "user": user, "email_notification": notification_status}


@app.post("/api/auth/login", summary="Sign in to an AgentGuard account")
async def auth_login(body: AuthLoginRequest, req: Request):
    enforce_auth_rate_limit(_get_client_ip(req))
    try:
        user = saas_store.authenticate_account(body.email, body.password)
        issued = saas_store.issue_session(
            user["id"], _get_client_ip(req), req.headers.get("user-agent", "")
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        logger.exception("Could not initialize account authentication.")
        raise HTTPException(status_code=503, detail="Authentication service is not ready.") from exc

    notification_status = await asyncio.to_thread(
        email_service.send_login_notice,
        user["email"], user["name"], _get_client_ip(req), "email",
    )
    return {**issued, "user": user, "email_notification": notification_status}


@app.get("/api/auth/me", summary="Return the authenticated account")
def auth_me(current_user: Dict = Depends(require_current_user)):
    return {"user": {key: current_user.get(key) for key in ("id", "email", "name", "role", "authProvider", "createdAt")}, "session_id": current_user.get("session_id")}


@app.post("/api/auth/logout", summary="Revoke the current authenticated session")
def auth_logout(current_user: Dict = Depends(require_current_user)):
    revoked = saas_store.revoke_session(current_user.get("session_id"), current_user["user_id"])
    return {"status": "SUCCESS", "revoked": bool(revoked)}


@app.post("/api/auth/password-reset/request", status_code=status.HTTP_202_ACCEPTED, summary="Send a one-time password reset code by email")
@app.post("/api/auth/forgot-password", status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
async def request_password_reset(body: PasswordResetStartRequest, req: Request):
    """Request an email OTP without revealing whether the email has an account."""
    enforce_auth_rate_limit(_get_client_ip(req))
    if not email_service.notifications_enabled():
        # The same response for every email is only meaningful when email
        # delivery is configured; return a configuration error before looking
        # up the account so this does not reveal account existence.
        raise HTTPException(
            status_code=503,
            detail="Password reset email is not configured. Set the SMTP environment variables and enable email notifications.",
        )

    otp = f"{secrets.randbelow(1_000_000):06d}"
    try:
        should_send = saas_store.create_password_reset_challenge(
            body.email, otp, _get_client_ip(req)
        )
    except (RuntimeError, OSError) as exc:
        logger.exception("Could not create a password reset challenge.")
        raise HTTPException(status_code=503, detail="Password reset service is not ready.") from exc

    if should_send:
        sent = await asyncio.to_thread(email_service.send_password_reset_otp, body.email.strip().lower(), otp)
        if not sent:
            saas_store.invalidate_password_reset_challenge(body.email, otp)
            logger.warning("Password reset email could not be delivered.")

    # Same body for existing, unknown, OAuth-only, and email-rate-limited users.
    return {
        "status": "ACCEPTED",
        "message": "If this address belongs to an AgentGuard email/password account, a reset code will be sent. The code is valid for 10 minutes.",
    }


@app.post("/api/auth/password-reset/confirm", summary="Verify a one-time code and reset password")
@app.post("/api/auth/reset-password", include_in_schema=False)
async def confirm_password_reset(body: PasswordResetConfirmRequest):
    try:
        user = saas_store.reset_password_with_otp(body.email, body.otp, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        logger.exception("Could not complete password reset.")
        raise HTTPException(status_code=503, detail="Password reset service is not ready.") from exc
    if user is None:
        raise HTTPException(status_code=400, detail="The code is invalid or expired. Request a new code and try again.")
    notice_status = await asyncio.to_thread(
        email_service.send_password_changed_notice, user["email"], user["name"]
    )
    return {
        "status": "SUCCESS",
        "message": "Your password was changed. All existing sessions have been revoked; please sign in again.",
        "email_notification": notice_status,
    }


def _oauth_provider_config(provider: str) -> Optional[dict]:
    provider = provider.lower()
    if provider == "google":
        client_id = os.getenv("OAUTH_GOOGLE_CLIENT_ID", "").strip()
        client_secret = os.getenv("OAUTH_GOOGLE_CLIENT_SECRET", "").strip()
        redirect_uri = os.getenv("OAUTH_GOOGLE_REDIRECT_URI", "").strip()
        return ({"client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri,
                 "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
                 "token_url": "https://oauth2.googleapis.com/token"}
                if client_id and client_secret and redirect_uri else None)
    if provider == "github":
        client_id = os.getenv("OAUTH_GITHUB_CLIENT_ID", "").strip()
        client_secret = os.getenv("OAUTH_GITHUB_CLIENT_SECRET", "").strip()
        redirect_uri = os.getenv("OAUTH_GITHUB_REDIRECT_URI", "").strip()
        return ({"client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri,
                 "authorize_url": "https://github.com/login/oauth/authorize",
                 "token_url": "https://github.com/login/oauth/access_token"}
                if client_id and client_secret and redirect_uri else None)
    return None


def _oauth_state_signature(provider: str, nonce: str, expires: int) -> str:
    message = f"{provider}|{nonce}|{expires}".encode("utf-8")
    return hmac.new(saas_store._auth_secret(), message, hashlib.sha256).hexdigest()


@app.get("/api/auth/oauth/providers", summary="List configured OAuth providers")
def auth_oauth_providers():
    return {"providers": [provider for provider in ("google", "github") if _oauth_provider_config(provider)]}


@app.get("/api/auth/oauth/{provider}/start", summary="Start configured OAuth login")
def auth_oauth_start(provider: str):
    provider = provider.lower()
    if provider not in {"google", "github"}:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider.")
    config = _oauth_provider_config(provider)
    if not config:
        raise HTTPException(status_code=501, detail=f"{provider.title()} OAuth is unavailable until its client ID, client secret, and callback URL are configured in the backend environment.")
    nonce = secrets.token_urlsafe(24)
    expires = int(time.time()) + 600
    state = f"{provider}.{nonce}.{expires}.{_oauth_state_signature(provider, nonce, expires)}"
    params = {"client_id": config["client_id"], "redirect_uri": config["redirect_uri"], "response_type": "code", "scope": "openid email profile" if provider == "google" else "read:user user:email", "state": state}
    if provider == "google":
        params["prompt"] = "select_account"
    else:
        params["allow_signup"] = "true"
    from fastapi.responses import RedirectResponse as _RedirectResponse
    response = _RedirectResponse(config["authorize_url"] + "?" + urlencode(params), status_code=302)
    response.set_cookie("agentguard_oauth_state", state, httponly=True, secure=os.getenv("AGENTGUARD_COOKIE_SECURE", "false").lower() == "true", samesite="lax", max_age=600, path="/api/auth/oauth")
    return response


@app.get("/api/auth/oauth/{provider}/callback", summary="Complete configured OAuth login")
async def auth_oauth_callback(provider: str, req: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    provider = provider.lower()
    frontend_base = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000").strip().rstrip("/")
    if provider not in {"google", "github"}:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider.")
    if error:
        return RedirectResponse(url=f"{frontend_base}/login?oauth_error={quote(error[:120])}", status_code=303)
    config = _oauth_provider_config(provider)
    if not config:
        raise HTTPException(status_code=501, detail=f"{provider.title()} OAuth is not configured.")
    cookie_state = req.cookies.get("agentguard_oauth_state", "")
    try:
        state_provider, nonce, exp_text, signature = (state or "").split(".", 3)
        exp = int(exp_text)
        expected_signature = _oauth_state_signature(state_provider, nonce, exp)
        state_ok = (state_provider == provider and exp >= int(time.time()) and hmac.compare_digest(expected_signature, signature)
                    and bool(cookie_state) and hmac.compare_digest(cookie_state, state or ""))
    except (ValueError, TypeError):
        state_ok = False
    if not state_ok or not code:
        raise HTTPException(status_code=400, detail="OAuth state is invalid or expired. Restart sign-in.")
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=False) as client:
            token_response = await client.post(config["token_url"], data={"client_id": config["client_id"], "client_secret": config["client_secret"], "code": code, "redirect_uri": config["redirect_uri"], "grant_type": "authorization_code"}, headers={"Accept": "application/json"})
            token_response.raise_for_status()
            token_data = token_response.json()
            access_token = str(token_data.get("access_token") or "")
            if not access_token:
                raise ValueError("OAuth provider returned no access token.")
            if provider == "google":
                user_response = await client.get("https://openidconnect.googleapis.com/v1/userinfo", headers={"Authorization": f"Bearer {access_token}"})
                user_response.raise_for_status()
                profile = user_response.json()
                if not profile.get("email_verified"):
                    raise ValueError("Google did not verify the account email address.")
                subject = str(profile.get("sub") or "")
                email = str(profile.get("email") or "")
                name = str(profile.get("name") or email.split("@", 1)[0])
            else:
                user_response = await client.get("https://api.github.com/user", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AgentGuard"})
                user_response.raise_for_status()
                profile = user_response.json()
                emails_response = await client.get("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AgentGuard"})
                emails_response.raise_for_status()
                email_entry = next((entry for entry in emails_response.json() if entry.get("primary") and entry.get("verified")), None)
                if not email_entry:
                    raise ValueError("GitHub did not return a primary verified email address.")
                subject = str(profile.get("id") or "")
                email = str(email_entry.get("email") or "")
                name = str(profile.get("name") or profile.get("login") or email.split("@", 1)[0])
        existing_account = saas_store.account_exists_by_email(email)
        user = saas_store.create_or_get_oauth_account(provider, subject, email, name)
        issued = saas_store.issue_session(user["id"], _get_client_ip(req), req.headers.get("user-agent", ""))
        if not existing_account:
            await asyncio.to_thread(email_service.send_registration_notice, user["email"], user["name"], _get_client_ip(req))
        await asyncio.to_thread(email_service.send_login_notice, user["email"], user["name"], _get_client_ip(req), provider)
    except FileExistsError:
        return RedirectResponse(url=f"{frontend_base}/login?oauth_error=account_exists", status_code=303)
    except (httpx.HTTPError, ValueError, RuntimeError, OSError, PermissionError) as exc:
        logger.warning("OAuth callback failed for provider %s: %s", provider, type(exc).__name__)
        return RedirectResponse(url=f"{frontend_base}/login?oauth_error=provider_exchange_failed", status_code=303)
    user_payload = __import__("json").dumps(user, separators=(",", ":"))
    redirect_url = f"{frontend_base}/auth/callback#token={quote(issued['access_token'])}&user={quote(user_payload)}"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.delete_cookie("agentguard_oauth_state", path="/api/auth/oauth")
    return response


@app.post("/api/auth/oauth/{provider}", summary="OAuth availability check")
def auth_oauth_not_configured(provider: str):
    provider = provider.lower()
    if provider not in {"google", "github"}:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider.")
    if not _oauth_provider_config(provider):
        raise HTTPException(status_code=501, detail=f"{provider.title()} OAuth is not configured. Add its client ID, secret, and callback URL to the backend environment.")
    raise HTTPException(status_code=405, detail="Use GET /api/auth/oauth/{provider}/start to begin OAuth authorization.")


@app.get("/api/account/settings", summary="Read account preferences")
def account_get_settings(current_user: Dict = Depends(require_current_user)):
    return {"preferences": saas_store.get_preferences(current_user["user_id"])}


@app.patch("/api/account/settings", summary="Update account preferences")
def account_update_settings(body: PreferencesPatchRequest, current_user: Dict = Depends(require_current_user)):
    patch = body.model_dump(exclude_unset=True, exclude_none=True)
    try:
        preferences = saas_store.update_preferences(current_user["user_id"], patch)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"preferences": preferences}


@app.get("/api/account/sessions", summary="List active account sessions")
def account_list_sessions(current_user: Dict = Depends(require_current_user)):
    return {"sessions": saas_store.list_sessions(current_user["user_id"], current_user.get("session_id"))}


@app.delete("/api/account/sessions/revoke-others", summary="Revoke all other account sessions")
def account_revoke_other_sessions(current_user: Dict = Depends(require_current_user)):
    count = saas_store.revoke_other_sessions(current_user["user_id"], current_user.get("session_id"))
    return {"status": "SUCCESS", "revoked_count": count}


@app.delete("/api/account/sessions/{session_id}", summary="Revoke one account session")
def account_revoke_session(session_id: str, current_user: Dict = Depends(require_current_user)):
    if not saas_store.revoke_session(session_id, current_user["user_id"]):
        raise HTTPException(status_code=404, detail="Active session not found.")
    return {"status": "SUCCESS", "revoked": True}


@app.get("/api/account/api-keys", summary="List API key metadata")
def account_list_api_keys(current_user: Dict = Depends(require_current_user)):
    return {"api_keys": saas_store.list_api_keys(current_user["user_id"])}


@app.post("/api/account/api-keys", status_code=status.HTTP_201_CREATED, summary="Create an API key")
def account_create_api_key(body: ApiKeyCreateRequest, current_user: Dict = Depends(require_current_user)):
    try:
        key = saas_store.create_api_key(current_user["user_id"], body.name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # The plaintext secret is returned only once; only its hash is stored.
    return {"api_key": key}


@app.delete("/api/account/api-keys/{key_id}", summary="Revoke an API key")
def account_revoke_api_key(key_id: str, current_user: Dict = Depends(require_current_user)):
    if not saas_store.revoke_api_key(current_user["user_id"], key_id):
        raise HTTPException(status_code=404, detail="Active API key not found.")
    return {"status": "SUCCESS", "revoked": True}


@app.get("/api/history", summary="List the authenticated user's saved audit sessions")
def history_list(
    limit: int = Query(default=30, ge=1, le=100),
    current_user: Dict = Depends(require_current_user),
):
    return {"sessions": saas_store.list_history(current_user["user_id"], limit=limit)}


@app.post("/api/history", status_code=status.HTTP_201_CREATED, summary="Create a metadata-only audit history entry")
def history_create(
    body: HistoryCreateRequest,
    req: Request,
    current_user: Dict = Depends(require_current_user),
):
    """Persist the sidebar entry when a user stages an upload; file bytes are never stored."""
    enforce_rate_limit(_get_client_ip(req))
    try:
        history = saas_store.create_history_session(
            user_id=current_user["user_id"],
            client_session_id=body.sessionId,
            title=body.title,
            mode=body.mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "SUCCESS", "history": history}


@app.delete("/api/history", summary="Clear the authenticated user's audit history")
def history_clear(current_user: Dict = Depends(require_current_user)):
    return {"status": "SUCCESS", "deleted_count": saas_store.clear_history(current_user["user_id"])}


@app.delete("/api/history/{session_id}", summary="Delete one saved audit session")
def history_delete(session_id: str, current_user: Dict = Depends(require_current_user)):
    if not saas_store.delete_history_session(current_user["user_id"], session_id):
        raise HTTPException(status_code=404, detail="Saved audit session not found.")
    return {"status": "SUCCESS", "deleted": True}


# ============================================================
# 25. Local Development Entry Point
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False,
    )