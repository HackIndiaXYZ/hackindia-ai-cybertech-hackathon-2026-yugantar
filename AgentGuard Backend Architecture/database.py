"""
AgentGuard Database Module
==========================

Responsibilities:
1. SQLite database initialization.
2. Pending human approval persistence.
3. Approval status management.
4. Security audit logging.
5. Canonical action hashes.
6. Audit history retrieval.

Compatible with:
- mcp_gateway.py
- main.py

All database operations use parameterized SQL queries.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterator, List, Optional


# ============================================================
# 1. Database Configuration
# ============================================================

DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent
    / "agentguard_audit.db"
)

DB_PATH = Path(
    os.getenv(
        "AGENTGUARD_DB_PATH",
        str(DEFAULT_DB_PATH),
    )
).expanduser().resolve()

APPROVAL_TTL = timedelta(minutes=10)

MAX_TOOL_ARGS_CHARS = 100_000
MAX_AUDIT_ARGS_CHARS = 20_000
MAX_AUDIT_RESULT_CHARS = 4_000
MAX_AUDIT_REASON_CHARS = 2_000

_DB_INIT_LOCK = RLock()


# ============================================================
# 2. Time Utilities
# ============================================================

def utc_now_iso() -> str:
    """Return the current UTC time in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def _to_utc(value: str) -> datetime:
    """Convert an ISO-8601 timestamp to a UTC-aware datetime."""

    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


# ============================================================
# 3. JSON Serialization
# ============================================================

def _serialize_json(value: Any) -> str:
    """
    Serialize JSON-compatible data deterministically.

    Non-finite floating-point values are rejected.
    Unsupported Python objects are not silently converted.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _deserialize_dict(value: str) -> Dict[str, Any]:
    """Safely decode a JSON object."""

    try:
        decoded = json.loads(value)

        if isinstance(decoded, dict):
            return decoded

    except (TypeError, json.JSONDecodeError):
        pass

    return {}


# ============================================================
# 4. SQLite Connection Management
# ============================================================

@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    """
    Open a SQLite connection with transaction handling.

    Successful operations are committed.
    Failed operations are rolled back.
    Connections are always closed.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    conn = sqlite3.connect(
        str(DB_PATH),
        timeout=10.0,
        isolation_level="DEFERRED",
    )

    conn.row_factory = sqlite3.Row

    try:
        conn.execute(
            "PRAGMA busy_timeout = 10000"
        )

        yield conn

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ============================================================
# 5. Canonical Action Hash
# ============================================================

def compute_canonical_hash(
    tool_name: str,
    tool_args: Dict[str, Any],
) -> str:
    """
    Generate a deterministic SHA-256 hash of a proposed action.

    The hash is intended to detect modifications to the action
    between the approval request and approval processing.

    It is an integrity check, not an authentication mechanism.
    """

    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("A valid tool name is required.")

    if not isinstance(tool_args, dict):
        raise ValueError("Tool arguments must be a dictionary.")

    canonical_json = _serialize_json(
        {
            "tool_name": tool_name,
            "tool_args": tool_args,
        }
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


# ============================================================
# 6. Database Initialization
# ============================================================

def init_db() -> None:
    """
    Create AgentGuard database tables and indexes.

    Safe to call repeatedly.
    Existing tables and their data are preserved.
    """

    with _DB_INIT_LOCK:
        with _connection() as conn:

            conn.execute(
                "PRAGMA journal_mode = WAL"
            )

            # ------------------------------------------------
            # Pending Human Approvals
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_approvals (
                    approval_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    tool_args TEXT NOT NULL,
                    args_hash TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    provenance_source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )

            # ------------------------------------------------
            # Tool-Action Audit History
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    approval_id TEXT,
                    tool_name TEXT NOT NULL,
                    tool_args TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    result TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )

            # ------------------------------------------------
            # Security Evaluation Audit Logs
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    file_name TEXT,
                    user_prompt TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_pending_status_created
                ON pending_approvals(status, created_at)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_security_audit_id
                ON security_audit_logs(id DESC)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_history_timestamp
                ON audit_history(timestamp DESC)
                """
            )


# ============================================================
# 7. Save Pending Human Approval
# ============================================================

def save_pending_approval(
    approval_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    reason: str,
    risk_level: str,
    provenance_source: str,
) -> str:
    """
    Persist an action awaiting human approval.

    Returns the canonical action hash.

    The caller must ensure the action has passed the required
    security checks before creating an approval request.
    """

    if not approval_id or not str(approval_id).strip():
        raise ValueError("Approval ID is required.")

    if not tool_name or not str(tool_name).strip():
        raise ValueError("Tool name is required.")

    if not isinstance(tool_args, dict):
        raise ValueError("Tool arguments must be a dictionary.")

    serialized_args = _serialize_json(tool_args)

    if len(serialized_args) > MAX_TOOL_ARGS_CHARS:
        raise ValueError(
            "Tool arguments exceed the permitted storage limit."
        )

    init_db()

    args_hash = compute_canonical_hash(
        tool_name,
        tool_args,
    )

    created_at = utc_now_iso()

    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO pending_approvals (
                approval_id,
                tool_name,
                tool_args,
                args_hash,
                reason,
                risk_level,
                provenance_source,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
            """,
            (
                str(approval_id)[:100],
                str(tool_name)[:120],
                serialized_args,
                args_hash,
                str(reason)[:MAX_AUDIT_REASON_CHARS],
                str(risk_level)[:30],
                str(provenance_source)[:80],
                created_at,
            ),
        )

    return args_hash


# ============================================================
# 8. Retrieve Pending Approvals
# ============================================================

def get_all_pending_approvals() -> List[Dict[str, Any]]:
    """
    Return active pending approvals.

    Expired approvals are marked EXPIRED and not returned.
    """

    init_db()

    now = datetime.now(timezone.utc)
    output: List[Dict[str, Any]] = []

    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT
                approval_id,
                tool_name,
                tool_args,
                args_hash,
                reason,
                risk_level,
                provenance_source,
                created_at,
                status
            FROM pending_approvals
            WHERE status = 'PENDING'
            ORDER BY created_at ASC
            """
        ).fetchall()

        for row in rows:
            approval_id = row["approval_id"]

            try:
                created_at = _to_utc(
                    row["created_at"]
                )

                expired = (
                    now - created_at
                ) > APPROVAL_TTL

            except (ValueError, TypeError, OverflowError):
                expired = True

            if expired:
                conn.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'EXPIRED'
                    WHERE approval_id = ?
                      AND status = 'PENDING'
                    """,
                    (approval_id,),
                )

                continue

            output.append(
                {
                    "approval_id": approval_id,
                    "tool_name": row["tool_name"],
                    "tool_args": _deserialize_dict(
                        row["tool_args"]
                    ),
                    "args_hash": row["args_hash"],
                    "reason": row["reason"],
                    "risk_level": row["risk_level"],
                    "provenance_source": row["provenance_source"],
                    "created_at": row["created_at"],
                    "status": row["status"],
                }
            )

    return output


# ============================================================
# 9. Atomically Claim an Approval
# ============================================================

def claim_pending_approval(
    approval_id: str,
) -> bool:
    """
    Atomically change PENDING to PROCESSING.

    Prevents two concurrent requests from claiming the same
    approval at the same time.

    Expired or previously consumed approvals cannot be claimed.
    """

    init_db()

    now = datetime.now(timezone.utc)

    with _connection() as conn:

        row = conn.execute(
            """
            SELECT created_at, status
            FROM pending_approvals
            WHERE approval_id = ?
            """,
            (approval_id,),
        ).fetchone()

        if row is None or row["status"] != "PENDING":
            return False

        try:
            created_at = _to_utc(
                row["created_at"]
            )

            if now - created_at > APPROVAL_TTL:

                conn.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'EXPIRED'
                    WHERE approval_id = ?
                      AND status = 'PENDING'
                    """,
                    (approval_id,),
                )

                return False

        except (ValueError, TypeError, OverflowError):

            conn.execute(
                """
                UPDATE pending_approvals
                SET status = 'EXPIRED'
                WHERE approval_id = ?
                  AND status = 'PENDING'
                """,
                (approval_id,),
            )

            return False

        cursor = conn.execute(
            """
            UPDATE pending_approvals
            SET status = 'PROCESSING'
            WHERE approval_id = ?
              AND status = 'PENDING'
            """,
            (approval_id,),
        )

        return cursor.rowcount == 1


# ============================================================
# 10. Update Approval Status
# ============================================================

def update_approval_status(
    approval_id: str,
    status: str,
) -> bool:
    """
    Update the stored status of an approval.

    Supported states:
    PENDING, PROCESSING, APPROVED, REJECTED,
    EXPIRED, FAILED, BLOCKED.
    """

    allowed_statuses = {
        "PENDING",
        "PROCESSING",
        "APPROVED",
        "REJECTED",
        "EXPIRED",
        "FAILED",
        "BLOCKED",
    }

    normalized_status = str(status).upper()

    if normalized_status not in allowed_statuses:
        raise ValueError("Invalid approval status.")

    init_db()

    with _connection() as conn:
        cursor = conn.execute(
            """
            UPDATE pending_approvals
            SET status = ?
            WHERE approval_id = ?
            """,
            (
                normalized_status,
                approval_id,
            ),
        )

        return cursor.rowcount == 1


# ============================================================
# 11. Audit Argument Redaction
# ============================================================

def _redact_for_audit(
    value: Any,
    depth: int = 0,
) -> Any:
    """
    Redact common secret fields before writing audit logs.

    Approval records retain their original arguments because
    changing those arguments would invalidate the action hash.
    """

    if depth >= 8:
        return "[MAX_DEPTH_REACHED]"

    sensitive_names = {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
        "token",
    }

    if isinstance(value, dict):
        result: Dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):

            if index >= 100:
                result["_truncated"] = True
                break

            normalized_key = str(key).lower()

            if any(
                sensitive in normalized_key
                for sensitive in sensitive_names
            ):
                result[str(key)] = "[REDACTED]"

            elif normalized_key in {
                "body",
                "document_text",
                "prompt",
                "content",
            }:
                if item is None:
                    result[str(key)] = None
                else:
                    result[str(key)] = (
                        "[TEXT OMITTED: "
                        f"{len(str(item))} characters]"
                    )

            else:
                result[str(key)] = _redact_for_audit(
                    item,
                    depth + 1,
                )

        return result

    if isinstance(value, (list, tuple)):
        return [
            _redact_for_audit(item, depth + 1)
            for item in value[:100]
        ]

    if isinstance(value, str):
        return value[:2_000]

    if value is None or isinstance(
        value,
        (bool, int, float),
    ):
        return value

    return f"[UNSUPPORTED: {type(value).__name__}]"


# ============================================================
# 12. Record Tool-Action Audit Events
# ============================================================

def log_audit_event(
    approval_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    decision: str,
    result: str,
) -> None:
    """
    Store an audit event for a proposed tool action.

    Sensitive fields and long text values are redacted.
    """

    init_db()

    safe_args = _redact_for_audit(
        tool_args
    )

    serialized_args = _serialize_json(
        safe_args
    )[:MAX_AUDIT_ARGS_CHARS]

    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_history (
                approval_id,
                tool_name,
                tool_args,
                decision,
                result,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(approval_id)[:100],
                str(tool_name)[:120],
                serialized_args,
                str(decision)[:80],
                str(result)[:MAX_AUDIT_RESULT_CHARS],
                utc_now_iso(),
            ),
        )


# ============================================================
# 13. Normalize Audit Verdicts
# ============================================================

def _normalize_verdict(verdict: str) -> str:
    """
    Normalize security verdicts for audit display.

    Unknown values fail closed in the audit representation.
    This function only formats the log; it does not authorize
    or execute any action.
    """

    value = str(verdict).strip().upper()

    if value in {
        "ALLOW",
        "ALLOWED",
        "APPROVED",
    }:
        return "ALLOW"

    if value in {
        "REVIEW",
        "PENDING",
        "PROCESSING",
        "AWAITING_APPROVAL",
    }:
        return "REVIEW"

    # Informational audit events are not security authorizations. Preserve
    # this label separately rather than coercing them to ALLOW or BLOCK.
    if value == "ANALYSIS_ONLY":
        return "ANALYSIS_ONLY"

    return "BLOCK"


# ============================================================
# 14. Record Security Evaluation
# ============================================================

def log_security_evaluation(
    verdict: str,
    reason: str,
    user_prompt: str = "",
    file_name: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Store a bounded security-analysis audit record.

    Prompt text is truncated. Sensitive fields in the prompt
    are not interpreted as authorization to execute actions.
    """

    init_db()

    safe_timestamp = timestamp or utc_now_iso()
    safe_verdict = _normalize_verdict(verdict)

    safe_filename = os.path.basename(
        str(file_name or "N/A")
    )[:255]

    safe_prompt = str(
        user_prompt or ""
    )[:4_000]

    safe_reason = str(
        reason or ""
    )[:MAX_AUDIT_REASON_CHARS]

    with _connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO security_audit_logs (
                timestamp,
                file_name,
                user_prompt,
                verdict,
                reason
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                safe_timestamp,
                safe_filename,
                safe_prompt,
                safe_verdict,
                safe_reason,
            ),
        )

        row_id = cursor.lastrowid

    return {
        "id": row_id,
        "timestamp": safe_timestamp,
        "file_name": safe_filename,
        "user_prompt": safe_prompt,
        "verdict": safe_verdict,
        "reason": safe_reason,
    }


# ============================================================
# 15. Retrieve Security Audit Logs
# ============================================================

def get_security_audit_logs(
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Return recent security evaluations.

    The requested result count is bounded to prevent
    unnecessarily large database reads.
    """

    init_db()

    try:
        bounded_limit = int(limit)
    except (TypeError, ValueError):
        bounded_limit = 50

    bounded_limit = max(
        1,
        min(bounded_limit, 100),
    )

    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                timestamp,
                file_name,
                user_prompt,
                verdict,
                reason
            FROM security_audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


# ============================================================
# 16. Audit Logger Adapter
# ============================================================

class AuditLogger:
    """
    Convenience adapter for FastAPI and gateway modules.

    Kept compatible with the original AgentGuard interface.
    """

    @staticmethod
    def log_evaluation(
        verdict: str,
        reason: str,
        user_prompt: str = "",
        file_name: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:

        return log_security_evaluation(
            verdict=verdict,
            reason=reason,
            user_prompt=user_prompt,
            file_name=file_name,
            timestamp=timestamp,
        )

    @staticmethod
    def get_recent_logs(
        limit: int = 50,
    ) -> List[Dict[str, Any]]:

        return get_security_audit_logs(
            limit=limit
        )


# ============================================================
# 17. Shared Audit Logger
# ============================================================

audit_logger = AuditLogger()


# ============================================================
# 18. Initialize Database
# ============================================================

# Create the local SQLite schema on module import.
# An initialization failure should surface rather than be hidden.

init_db()