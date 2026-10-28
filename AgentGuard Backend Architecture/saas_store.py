"""Local-first account, session, history, preferences, and API-key store.

This module uses a separate SQLite database from AgentGuard's security-audit
log database. It is designed for local development and a single FastAPI process;
use a managed database/session service before deploying multiple workers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

BACKEND_DIR = Path(__file__).resolve().parent
APP_DB_PATH_ENV = "AGENTGUARD_APP_DB_PATH"
TOKEN_ISSUER = "agentguard-local"
TOKEN_TTL_SECONDS = 60 * 60 * 24
PASSWORD_ITERATIONS = 310_000
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,100}$")
ALLOWED_MODES = {"deep_audit", "quick_scan", "policy_check"}


def _db_path() -> Path:
    raw = os.getenv(APP_DB_PATH_ENV, "").strip()
    path = Path(raw).expanduser() if raw else BACKEND_DIR / "agentguard_app.db"
    if not path.is_absolute():
        path = (BACKEND_DIR / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()), timeout=10, isolation_level="DEFERRED")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS app_users (
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0,
            auth_provider TEXT NOT NULL DEFAULT 'email'
        );
        CREATE TABLE IF NOT EXISTS app_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER,
            ip_address TEXT NOT NULL DEFAULT 'unknown',
            user_agent TEXT NOT NULL DEFAULT '',
            last_active_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_app_sessions_user ON app_sessions(user_id, expires_at);
        CREATE TABLE IF NOT EXISTS app_history (
            user_id TEXT NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
            client_session_id TEXT NOT NULL,
            title TEXT NOT NULL,
            mode TEXT NOT NULL,
            messages_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, client_session_id)
        );
        CREATE INDEX IF NOT EXISTS idx_app_history_updated ON app_history(user_id, updated_at DESC);
        CREATE TABLE IF NOT EXISTS app_preferences (
            user_id TEXT PRIMARY KEY REFERENCES app_users(user_id) ON DELETE CASCADE,
            preferences_json TEXT NOT NULL DEFAULT '{}',
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_api_keys (
            key_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            secret_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            revoked_at INTEGER,
            last_used_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_app_api_keys_user ON app_api_keys(user_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS app_oauth_identities (
            provider TEXT NOT NULL,
            provider_subject TEXT NOT NULL,
            user_id TEXT NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            PRIMARY KEY(provider, provider_subject),
            UNIQUE(provider, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_oauth_identity_user ON app_oauth_identities(user_id);
        CREATE TABLE IF NOT EXISTS app_password_reset_otps (
            request_id TEXT PRIMARY KEY,
            email_digest TEXT NOT NULL,
            user_id TEXT REFERENCES app_users(user_id) ON DELETE CASCADE,
            otp_hash TEXT NOT NULL,
            requested_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            consumed_at INTEGER,
            ip_address TEXT NOT NULL DEFAULT 'unknown'
        );
        CREATE INDEX IF NOT EXISTS idx_password_reset_email_requested
            ON app_password_reset_otps(email_digest, requested_at DESC);
        """
    )
    # Additive migration for databases created before OAuth support.
    user_columns = {row[1] for row in conn.execute("PRAGMA table_info(app_users)").fetchall()}
    if "auth_provider" not in user_columns:
        conn.execute("ALTER TABLE app_users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'email'")
        conn.commit()
    session_columns = {row[1] for row in conn.execute("PRAGMA table_info(app_sessions)").fetchall()}
    if "last_active_at" not in session_columns:
        conn.execute("ALTER TABLE app_sessions ADD COLUMN last_active_at INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE app_sessions SET last_active_at=created_at WHERE last_active_at=0")
        conn.commit()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _auth_secret() -> bytes:
    configured = os.getenv("AGENTGUARD_AUTH_SECRET", "").strip()
    if configured:
        if len(configured.encode("utf-8")) < 32:
            raise RuntimeError("AGENTGUARD_AUTH_SECRET must contain at least 32 characters.")
        return configured.encode("utf-8")

    # Local development fallback: generated once and stored separately from source.
    # The key is never included in source archives or .env.example.
    secret_path = BACKEND_DIR / ".agentguard_auth_secret"
    try:
        if secret_path.exists():
            existing = secret_path.read_bytes()
            if len(existing) >= 32:
                return existing
    except OSError:
        pass

    new_secret = secrets.token_bytes(64)
    try:
        with open(secret_path, "xb") as handle:
            handle.write(new_secret)
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
        return new_secret
    except FileExistsError:
        existing = secret_path.read_bytes()
        if len(existing) >= 32:
            return existing
        raise RuntimeError("The local AgentGuard auth secret file is invalid.")
    except OSError as exc:
        raise RuntimeError(
            "Could not create the local auth signing key. Set AGENTGUARD_AUTH_SECRET "
            "to a random value of at least 32 characters."
        ) from exc


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        _b64url(salt),
        _b64url(digest),
    )


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iteration_text, salt_text, digest_text = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        if not 100_000 <= iterations <= 2_000_000:
            return False
        salt = _b64url_decode(salt_text)
        expected = _b64url_decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _public_user(row: sqlite3.Row | Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["user_id"],
        "email": row["email"],
        "name": row["display_name"],
        "role": row["role"],
        "authProvider": (row["auth_provider"] if "auth_provider" in row.keys() else "email"),
        "createdAt": int(row["created_at"]),
    }


def create_account(email: str, password: str, name: str) -> Dict[str, Any]:
    clean_email = (email or "").strip().lower()
    clean_name = " ".join((name or "").strip().split())
    if not EMAIL_RE.fullmatch(clean_email):
        raise ValueError("Enter a valid email address.")
    if not clean_name or len(clean_name) > 100:
        raise ValueError("Name must contain between 1 and 100 characters.")
    if len(password or "") < 8:
        raise ValueError("Password must be at least 8 characters.")
    if len(password) > 256:
        raise ValueError("Password must not exceed 256 characters.")

    user_id = "usr_" + uuid4().hex
    created_at = int(time.time())
    password_hash = _hash_password(password)
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO app_users(user_id,email,display_name,role,password_hash,created_at) VALUES(?,?,?,?,?,?)",
            (user_id, clean_email, clean_name, "Security Operations Analyst", password_hash, created_at),
        )
        conn.execute(
            "INSERT INTO app_preferences(user_id,preferences_json,updated_at) VALUES(?,?,?)",
            (user_id, json.dumps({"theme": "system"}), created_at),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM app_users WHERE user_id=?", (user_id,)).fetchone()
        return _public_user(row)
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise FileExistsError("An account with this email already exists.") from exc
    finally:
        conn.close()


def create_or_get_oauth_account(provider: str, provider_subject: str, email: str, name: str) -> Dict[str, Any]:
    """Create or retrieve an account tied to a verified OAuth provider identity.

    Existing email/password accounts are never silently linked by matching email;
    that would let a provider with weak/unverified email claims take over an account.
    """
    provider = (provider or "").strip().lower()
    provider_subject = (provider_subject or "").strip()
    clean_email = (email or "").strip().lower()
    clean_name = " ".join((name or "").strip().split())[:100]
    if provider not in {"google", "github"}:
        raise ValueError("Unsupported OAuth provider.")
    if not provider_subject or len(provider_subject) > 255:
        raise ValueError("OAuth provider did not return a valid account subject.")
    if not EMAIL_RE.fullmatch(clean_email):
        raise ValueError("OAuth provider did not return a valid email address.")
    if not clean_name:
        clean_name = clean_email.split("@", 1)[0][:100] or "AgentGuard Analyst"

    conn = _connect()
    try:
        identity = conn.execute(
            "SELECT user_id FROM app_oauth_identities WHERE provider=? AND provider_subject=?",
            (provider, provider_subject),
        ).fetchone()
        if identity:
            row = conn.execute("SELECT * FROM app_users WHERE user_id=?", (identity["user_id"],)).fetchone()
            if row is None or row["disabled"]:
                raise PermissionError("This OAuth account is disabled.")
            return _public_user(row)

        existing = conn.execute("SELECT user_id FROM app_users WHERE email=?", (clean_email,)).fetchone()
        if existing:
            raise FileExistsError("An account with this email already exists. Sign in with that account before linking an identity.")

        user_id = "usr_" + uuid4().hex
        now = int(time.time())
        # This sentinel is intentionally not a valid PBKDF2 password hash.
        password_hash = "oauth$" + secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO app_users(user_id,email,display_name,role,password_hash,created_at,auth_provider) VALUES(?,?,?,?,?,?,?)",
            (user_id, clean_email, clean_name, "Security Operations Analyst", password_hash, now, provider),
        )
        conn.execute(
            "INSERT INTO app_oauth_identities(provider,provider_subject,user_id,created_at) VALUES(?,?,?,?)",
            (provider, provider_subject, user_id, now),
        )
        conn.execute(
            "INSERT INTO app_preferences(user_id,preferences_json,updated_at) VALUES(?,?,?)",
            (user_id, json.dumps({"theme": "system"}), now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM app_users WHERE user_id=?", (user_id,)).fetchone()
        return _public_user(row)
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise FileExistsError("This OAuth identity is already linked to another account.") from exc
    finally:
        conn.close()


def authenticate_account(email: str, password: str) -> Dict[str, Any]:
    clean_email = (email or "").strip().lower()
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM app_users WHERE email=?", (clean_email,)).fetchone()
        if row is None:
            # Reduce basic account-enumeration timing differences.
            _verify_password(password or "", _hash_password("constant-time dummy password"))
            raise PermissionError("Invalid email or password.")
        if row["disabled"] or not _verify_password(password or "", row["password_hash"]):
            raise PermissionError("Invalid email or password.")
        return _public_user(row)
    finally:
        conn.close()


def issue_session(user_id: str, ip_address: str = "unknown", user_agent: str = "") -> Dict[str, Any]:
    now = int(time.time())
    session_id = uuid4().hex
    expires_at = now + TOKEN_TTL_SECONDS
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO app_sessions(session_id,user_id,created_at,expires_at,ip_address,user_agent,last_active_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, user_id, now, expires_at, (ip_address or "unknown")[:64], (user_agent or "")[:300], now),
        )
        conn.commit()
    finally:
        conn.close()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": TOKEN_ISSUER,
        "sub": user_id,
        "sid": session_id,
        "iat": now,
        "exp": expires_at,
    }
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = _b64url(hmac.new(_auth_secret(), message, hashlib.sha256).digest())
    token = f"{encoded_header}.{encoded_payload}.{signature}"
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_TTL_SECONDS, "session_id": session_id}


def _decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        if not token or len(token) > 4096:
            return None
        first, second, supplied_signature = token.split(".", 2)
        signed = f"{first}.{second}".encode("ascii")
        expected_signature = _b64url(hmac.new(_auth_secret(), signed, hashlib.sha256).digest())
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return None
        header = json.loads(_b64url_decode(first))
        claims = json.loads(_b64url_decode(second))
        if header.get("alg") != "HS256" or claims.get("iss") != TOKEN_ISSUER:
            return None
        if int(claims.get("exp", 0)) <= int(time.time()):
            return None
        if not claims.get("sub") or not claims.get("sid"):
            return None
        return claims
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, RuntimeError, OSError):
        return None


def validate_access_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    if token.startswith("ag_sec_live_"):
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT u.*, k.key_id FROM app_api_keys k JOIN app_users u ON u.user_id=k.user_id "
                "WHERE k.secret_hash=? AND k.revoked_at IS NULL AND u.disabled=0",
                (digest,),
            ).fetchone()
            if not row:
                return None
            conn.execute("UPDATE app_api_keys SET last_used_at=? WHERE key_id=?", (int(time.time()), row["key_id"]))
            conn.commit()
            user = _public_user(row)
            user.update({"user_id": user["id"], "session_id": None, "auth_kind": "api_key"})
            return user
        finally:
            conn.close()

    claims = _decode_token(token)
    if not claims:
        return None
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT u.*, s.session_id FROM app_sessions s JOIN app_users u ON u.user_id=s.user_id "
            "WHERE s.session_id=? AND s.user_id=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.disabled=0",
            (claims["sid"], claims["sub"], int(time.time())),
        ).fetchone()
        if not row:
            return None
        now = int(time.time())
        conn.execute("UPDATE app_sessions SET last_active_at=? WHERE session_id=?", (now, row["session_id"]))
        conn.commit()
        user = _public_user(row)
        user.update({"user_id": user["id"], "session_id": row["session_id"], "auth_kind": "session"})
        return user
    finally:
        conn.close()


def revoke_session(session_id: Optional[str], user_id: str) -> bool:
    if not session_id:
        return False
    conn = _connect()
    try:
        cursor = conn.execute(
            "UPDATE app_sessions SET revoked_at=? WHERE session_id=? AND user_id=? AND revoked_at IS NULL",
            (int(time.time()), session_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def list_sessions(user_id: str, current_session_id: Optional[str]) -> list[Dict[str, Any]]:
    now = int(time.time())
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT session_id,created_at,expires_at,ip_address,user_agent,last_active_at FROM app_sessions "
            "WHERE user_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 50",
            (user_id, now),
        ).fetchall()
        return [
            {
                "id": row["session_id"],
                "device": (row["user_agent"] or "Unknown client")[:120],
                "ip": row["ip_address"],
                "createdAt": row["created_at"],
                "lastActive": row["last_active_at"] or row["created_at"],
                "expiresAt": row["expires_at"],
                "isCurrent": row["session_id"] == current_session_id,
            }
            for row in rows
        ]
    finally:
        conn.close()


def revoke_other_sessions(user_id: str, current_session_id: Optional[str]) -> int:
    if not current_session_id:
        return 0
    conn = _connect()
    try:
        cursor = conn.execute(
            "UPDATE app_sessions SET revoked_at=? WHERE user_id=? AND session_id<>? AND revoked_at IS NULL",
            (int(time.time()), user_id, current_session_id),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_preferences(user_id: str) -> Dict[str, Any]:
    conn = _connect()
    try:
        row = conn.execute("SELECT preferences_json FROM app_preferences WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            prefs = {"theme": "system"}
            conn.execute(
                "INSERT OR REPLACE INTO app_preferences(user_id,preferences_json,updated_at) VALUES(?,?,?)",
                (user_id, json.dumps(prefs), int(time.time())),
            )
            conn.commit()
            return prefs
        try:
            return json.loads(row["preferences_json"])
        except (json.JSONDecodeError, TypeError):
            return {"theme": "system"}
    finally:
        conn.close()


def update_preferences(user_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {"theme", "reduceMotion", "autoSplitView"}
    unknown = set(patch) - allowed
    if unknown:
        raise ValueError("Unsupported preference field(s): " + ", ".join(sorted(unknown)))
    if "theme" in patch and patch["theme"] not in {"light", "dark", "system"}:
        raise ValueError("theme must be one of: light, dark, system.")
    for key in ("reduceMotion", "autoSplitView"):
        if key in patch and not isinstance(patch[key], bool):
            raise ValueError(f"{key} must be a boolean.")
    prefs = get_preferences(user_id)
    prefs.update(patch)
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO app_preferences(user_id,preferences_json,updated_at) VALUES(?,?,?)",
            (user_id, json.dumps(prefs, separators=(",", ":")), int(time.time())),
        )
        conn.commit()
        return prefs
    finally:
        conn.close()


def create_history_session(
    user_id: str,
    client_session_id: str,
    title: str,
    mode: str = "deep_audit",
) -> Dict[str, Any]:
    """Persist a history row when a user stages an upload, without storing file bytes."""
    requested_id = (client_session_id or "").strip()
    if not SAFE_ID_RE.fullmatch(requested_id):
        raise ValueError("sessionId must be 8-100 letters, numbers, underscores, or hyphens.")
    if mode not in ALLOWED_MODES:
        raise ValueError("Unknown analysis mode.")
    clean_title = " ".join((title or "").strip().split())[:72]
    if not clean_title:
        clean_title = "Security Audit"
    now = int(time.time())
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT client_session_id,title,created_at,updated_at FROM app_history WHERE user_id=? AND client_session_id=?",
            (user_id, requested_id),
        ).fetchone()
        if row:
            return {
                "sessionId": row["client_session_id"],
                "title": row["title"],
                "createdAt": row["created_at"] * 1000,
                "updatedAt": row["updated_at"] * 1000,
            }
        conn.execute(
            "INSERT INTO app_history(user_id,client_session_id,title,mode,messages_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (user_id, requested_id, clean_title, mode, "[]", now, now),
        )
        conn.commit()
        return {"sessionId": requested_id, "title": clean_title, "createdAt": now * 1000, "updatedAt": now * 1000}
    finally:
        conn.close()


def save_history_analysis(
    user_id: str,
    client_session_id: Optional[str],
    mode: str,
    prompt: str,
    filename: Optional[str],
    content: str,
    evidence: Dict[str, Any],
    telemetry: Dict[str, Any],
) -> Dict[str, Any]:
    if mode not in ALLOWED_MODES:
        raise ValueError("Unknown analysis mode.")
    requested_id = (client_session_id or "").strip()
    if requested_id and not SAFE_ID_RE.fullmatch(requested_id):
        raise ValueError("sessionId must be 8-100 letters, numbers, underscores, or hyphens.")
    session_id = requested_id or ("session_" + uuid4().hex)
    now = int(time.time())
    prompt_text = (prompt or "").strip()[:4000]
    answer_text = (content or "")[:120_000]
    title_source = (filename and f"Audit: {filename}") or prompt_text or "Security Audit"
    title = title_source[:72]

    user_message = {
        "id": "usr_" + uuid4().hex,
        "role": "user",
        "content": prompt_text or (f"Analyze uploaded PDF: {filename}" if filename else "Security analysis request"),
        "analysisMode": mode,
        "timestamp": time.strftime("%H:%M", time.localtime(now)),
    }
    agent_message = {
        "id": "agent_" + uuid4().hex,
        "role": "agent",
        "content": answer_text,
        "analysisMode": mode,
        "evidence": evidence,
        "telemetry": telemetry,
        "timestamp": time.strftime("%H:%M", time.localtime(now)),
    }

    conn = _connect()
    try:
        row = conn.execute(
            "SELECT messages_json,created_at,title FROM app_history WHERE user_id=? AND client_session_id=?",
            (user_id, session_id),
        ).fetchone()
        if row:
            try:
                messages = json.loads(row["messages_json"])
                if not isinstance(messages, list):
                    messages = []
            except (ValueError, TypeError):
                messages = []
            messages.extend([user_message, agent_message])
            messages = messages[-100:]
            created_at = int(row["created_at"])
            if title_source == "Security Audit" or not title_source:
                title = row["title"]
        else:
            messages = [user_message, agent_message]
            created_at = now
        conn.execute(
            "INSERT OR REPLACE INTO app_history(user_id,client_session_id,title,mode,messages_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (user_id, session_id, title, mode, json.dumps(messages, ensure_ascii=False, separators=(",", ":")), created_at, now),
        )
        conn.commit()
        return {"sessionId": session_id, "title": title, "createdAt": created_at * 1000, "updatedAt": now * 1000}
    finally:
        conn.close()


def list_history(user_id: str, limit: int = 50) -> list[Dict[str, Any]]:
    limit = max(1, min(int(limit), 100))
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT client_session_id,title,mode,messages_json,created_at,updated_at FROM app_history "
            "WHERE user_id=? ORDER BY updated_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        items = []
        for row in rows:
            try:
                messages = json.loads(row["messages_json"])
                if not isinstance(messages, list):
                    messages = []
            except (ValueError, TypeError):
                messages = []
            items.append({
                "id": row["client_session_id"],
                "title": row["title"],
                "date": time.strftime("%b %d, %Y", time.localtime(row["updated_at"])),
                "mode": row["mode"],
                "messages": messages,
                "createdAt": row["created_at"] * 1000,
                "updatedAt": row["updated_at"] * 1000,
            })
        return items
    finally:
        conn.close()


def delete_history_session(user_id: str, client_session_id: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM app_history WHERE user_id=? AND client_session_id=?", (user_id, client_session_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_history(user_id: str) -> int:
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM app_history WHERE user_id=?", (user_id,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def create_api_key(user_id: str, name: str) -> Dict[str, Any]:
    clean_name = " ".join((name or "").strip().split())
    if not clean_name or len(clean_name) > 80:
        raise ValueError("API key name must contain between 1 and 80 characters.")
    secret = "ag_sec_live_" + secrets.token_urlsafe(32)
    key_id = "key_" + uuid4().hex
    prefix = secret[:24] + "..."
    now = int(time.time())
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO app_api_keys(key_id,user_id,name,prefix,secret_hash,created_at) VALUES(?,?,?,?,?,?)",
            (key_id, user_id, clean_name, prefix, digest, now),
        )
        conn.commit()
    finally:
        conn.close()
    return {"id": key_id, "name": clean_name, "prefix": prefix, "createdAt": now, "scope": "AgentGuard API", "secret": secret}


def list_api_keys(user_id: str) -> list[Dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT key_id,name,prefix,created_at,last_used_at FROM app_api_keys "
            "WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [
            {"id": row["key_id"], "name": row["name"], "prefix": row["prefix"], "createdAt": row["created_at"], "lastUsedAt": row["last_used_at"], "scope": "AgentGuard API"}
            for row in rows
        ]
    finally:
        conn.close()


def validate_api_key(secret: str) -> Optional[Dict[str, Any]]:
    """Validate a user-created AgentGuard API key and update last-used time."""
    clean_secret = (secret or "").strip()
    if not clean_secret or not clean_secret.startswith("ag_sec_live_"):
        return None
    digest = hashlib.sha256(clean_secret.encode("utf-8")).hexdigest()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT k.user_id,u.* FROM app_api_keys k JOIN app_users u ON u.user_id=k.user_id "
            "WHERE k.secret_hash=? AND k.revoked_at IS NULL AND u.disabled=0",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE app_api_keys SET last_used_at=? WHERE secret_hash=? AND revoked_at IS NULL", (int(time.time()), digest))
        conn.commit()
        user = _public_user(row)
        user.update({"user_id": user["id"], "session_id": None, "auth_kind": "api_key"})
        return user
    finally:
        conn.close()


def revoke_api_key(user_id: str, key_id: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE app_api_keys SET revoked_at=? WHERE key_id=? AND user_id=? AND revoked_at IS NULL",
            (int(time.time()), key_id, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Email OTP password-reset workflow
# ---------------------------------------------------------------------------
PASSWORD_RESET_OTP_TTL_SECONDS = 10 * 60
PASSWORD_RESET_OTP_MAX_ATTEMPTS = 5
PASSWORD_RESET_MAX_REQUESTS_PER_15_MINUTES = 3


def account_exists_by_email(email: str) -> bool:
    clean_email = (email or "").strip().lower()
    conn = _connect()
    try:
        row = conn.execute("SELECT 1 FROM app_users WHERE email=? AND disabled=0", (clean_email,)).fetchone()
        return row is not None
    finally:
        conn.close()


def _password_reset_email_digest(email: str) -> str:
    clean_email = (email or "").strip().lower()
    return hmac.new(_auth_secret(), b"password-reset-email:" + clean_email.encode("utf-8"), hashlib.sha256).hexdigest()


def _password_reset_otp_digest(email: str, otp: str) -> str:
    material = ("password-reset-otp:" + (email or "").strip().lower() + ":" + (otp or "")).encode("utf-8")
    return hmac.new(_auth_secret(), material, hashlib.sha256).hexdigest()


def create_password_reset_challenge(email: str, otp: str, ip_address: str = "unknown") -> bool:
    """Store a one-time password-reset challenge; return True only when mail should be sent.

    Unknown and OAuth-only emails get a dummy row to keep response behaviour generic,
    but never receive a usable OTP. The OTP is HMAC-digested at rest.
    """
    clean_email = (email or "").strip().lower()
    if not EMAIL_RE.fullmatch(clean_email):
        return False
    if not re.fullmatch(r"\d{6}", otp or ""):
        raise ValueError("OTP must be exactly six digits.")

    now = int(time.time())
    email_digest = _password_reset_email_digest(clean_email)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM app_password_reset_otps WHERE email_digest=? AND requested_at>=?",
            (email_digest, now - 15 * 60),
        ).fetchone()["n"]
        if int(recent) >= PASSWORD_RESET_MAX_REQUESTS_PER_15_MINUTES:
            conn.rollback()
            return False

        user = conn.execute(
            "SELECT user_id, auth_provider, disabled FROM app_users WHERE email=? COLLATE NOCASE",
            (clean_email,),
        ).fetchone()
        eligible = bool(user and not user["disabled"] and user["auth_provider"] == "email")
        user_id = user["user_id"] if eligible else None

        # A new request immediately invalidates any older outstanding code.
        conn.execute(
            "UPDATE app_password_reset_otps SET consumed_at=? WHERE email_digest=? AND consumed_at IS NULL",
            (now, email_digest),
        )
        conn.execute(
            "INSERT INTO app_password_reset_otps(request_id,email_digest,user_id,otp_hash,requested_at,expires_at,attempts,consumed_at,ip_address) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "otp_" + uuid4().hex,
                email_digest,
                user_id,
                _password_reset_otp_digest(clean_email, otp),
                now,
                now + PASSWORD_RESET_OTP_TTL_SECONDS,
                0,
                None if eligible else now,
                (ip_address or "unknown")[:64],
            ),
        )
        conn.commit()
        return eligible
    finally:
        conn.close()


def invalidate_password_reset_challenge(email: str, otp: str) -> None:
    clean_email = (email or "").strip().lower()
    now = int(time.time())
    conn = _connect()
    try:
        conn.execute(
            "UPDATE app_password_reset_otps SET consumed_at=? WHERE email_digest=? AND otp_hash=? AND consumed_at IS NULL",
            (now, _password_reset_email_digest(clean_email), _password_reset_otp_digest(clean_email, otp)),
        )
        conn.commit()
    finally:
        conn.close()


def reset_password_with_otp(email: str, otp: str, new_password: str) -> Optional[Dict[str, Any]]:
    """Validate a six-digit OTP, update the password, and revoke all user sessions.

    Returns the public account record on success and None for invalid, expired,
    consumed, exhausted, unknown-account, or OAuth-only challenges.
    """
    clean_email = (email or "").strip().lower()
    if not EMAIL_RE.fullmatch(clean_email):
        return None
    if not isinstance(new_password, str) or len(new_password) < 8 or len(new_password) > 256:
        raise ValueError("Password must contain between 8 and 256 characters.")
    if not re.fullmatch(r"\d{6}", otp or ""):
        return None

    now = int(time.time())
    email_digest = _password_reset_email_digest(clean_email)
    supplied_hash = _password_reset_otp_digest(clean_email, otp)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM app_password_reset_otps WHERE email_digest=? ORDER BY requested_at DESC LIMIT 1",
            (email_digest,),
        ).fetchone()
        if (
            row is None
            or row["user_id"] is None
            or row["consumed_at"] is not None
            or int(row["expires_at"]) <= now
            or int(row["attempts"]) >= PASSWORD_RESET_OTP_MAX_ATTEMPTS
        ):
            conn.rollback()
            return None

        if not hmac.compare_digest(row["otp_hash"], supplied_hash):
            attempts = int(row["attempts"]) + 1
            conn.execute(
                "UPDATE app_password_reset_otps SET attempts=?, consumed_at=? WHERE request_id=?",
                (attempts, now if attempts >= PASSWORD_RESET_OTP_MAX_ATTEMPTS else None, row["request_id"]),
            )
            conn.commit()
            return None

        user = conn.execute(
            "SELECT * FROM app_users WHERE user_id=? AND email=? COLLATE NOCASE AND disabled=0 AND auth_provider='email'",
            (row["user_id"], clean_email),
        ).fetchone()
        if user is None:
            conn.execute("UPDATE app_password_reset_otps SET consumed_at=? WHERE request_id=?", (now, row["request_id"]))
            conn.commit()
            return None

        new_hash = _hash_password(new_password)
        conn.execute("UPDATE app_users SET password_hash=? WHERE user_id=?", (new_hash, user["user_id"]))
        conn.execute(
            "UPDATE app_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
            (now, user["user_id"]),
        )
        conn.execute("UPDATE app_password_reset_otps SET consumed_at=? WHERE request_id=?", (now, row["request_id"]))
        # Invalidate every other OTP previously created for the same email.
        conn.execute(
            "UPDATE app_password_reset_otps SET consumed_at=? WHERE email_digest=? AND consumed_at IS NULL",
            (now, email_digest),
        )
        conn.commit()
        return _public_user(user)
    finally:
        conn.close()

