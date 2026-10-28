"""SMTP email notices for AgentGuard authentication.

Email delivery is explicitly opt-in: set AGENTGUARD_EMAIL_NOTIFICATIONS_ENABLED=true
and configure SMTP_HOST and SMTP_FROM_EMAIL. No OTP or password is written to logs.
"""
from __future__ import annotations

import html
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional

logger = logging.getLogger("agentguard.email")


def notifications_enabled() -> bool:
    # Do not send real mail as a side effect of test execution unless a test
    # explicitly opts in. Individual unit tests can monkeypatch this function.
    if os.getenv("PYTEST_CURRENT_TEST") and os.getenv("AGENTGUARD_ALLOW_EMAILS_IN_TESTS", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return False
    if os.getenv("AGENTGUARD_EMAIL_NOTIFICATIONS_ENABLED", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return False
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM_EMAIL", "").strip()
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if not host or not sender:
        return False
    if bool(username) != bool(password):
        return False
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        return False
    return 1 <= port <= 65535


def send_email(to_email: str, subject: str, text_body: str, html_body: Optional[str] = None) -> bool:
    if not notifications_enabled():
        return False
    recipient = (to_email or "").strip()
    if not recipient or "@" not in recipient:
        return False

    host = os.getenv("SMTP_HOST", "").strip()
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM_EMAIL", "").strip()
    sender_name = os.getenv("SMTP_FROM_NAME", "AgentGuard Security").strip() or "AgentGuard Security"
    use_ssl = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
    use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = f"{sender_name} <{sender}>"
        msg["To"] = recipient
        msg.set_content(text_body)
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        timeout = float(os.getenv("SMTP_TIMEOUT_SECONDS", "8"))
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()) as server:
                if username:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                if use_tls:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if username:
                    server.login(username, password)
                server.send_message(msg)
        return True
    except Exception as exc:
        # Never log addresses, reset codes, message content, or SMTP credentials.
        logger.warning("Email delivery failed (%s).", type(exc).__name__)
        return False


def _when_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def send_registration_notice(email: str, name: str, ip_address: str = "unknown") -> str:
    if not notifications_enabled():
        return "not_configured"
    safe_name = (name or "AgentGuard user").strip()[:100]
    stamp = _when_text()
    text = (
        f"Hello {safe_name},\n\nYour AgentGuard account was created successfully.\n"
        f"Time: {stamp}\nNetwork address: {(ip_address or 'unknown')[:64]}\n\n"
        "If you did not create this account, contact the AgentGuard administrator.\n"
        "AgentGuard Security"
    )
    html_body = (
        f"<p>Hello {html.escape(safe_name)},</p><p>Your AgentGuard account was created successfully.</p>"
        f"<p><b>Time:</b> {html.escape(stamp)}<br><b>Network address:</b> {html.escape((ip_address or 'unknown')[:64])}</p>"
        "<p>If you did not create this account, contact the AgentGuard administrator.</p><p>AgentGuard Security</p>"
    )
    return "sent" if send_email(email, "AgentGuard account created", text, html_body) else "failed"


def send_login_notice(email: str, name: str, ip_address: str = "unknown", provider: str = "email") -> str:
    if not notifications_enabled():
        return "not_configured"
    safe_name = (name or "AgentGuard user").strip()[:100]
    stamp = _when_text()
    text = (
        f"Hello {safe_name},\n\nA successful login to your AgentGuard account was detected.\n"
        f"Time: {stamp}\nMethod: {(provider or 'email')[:20]}\nNetwork address: {(ip_address or 'unknown')[:64]}\n\n"
        "If this was not you, reset your password and review/revoke active sessions.\nAgentGuard Security"
    )
    html_body = (
        f"<p>Hello {html.escape(safe_name)},</p><p>A successful login to your AgentGuard account was detected.</p>"
        f"<p><b>Time:</b> {html.escape(stamp)}<br><b>Method:</b> {html.escape((provider or 'email')[:20])}<br>"
        f"<b>Network address:</b> {html.escape((ip_address or 'unknown')[:64])}</p>"
        "<p>If this was not you, reset your password and review or revoke active sessions.</p><p>AgentGuard Security</p>"
    )
    return "sent" if send_email(email, "AgentGuard login alert", text, html_body) else "failed"


def send_password_reset_otp(email: str, otp: str) -> bool:
    if not notifications_enabled():
        return False
    text = (
        "A password reset was requested for your AgentGuard account.\n\n"
        f"Your one-time code is: {otp}\n\nThis code expires in 10 minutes and can only be used once. "
        "If you did not request this, ignore this email. Do not share the code with anyone.\nAgentGuard Security"
    )
    html_body = (
        "<p>A password reset was requested for your AgentGuard account.</p>"
        f"<p>Your one-time code is: <strong style='font-size:24px;letter-spacing:5px'>{html.escape(otp)}</strong></p>"
        "<p>This code expires in 10 minutes and can only be used once. Do not share the code with anyone.</p>"
        "<p>If you did not request this, ignore this email.</p><p>AgentGuard Security</p>"
    )
    return send_email(email, "AgentGuard password reset code", text, html_body)


def send_password_changed_notice(email: str, name: str) -> str:
    if not notifications_enabled():
        return "not_configured"
    safe_name = (name or "AgentGuard user").strip()[:100]
    text = (
        f"Hello {safe_name},\n\nYour AgentGuard password was changed successfully. "
        "All existing sessions were revoked. Sign in again using your new password.\n\n"
        "If this was not you, contact the AgentGuard administrator immediately.\nAgentGuard Security"
    )
    html_body = (
        f"<p>Hello {html.escape(safe_name)},</p><p>Your AgentGuard password was changed successfully.</p>"
        "<p>All existing sessions were revoked. Sign in again using your new password.</p>"
        "<p>If this was not you, contact the AgentGuard administrator immediately.</p><p>AgentGuard Security</p>"
    )
    return "sent" if send_email(email, "AgentGuard password changed", text, html_body) else "failed"
