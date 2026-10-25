"""
AgentGuard Security Detectors
=============================

Provides:
1. PromptInjectionDetector
2. SensitiveDataDetector
3. Structured prompt-injection detection results

Integration:
- agent_logic.py
- rag_engine.py
- mcp_gateway.py

Security note:
These detectors use bounded heuristic checks.
They are one layer of defense, not a guarantee that
all prompt injections or sensitive data will be detected.
"""

from __future__ import annotations

import base64
import json
import re

from typing import Any, Dict, List, Tuple

from pydantic import BaseModel, Field


# ============================================================
# 1. Global Limits
# ============================================================

MAX_DETECTION_CHARS = 200_000
MAX_ENCODED_CANDIDATES = 20
MAX_DECODED_CHARS = 2_000

MAX_INSPECTED_ARGUMENTS = 100
MAX_NESTING_DEPTH = 8


# ============================================================
# 2. Prompt Injection Detection Result
# ============================================================

class InjectionDetectionResult(BaseModel):
    """
    Standard result consumed by other AgentGuard modules.

    is_injection:
        Whether suspicious injection indicators were detected.

    score:
        Heuristic risk score between 0.0 and 1.0.

    reasons:
        Stable identifiers for the detection indicators.
    """

    is_injection: bool

    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    reasons: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# 3. Prompt Injection Detector
# ============================================================

class PromptInjectionDetector:
    """
    Detect common prompt-injection indicators.

    The detector does not execute instructions, call tools,
    or make authorization decisions.

    Authorization remains the responsibility of
    AgentGuard's deterministic security gateway.
    """

    PATTERNS: List[Tuple[str, str, float]] = [
        (
            r"\bignore\s+(?:all\s+)?"
            r"(?:previous|prior|above|system)\s+instructions?\b",
            "IGNORE_INSTRUCTIONS_DIRECTIVE",
            0.95,
        ),
        (
            r"\b(?:disregard|forget)\s+(?:all\s+)?"
            r"(?:previous|prior|above|system)\s+instructions?\b",
            "DISREGARD_INSTRUCTIONS_DIRECTIVE",
            0.90,
        ),
        (
            r"(?:\bsystem\s*:|\[system\]|\[instruction\]|"
            r"<impersonate>)",
            "ROLE_IMPERSONATION_MARKER",
            0.85,
        ),
        (
            r"\b(?:system|developer|admin)\s+"
            r"(?:directive|instruction|override|message)\s*:",
            "PRIVILEGED_DIRECTIVE_MARKER",
            0.90,
        ),
        (
            r"\b(?:call|execute|run|trigger)\s+"
            r"(?:the\s+)?(?:tool|function)\s+[\w.-]+",
            "TOOL_EXECUTION_COMMAND",
            0.85,
        ),
        (
            r"\b(?:call|execute|run|trigger)\s+"
            r"(?:the\s+)?"
            r"(?:export_customer_data|send_email|"
            r"search_academic_db)\b",
            "DIRECT_TOOL_NAME_COMMAND",
            0.90,
        ),
        (
            r"\b(?:override|bypass|disable)\s+"
            r"(?:the\s+)?(?:system\s+)?"
            r"(?:security\s+)?(?:rules|policy|instructions|guardrails)\b",
            "POLICY_OVERRIDE_DIRECTIVE",
            0.85,
        ),
        (
            r"\b(?:reveal|print|expose|exfiltrate)\s+"
            r"(?:all\s+)?(?:secrets|credentials|api keys|tokens)\b",
            "CREDENTIAL_DISCLOSURE_DIRECTIVE",
            0.95,
        ),
        (
            r"(?:instrucci[oó]n(?:es)?\s+del\s+sistema|"
            r"ignora\s+(?:las\s+)?instrucciones|"
            r"ejecutar\s+(?:la\s+)?herramienta)",
            "SPANISH_INJECTION_CUE",
            0.85,
        ),
        (
            r"(?:font-size\s*:\s*0(?:px|em|rem|%)?|"
            r"display\s*:\s*none|visibility\s*:\s*hidden)",
            "HIDDEN_TEXT_MARKER",
            0.90,
        ),
        (
            r"<!--[\s\S]{0,2000}?"
            r"(?:instruction|ignore|execute|export|system)"
            r"[\s\S]{0,2000}?-->",
            "HTML_COMMENT_INJECTION",
            0.90,
        ),
        (
            r"\bplease\s+(?:also\s+)?"
            r"(?:send|export|transfer|email)\b"
            r".{0,300}?\bto\s+"
            r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
            "POSSIBLE_DATA_EXFILTRATION",
            0.90,
        ),
        (
            r"\b(?:note to the model|"
            r"message to the assistant)\s*:",
            "MODEL_DIRECTIVE_MARKER",
            0.75,
        ),
        (
            r"\b(?:base64|encoded)\s+"
            r"(?:payload|instruction|directive)\s*:\s*"
            r"[A-Za-z0-9+/]{20,}={0,2}",
            "ENCODED_DIRECTIVE_PAYLOAD",
            0.80,
        ),
    ]

    @classmethod
    def detect(
        cls,
        text: str,
    ) -> InjectionDetectionResult:
        """
        Inspect text and return a structured detection result.

        Compatible interface:
            result = PromptInjectionDetector.detect(text)

            result.is_injection
            result.score
            result.reasons
        """

        if not isinstance(text, str) or not text:
            return InjectionDetectionResult(
                is_injection=False,
                score=0.0,
                reasons=[],
            )

        # Bound the amount of text processed.
        sample = text[:MAX_DETECTION_CHARS]

        reasons: List[str] = []
        max_score = 0.0

        for pattern, label, weight in cls.PATTERNS:
            if re.search(
                pattern,
                sample,
                flags=re.IGNORECASE,
            ):
                reasons.append(label)
                max_score = max(max_score, weight)

        # Inspect a limited number of possible encoded instructions.
        decoded_reason = cls._detect_encoded_instruction(sample)

        if decoded_reason:
            reasons.append(decoded_reason)
            max_score = max(max_score, 0.90)

        # Preserve order while eliminating duplicate reason labels.
        reasons = list(dict.fromkeys(reasons))

        # Multiple independent indicators can increase suspicion.
        if len(reasons) >= 2:
            combined_score = min(
                0.99,
                max_score + 0.05 * (len(reasons) - 1),
            )
        else:
            combined_score = max_score

        combined_score = round(
            min(combined_score, 1.0),
            2,
        )

        is_injection = (
            combined_score >= 0.75
            or len(reasons) >= 2
        )

        return InjectionDetectionResult(
            is_injection=is_injection,
            score=combined_score,
            reasons=reasons,
        )

    @staticmethod
    def _detect_encoded_instruction(
        text: str,
    ) -> str | None:
        """
        Check a limited number of Base64-like strings.

        A string is flagged only when decoding reveals
        a recognizable suspicious instruction indicator.

        Base64 itself is not considered proof of an attack.
        """

        token_pattern = re.compile(
            r"(?<![A-Za-z0-9+/])"
            r"[A-Za-z0-9+/]{24,}={0,2}"
            r"(?![A-Za-z0-9+/])"
        )

        candidates = token_pattern.finditer(
            text[:MAX_DETECTION_CHARS]
        )

        directive_pattern = re.compile(
            r"(?:ignore\s+(?:previous|prior)\s+instructions|"
            r"system\s+instruction|"
            r"export_customer_data|"
            r"send_email|"
            r"call\s+(?:the\s+)?tool|"
            r"execute\s+(?:the\s+)?tool|"
            r"exfiltrat)",
            flags=re.IGNORECASE,
        )

        inspected = 0

        for match in candidates:
            if inspected >= MAX_ENCODED_CANDIDATES:
                break

            token = match.group(0)
            inspected += 1

            try:
                padding = "=" * ((4 - len(token) % 4) % 4)

                decoded = base64.b64decode(
                    token + padding,
                    validate=True,
                )

                decoded_text = decoded.decode(
                    "utf-8",
                    errors="ignore",
                )[:MAX_DECODED_CHARS]

            except (
                ValueError,
                UnicodeError,
            ):
                continue

            if (
                len(decoded_text) >= 8
                and directive_pattern.search(decoded_text)
            ):
                return "DECODED_BASE64_INSTRUCTION"

        return None


# ============================================================
# 4. Sensitive Data Detector
# ============================================================

class SensitiveDataDetector:
    """
    Detect common credential patterns, possible SSNs,
    sensitive argument fields, and bulk-record requests.

    Results contain finding descriptions rather than
    copying detected secret values into application logs.
    """

    SECRET_PATTERNS = [
        re.compile(
            r"\b(?:sk|pk|api|key)_[A-Za-z0-9_-]{20,}\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        ),
        re.compile(
            r"\bAIza[0-9A-Za-z_-]{30,}\b",
        ),
        re.compile(
            r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        ),
        re.compile(
            r"\bAKIA[A-Z0-9]{16}\b",
        ),
        re.compile(
            r"-----BEGIN\s+"
            r"(?:RSA\s+|EC\s+|OPENSSH\s+)?"
            r"PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ]

    SSN_PATTERN = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )

    SENSITIVE_FIELD_NAMES = {
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
        "credentials",
    }

    @classmethod
    def inspect_tool_args(
        cls,
        tool_args: Dict[str, Any],
        bulk_threshold: int = 100,
    ) -> List[str]:
        """
        Inspect tool arguments and return security findings.

        Compatible interface:
            findings = SensitiveDataDetector.inspect_tool_args(
                tool_args,
                bulk_threshold=100,
            )
        """

        if not isinstance(tool_args, dict):
            return [
                "SENSITIVE_DATA: Tool arguments are not a valid dictionary"
            ]

        if (
            isinstance(bulk_threshold, bool)
            or not isinstance(bulk_threshold, int)
            or bulk_threshold < 0
        ):
            return [
                "SENSITIVE_DATA: Invalid bulk-record threshold"
            ]

        findings: List[str] = []

        # Inspect only bounded, JSON-compatible content.
        try:
            serialized = json.dumps(
                tool_args,
                ensure_ascii=False,
                default=lambda _: "[unsupported value]",
            )

            text_repr = serialized[:MAX_DETECTION_CHARS]

        except (
            TypeError,
            ValueError,
            RecursionError,
        ):
            return [
                "SENSITIVE_DATA: Unable to safely inspect tool arguments"
            ]

        # Detect common credential formats.
        if any(
            pattern.search(text_repr)
            for pattern in cls.SECRET_PATTERNS
        ):
            findings.append(
                "SENSITIVE_DATA: Possible API key or credential detected"
            )

        # Detect a possible US Social Security Number pattern.
        if cls.SSN_PATTERN.search(text_repr):
            findings.append(
                "SENSITIVE_DATA: Possible SSN pattern detected"
            )

        # Check whether arguments contain credential-like fields.
        if cls._contains_sensitive_field(tool_args):
            findings.append(
                "SENSITIVE_DATA: Credential-like argument field detected"
            )

        # Support both the original and a common alternate field name.
        record_count = tool_args.get(
            "records_count",
            tool_args.get("record_count"),
        )

        if (
            isinstance(record_count, int)
            and not isinstance(record_count, bool)
            and record_count > bulk_threshold
        ):
            findings.append(
                "BULK_DATA: Requested record count exceeds "
                f"the configured threshold ({bulk_threshold})"
            )

        # Avoid duplicate messages.
        return list(dict.fromkeys(findings))

    @classmethod
    def _contains_sensitive_field(
        cls,
        value: Any,
        depth: int = 0,
    ) -> bool:
        """
        Recursively check dictionary keys with bounded depth
        and bounded numbers of inspected entries.
        """

        if depth >= MAX_NESTING_DEPTH:
            return False

        if isinstance(value, dict):
            for index, (key, item) in enumerate(value.items()):
                if index >= MAX_INSPECTED_ARGUMENTS:
                    break

                normalized_key = str(key).strip().lower()

                if normalized_key in cls.SENSITIVE_FIELD_NAMES:
                    # Empty or unset fields are not automatically
                    # treated as proof of a leaked credential.
                    if item not in (None, ""):
                        return True

                if cls._contains_sensitive_field(
                    item,
                    depth + 1,
                ):
                    return True

        elif isinstance(value, (list, tuple)):
            for item in value[:MAX_INSPECTED_ARGUMENTS]:
                if cls._contains_sensitive_field(
                    item,
                    depth + 1,
                ):
                    return True

        return False