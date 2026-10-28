"""
AgentGuard MCP Security Gateway
================================

Responsibilities:
1. Load and validate policy.yaml.
2. Enforce deterministic ALLOW / REVIEW / BLOCK decisions.
3. Enforce fail-closed behaviour.
4. Detect suspicious proposed tool arguments.
5. Check sensitive data and destination allowlists.
6. Maintain action provenance and lineage.
7. Persist human approval requests.
8. Verify approval hashes before processing.
9. Enforce single-use approval processing.
10. Integrate with AgentGuard's guarded-tool registry.

Important:
- Unknown tools are never executed.
- Prompt-injection indicators cannot be overridden by a
  simple human_approved flag.
- An approval is bound to a specific action hash.
- This module does not make arbitrary external tools safe.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid

from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field


# ============================================================
# 1. Compatible Imports
# ============================================================

try:
    from .agent_logic import (
        AgentGuardDecision,
        ContextItem,
        LineageNode,
        SecurityDecisionType,
        SessionContext,
        ToolRiskLevel,
    )

    from .database import (
        AuditLogger,
        audit_logger,
        claim_pending_approval,
        compute_canonical_hash,
        get_all_pending_approvals,
        log_audit_event,
        save_pending_approval,
        update_approval_status,
    )

    from .detectors import (
        PromptInjectionDetector,
        SensitiveDataDetector,
    )

except ImportError:
    # Supports running from inside the backend directory.
    from agent_logic import (
        AgentGuardDecision,
        ContextItem,
        LineageNode,
        SecurityDecisionType,
        SessionContext,
        ToolRiskLevel,
    )

    from database import (
        AuditLogger,
        audit_logger,
        claim_pending_approval,
        compute_canonical_hash,
        get_all_pending_approvals,
        log_audit_event,
        save_pending_approval,
        update_approval_status,
    )

    from detectors import (
        PromptInjectionDetector,
        SensitiveDataDetector,
    )


logger = logging.getLogger("agentguard.gateway")


# ============================================================
# 2. Default Policy
# ============================================================

DEFAULT_FALLBACK_POLICY: Dict[str, Any] = {
    "tool_risk_levels": {
        "export_customer_data": "CRITICAL",
        "send_email": "HIGH",
        "search_academic_db": "LOW",
    },
    "defaults": {
        "unknown_tool_risk": "CRITICAL",
        "default_verdict": "BLOCK",
        "bulk_record_threshold": 100,
    },
    "destinations": {
        "allowed_email_domains": [
            "org.com",
            "trusted-partner.org",
            "company.com",
        ],
        "allowed_api_hosts": [
            "api.ncbi.nlm.nih.gov",
            "export.arxiv.org",
            "internal-db.company.com",
        ],
    },
    "evaluations": {
        "untrusted_context_high_critical": "BLOCK",
        "untrusted_context_medium": "REVIEW",
        "untrusted_context_low": "ALLOW",
        "untainted_critical": "REVIEW",
        "untainted_allowlisted": "ALLOW",
    },
}


RISK_ORDER = {
    ToolRiskLevel.LOW: 0,
    ToolRiskLevel.MEDIUM: 1,
    ToolRiskLevel.HIGH: 2,
    ToolRiskLevel.CRITICAL: 3,
}


EMAIL_TOOL_NAMES = {
    "send_email",
    "export_customer_data",
}


EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Z0-9.-]+\.[A-Z]{2,}$",
    re.IGNORECASE,
)


# ============================================================
# 3. Utility Functions
# ============================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_decision(
    value: Any,
    fallback: SecurityDecisionType = SecurityDecisionType.BLOCK,
) -> SecurityDecisionType:
    """
    Parse a configured decision safely.

    Invalid values never turn into ALLOW.
    """

    try:
        return SecurityDecisionType(
            str(value).strip().upper()
        )
    except (ValueError, TypeError):
        return fallback


def _safe_risk(
    value: Any,
) -> ToolRiskLevel:
    """
    Parse risk configuration.

    Invalid risk values are treated as CRITICAL.
    """

    try:
        return ToolRiskLevel(
            str(value).strip().upper()
        )
    except (ValueError, TypeError):
        return ToolRiskLevel.CRITICAL


def _safe_lineage_args(
    args: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Redact sensitive fields and bound values displayed
    in the security lineage.
    """

    output: Dict[str, Any] = {}

    sensitive_fragments = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "credential",
        "private_key",
        "authorization",
    )

    for key, value in list(args.items())[:30]:
        name = str(key)
        lower_name = name.lower()

        if any(
            fragment in lower_name
            for fragment in sensitive_fragments
        ):
            output[name] = "[REDACTED]"

        elif lower_name in {
            "body",
            "content",
            "document_text",
            "prompt",
        }:
            output[name] = (
                "[TEXT OMITTED: "
                f"{len(str(value))} characters]"
            )

        elif isinstance(value, str):
            output[name] = value[:160]

        elif (
            isinstance(value, (int, float, bool))
            or value is None
        ):
            output[name] = value

        elif isinstance(value, (dict, list)):
            output[name] = (
                f"[{type(value).__name__}: "
                f"{len(value)} item(s)]"
            )

        else:
            output[name] = (
                f"[UNSUPPORTED: {type(value).__name__}]"
            )

    return output


# ============================================================
# 4. Policy Configuration Error
# ============================================================

class PolicyConfigurationError(RuntimeError):
    """Raised when AgentGuard cannot safely load its policy."""


# ============================================================
# 5. Deterministic Policy Engine
# ============================================================

class PolicyEngine:
    """
    Load policy.yaml and validate configuration.

    This engine fails closed when:
    - The policy file is missing.
    - YAML syntax is invalid.
    - A required section is malformed.
    - Policy values are invalid.
    """

    REQUIRED_SECTIONS = {
        "tool_risk_levels",
        "defaults",
        "destinations",
        "evaluations",
    }

    def __init__(
        self,
        policy_path: Optional[str] = None,
    ) -> None:

        self.policy_path = (
            Path(policy_path).resolve()
            if policy_path
            else Path(__file__).resolve().parent / "policy.yaml"
        )

        self._cached_policy: Optional[Dict[str, Any]] = None
        self._last_mtime: Optional[int] = None
        self._lock = RLock()

    def load_policy(self) -> Dict[str, Any]:
        """
        Load and validate the current YAML policy.

        The cached policy is used only when its modification
        timestamp still matches the current file.
        """

        with self._lock:
            try:
                if not self.policy_path.is_file():
                    raise PolicyConfigurationError(
                        "policy.yaml is missing."
                    )

                stat = self.policy_path.stat()
                mtime = stat.st_mtime_ns

                if (
                    self._cached_policy is not None
                    and self._last_mtime == mtime
                ):
                    return self._cached_policy

                with self.policy_path.open(
                    "r",
                    encoding="utf-8",
                ) as handle:
                    loaded = yaml.safe_load(handle)

            except PolicyConfigurationError:
                raise

            except Exception as exc:
                raise PolicyConfigurationError(
                    "Unable to read policy.yaml."
                ) from exc

            if not isinstance(loaded, dict):
                raise PolicyConfigurationError(
                    "Policy configuration must be a YAML mapping."
                )

            missing = (
                self.REQUIRED_SECTIONS
                - set(loaded.keys())
            )

            if missing:
                raise PolicyConfigurationError(
                    "Missing required policy sections: "
                    + ", ".join(sorted(missing))
                )

            for section in self.REQUIRED_SECTIONS:
                if not isinstance(loaded[section], dict):
                    raise PolicyConfigurationError(
                        f"Policy section '{section}' must be a mapping."
                    )

            policy = {
                **DEFAULT_FALLBACK_POLICY,
                **loaded,
            }

            # Validate defaults.
            defaults = policy["defaults"]

            if defaults.get("default_verdict") != "BLOCK":
                raise PolicyConfigurationError(
                    "default_verdict must remain BLOCK."
                )

            _safe_risk(
                defaults.get("unknown_tool_risk")
            )

            threshold = defaults.get(
                "bulk_record_threshold"
            )

            if (
                isinstance(threshold, bool)
                or not isinstance(threshold, int)
                or threshold < 0
            ):
                raise PolicyConfigurationError(
                    "bulk_record_threshold must be a non-negative integer."
                )

            # Validate all configured risk values.
            for tool_name, risk in policy[
                "tool_risk_levels"
            ].items():

                if not isinstance(tool_name, str) or not tool_name.strip():
                    raise PolicyConfigurationError(
                        "Tool names must be non-empty strings."
                    )

                try:
                    ToolRiskLevel(
                        str(risk).upper()
                    )
                except ValueError as exc:
                    raise PolicyConfigurationError(
                        f"Invalid risk level for tool '{tool_name}'."
                    ) from exc

            # Validate allowlists.
            destinations = policy["destinations"]

            for list_name in (
                "allowed_email_domains",
                "allowed_api_hosts",
            ):
                entries = destinations.get(list_name)

                if not isinstance(entries, list):
                    raise PolicyConfigurationError(
                        f"{list_name} must be a YAML list."
                    )

                if not all(
                    isinstance(entry, str) and entry.strip()
                    for entry in entries
                ):
                    raise PolicyConfigurationError(
                        f"{list_name} contains an invalid entry."
                    )

            # Validate decision policy values.
            for name, decision in policy[
                "evaluations"
            ].items():

                try:
                    parsed = SecurityDecisionType(
                        str(decision).upper()
                    )
                except ValueError as exc:
                    raise PolicyConfigurationError(
                        f"Invalid decision for evaluation '{name}'."
                    ) from exc

                # Unsafe changes to core default-deny rules must
                # not be allowed to turn a tainted critical action
                # into an allowed action.
                if (
                    name == "untrusted_context_high_critical"
                    and parsed != SecurityDecisionType.BLOCK
                ):
                    raise PolicyConfigurationError(
                        "Untrusted high/critical actions must BLOCK."
                    )

            self._cached_policy = policy
            self._last_mtime = mtime

            return policy


# ============================================================
# 6. Security Gateway
# ============================================================

class SecurityGateway:
    """
    Evaluate a proposed tool action before its execution.

    The evaluation is deterministic and based on:
    - Known tool registry
    - Policy configuration
    - Tool risk
    - Source provenance
    - Prompt-injection indicators
    - Sensitive data findings
    - Destination restrictions
    - Human approval state
    """

    def __init__(
        self,
        engine: Optional[PolicyEngine] = None,
    ) -> None:

        self.policy_engine = (
            engine
            if engine is not None
            else PolicyEngine()
        )

    # --------------------------------------------------------
    # Main Evaluation Entry Point
    # --------------------------------------------------------

    def evaluate_action(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_context: SessionContext,
        detected_injection_text: Optional[str] = None,
        human_approved: bool = False,
    ) -> AgentGuardDecision:
        """
        Evaluate an action proposal.

        This method never executes the tool. It only returns
        an authorization decision for GuardedTool to enforce.
        """

        if (
            not isinstance(tool_name, str)
            or not tool_name.strip()
            or not isinstance(tool_args, dict)
            or not isinstance(session_context, SessionContext)
        ):
            return self._block(
                tool_name=str(tool_name or "unknown"),
                args={},
                reason="Invalid action proposal.",
                reasons=["INVALID_ACTION_PROPOSAL"],
                checks=["INPUT_VALIDATION"],
            )

        tool_name = tool_name.strip()

        # ----------------------------------------------
        # Load security policy. Failure means BLOCK.
        # ----------------------------------------------

        try:
            policy = self.policy_engine.load_policy()

        except Exception:
            logger.exception(
                "AgentGuard policy loading failed."
            )

            return self._block(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "Security policy could not be loaded. "
                    "The action was blocked by fail-closed enforcement."
                ),
                reasons=["POLICY_CONFIGURATION_FAILURE"],
                checks=["FAIL_CLOSED"],
                context=session_context,
            )

        # ----------------------------------------------
        # Unknown tools must never execute.
        # ----------------------------------------------

        try:
            try:
                from .agent_logic import GUARDED_TOOL_REGISTRY
            except ImportError:
                from agent_logic import GUARDED_TOOL_REGISTRY

            registered_tool = GUARDED_TOOL_REGISTRY.get(
                tool_name
            )

        except Exception:
            registered_tool = None

        if registered_tool is None:
            return self._block(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "The proposed tool is not registered "
                    "in the guarded tool registry."
                ),
                reasons=["UNKNOWN_TOOL"],
                checks=["TOOL_ALLOWLIST"],
                context=session_context,
                risk_level=ToolRiskLevel.CRITICAL,
            )

        # ----------------------------------------------
        # Preserve a bounded representation of arguments.
        # ----------------------------------------------

        try:
            serialized_args = json.dumps(
                tool_args,
                ensure_ascii=False,
                allow_nan=False,
                default=lambda _: "[unsupported]",
            )
        except Exception:
            return self._block(
                tool_name=tool_name,
                args={},
                reason="Tool arguments could not be serialized safely.",
                reasons=["INVALID_TOOL_ARGUMENTS"],
                checks=["ARGUMENT_VALIDATION"],
                context=session_context,
            )

        if len(serialized_args) > 100_000:
            return self._block(
                tool_name=tool_name,
                args={},
                reason="Tool arguments exceed the permitted size.",
                reasons=["ARGUMENT_SIZE_LIMIT"],
                checks=["INPUT_LIMIT"],
                context=session_context,
            )

        checks: List[str] = [
            "POLICY_LOADED",
            "TOOL_REGISTRY_CHECK",
            "ARGUMENT_SIZE_CHECK",
        ]

        reasons: List[str] = []

        # ----------------------------------------------
        # Determine whether the context is untrusted.
        # ----------------------------------------------

        is_tainted = session_context.has_untrusted_content

        provenance_source = (
            session_context.provenance_label
        )

        # ----------------------------------------------
        # Prompt-injection checks.
        # ----------------------------------------------

        argument_detection = PromptInjectionDetector.detect(
            serialized_args
        )

        injection_detected = bool(
            detected_injection_text
            and str(detected_injection_text).strip()
        )

        if argument_detection.is_injection:
            injection_detected = True
            reasons.extend(
                argument_detection.reasons
            )

        if injection_detected:
            return self._block(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "Prompt-injection indicators were detected. "
                    "The proposed action cannot proceed."
                ),
                reasons=list(
                    dict.fromkeys(
                        reasons + ["PROMPT_INJECTION_SIGNAL"]
                    )
                ),
                checks=checks + [
                    "PROMPT_INJECTION_CHECK",
                    "INJECTION_BLOCK",
                ],
                context=session_context,
                risk_level=registered_tool.risk_level,
                is_tainted=True,
                provenance_source=provenance_source,
            )

        checks.append("PROMPT_INJECTION_CHECK")

        # ----------------------------------------------
        # Risk classification.
        #
        # The configured policy may raise risk, but it
        # cannot lower the tool's registered risk level.
        # ----------------------------------------------

        configured_risk = _safe_risk(
            policy["tool_risk_levels"].get(
                tool_name,
                policy["defaults"]["unknown_tool_risk"],
            )
        )

        registered_risk = registered_tool.risk_level

        risk_level = (
            configured_risk
            if RISK_ORDER[configured_risk]
            > RISK_ORDER[registered_risk]
            else registered_risk
        )

        checks.append("RISK_CLASSIFICATION")

        # ----------------------------------------------
        # Inspect for sensitive data and bulk requests.
        # ----------------------------------------------

        findings = SensitiveDataDetector.inspect_tool_args(
            tool_args,
            bulk_threshold=policy[
                "defaults"
            ]["bulk_record_threshold"],
        )

        if findings:
            return self._block(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "Sensitive-data or bulk-operation safeguards "
                    "rejected the proposed action."
                ),
                reasons=findings,
                checks=checks + [
                    "SENSITIVE_DATA_CHECK",
                    "SENSITIVE_DATA_BLOCK",
                ],
                context=session_context,
                risk_level=risk_level,
                is_tainted=is_tainted,
                provenance_source=provenance_source,
            )

        checks.append("SENSITIVE_DATA_CHECK")

        # ----------------------------------------------
        # Validate outbound destinations.
        # ----------------------------------------------

        destination_ok, destination_reason = (
            self._validate_destination(
                tool_name=tool_name,
                tool_args=tool_args,
                policy=policy,
            )
        )

        if not destination_ok:
            return self._block(
                tool_name=tool_name,
                args=tool_args,
                reason=destination_reason,
                reasons=["DESTINATION_NOT_ALLOWLISTED"],
                checks=checks + [
                    "DESTINATION_ALLOWLIST",
                    "DESTINATION_BLOCK",
                ],
                context=session_context,
                risk_level=risk_level,
                is_tainted=is_tainted,
                provenance_source=provenance_source,
            )

        checks.append("DESTINATION_ALLOWLIST")

        # ----------------------------------------------
        # Untrusted context policy.
        # ----------------------------------------------

        evaluations = policy["evaluations"]

        if is_tainted:

            if risk_level in {
                ToolRiskLevel.HIGH,
                ToolRiskLevel.CRITICAL,
            }:
                # This invariant is non-negotiable.
                return self._block(
                    tool_name=tool_name,
                    args=tool_args,
                    reason=(
                        "High/critical-risk actions influenced "
                        "by untrusted context are blocked."
                    ),
                    reasons=[
                        "UNTRUSTED_HIGH_CRITICAL_ACTION",
                    ],
                    checks=checks + [
                        "PROVENANCE_CHECK",
                        "UNTRUSTED_CONTEXT_BLOCK",
                    ],
                    context=session_context,
                    risk_level=risk_level,
                    is_tainted=True,
                    provenance_source=provenance_source,
                )

            if risk_level == ToolRiskLevel.MEDIUM:

                if not human_approved:
                    return self._review(
                        tool_name=tool_name,
                        args=tool_args,
                        reason=(
                            "A medium-risk action involving "
                            "untrusted context requires human review."
                        ),
                        reasons=[
                            "UNTRUSTED_MEDIUM_REQUIRES_REVIEW",
                        ],
                        checks=checks + [
                            "PROVENANCE_CHECK",
                            "HUMAN_REVIEW_REQUIRED",
                        ],
                        context=session_context,
                        risk_level=risk_level,
                        is_tainted=True,
                        provenance_source=provenance_source,
                    )

                # Human approval may satisfy medium-risk review,
                # but does not bypass injection, sensitive-data,
                # destination, or tool-registry checks.
                checks.append("HUMAN_APPROVAL_VERIFIED")

                return self._allow(
                    tool_name=tool_name,
                    args=tool_args,
                    reason=(
                        "The medium-risk action passed security "
                        "checks and received human approval."
                    ),
                    reasons=[
                        "HUMAN_APPROVAL_VERIFIED",
                    ],
                    checks=checks + [
                        "PROVENANCE_CHECK",
                        "POLICY_ALLOW",
                    ],
                    context=session_context,
                    risk_level=risk_level,
                    is_tainted=True,
                    provenance_source=provenance_source,
                )

            # Low-risk tools are still restricted to the
            # registered tool set and destination rules.
            low_result = _safe_decision(
                evaluations.get(
                    "untrusted_context_low",
                    "BLOCK",
                )
            )

            if low_result != SecurityDecisionType.ALLOW:
                return self._block(
                    tool_name=tool_name,
                    args=tool_args,
                    reason=(
                        "The configured policy does not allow "
                        "this low-risk action with untrusted context."
                    ),
                    reasons=[
                        "UNTRUSTED_LOW_RISK_POLICY_DENY",
                    ],
                    checks=checks + [
                        "PROVENANCE_CHECK",
                    ],
                    context=session_context,
                    risk_level=risk_level,
                    is_tainted=True,
                    provenance_source=provenance_source,
                )

            return self._allow(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "The registered low-risk action passed "
                    "the untrusted-context policy."
                ),
                reasons=[
                    "UNTRUSTED_LOW_RISK_POLICY",
                ],
                checks=checks + [
                    "PROVENANCE_CHECK",
                    "POLICY_ALLOW",
                ],
                context=session_context,
                risk_level=risk_level,
                is_tainted=True,
                provenance_source=provenance_source,
            )

        # ----------------------------------------------
        # Clean-context policy.
        # ----------------------------------------------

        if risk_level == ToolRiskLevel.CRITICAL:

            if not human_approved:
                return self._review(
                    tool_name=tool_name,
                    args=tool_args,
                    reason=(
                        "Critical-risk actions require explicit "
                        "human approval."
                    ),
                    reasons=[
                        "CRITICAL_ACTION_REQUIRES_HUMAN_REVIEW",
                    ],
                    checks=checks + [
                        "PROVENANCE_CHECK",
                        "CRITICAL_REVIEW_REQUIRED",
                    ],
                    context=session_context,
                    risk_level=risk_level,
                    is_tainted=False,
                    provenance_source=provenance_source,
                )

            return self._allow(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "The critical-risk action passed deterministic "
                    "checks and received human approval."
                ),
                reasons=[
                    "HUMAN_APPROVAL_VERIFIED",
                ],
                checks=checks + [
                    "PROVENANCE_CHECK",
                    "HUMAN_APPROVAL_VERIFIED",
                    "POLICY_ALLOW",
                ],
                context=session_context,
                risk_level=risk_level,
                is_tainted=False,
                provenance_source=provenance_source,
            )

        if risk_level == ToolRiskLevel.HIGH:

            allowlisted_decision = _safe_decision(
                evaluations.get(
                    "untainted_allowlisted",
                    "BLOCK",
                )
            )

            if allowlisted_decision != SecurityDecisionType.ALLOW:
                return self._block(
                    tool_name=tool_name,
                    args=tool_args,
                    reason=(
                        "Policy does not authorize this "
                        "high-risk action."
                    ),
                    reasons=[
                        "HIGH_RISK_POLICY_DENY",
                    ],
                    checks=checks + [
                        "PROVENANCE_CHECK",
                    ],
                    context=session_context,
                    risk_level=risk_level,
                    is_tainted=False,
                    provenance_source=provenance_source,
                )

            return self._allow(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "The high-risk action passed destination "
                    "checks and the configured allowlist policy."
                ),
                reasons=[
                    "HIGH_RISK_ALLOWLISTED_ACTION",
                ],
                checks=checks + [
                    "PROVENANCE_CHECK",
                    "POLICY_ALLOW",
                ],
                context=session_context,
                risk_level=risk_level,
                is_tainted=False,
                provenance_source=provenance_source,
            )

        if risk_level == ToolRiskLevel.MEDIUM:

            if not human_approved:
                return self._review(
                    tool_name=tool_name,
                    args=tool_args,
                    reason=(
                        "The medium-risk action requires "
                        "human approval."
                    ),
                    reasons=[
                        "MEDIUM_RISK_REVIEW_REQUIRED",
                    ],
                    checks=checks + [
                        "PROVENANCE_CHECK",
                        "HUMAN_REVIEW_REQUIRED",
                    ],
                    context=session_context,
                    risk_level=risk_level,
                    is_tainted=False,
                    provenance_source=provenance_source,
                )

            return self._allow(
                tool_name=tool_name,
                args=tool_args,
                reason=(
                    "Medium-risk action passed policy checks "
                    "and received human approval."
                ),
                reasons=[
                    "HUMAN_APPROVAL_VERIFIED",
                ],
                checks=checks + [
                    "PROVENANCE_CHECK",
                    "HUMAN_APPROVAL_VERIFIED",
                ],
                context=session_context,
                risk_level=risk_level,
                is_tainted=False,
                provenance_source=provenance_source,
            )

        # The only currently registered LOW-risk tool is
        # the read-only academic-search demonstration.
        return self._allow(
            tool_name=tool_name,
            args=tool_args,
            reason=(
                "The registered low-risk action passed "
                "deterministic policy checks."
            ),
            reasons=[
                "LOW_RISK_POLICY_ALLOW",
            ],
            checks=checks + [
                "PROVENANCE_CHECK",
                "POLICY_ALLOW",
            ],
            context=session_context,
            risk_level=risk_level,
            is_tainted=False,
            provenance_source=provenance_source,
        )

    # --------------------------------------------------------
    # Destination Validation
    # --------------------------------------------------------

    @staticmethod
    def _validate_destination(
        tool_name: str,
        tool_args: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> tuple[bool, str]:
        """
        Validate email destinations and explicitly supplied URLs.

        An unapproved destination is blocked before tool execution.
        """

        destinations = policy["destinations"]

        if tool_name in EMAIL_TOOL_NAMES:

            target_email = tool_args.get(
                "target_email"
            )

            if (
                not isinstance(target_email, str)
                or not EMAIL_PATTERN.fullmatch(
                    target_email.strip()
                )
            ):
                return (
                    False,
                    "The action has no valid target email address.",
                )

            domain = target_email.rsplit(
                "@",
                1,
            )[1].lower()

            allowed_domains = {
                item.strip().lower()
                for item in destinations[
                    "allowed_email_domains"
                ]
            }

            if domain not in allowed_domains:
                return (
                    False,
                    "The email destination is not allowlisted.",
                )

        # If the tool supplies a network destination, restrict
        # it to configured HTTPS hosts.
        url_fields = (
            "url",
            "endpoint",
            "api_url",
        )

        for field in url_fields:
            value = tool_args.get(field)

            if value is None:
                continue

            if not isinstance(value, str):
                return (
                    False,
                    "The network destination must be a valid URL string.",
                )

            try:
                parsed = urlparse(value)

                if (
                    parsed.scheme.lower() != "https"
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                ):
                    return (
                        False,
                        "Only valid HTTPS destinations without embedded credentials are allowed.",
                    )

                host = parsed.hostname.lower()

            except (ValueError, TypeError):
                return (
                    False,
                    "The network destination could not be validated.",
                )

            allowed_hosts = {
                item.strip().lower()
                for item in destinations[
                    "allowed_api_hosts"
                ]
            }

            if host not in allowed_hosts:
                return (
                    False,
                    "The API destination is not allowlisted.",
                )

        return True, "Destination checks passed."

    # --------------------------------------------------------
    # Decision Builders
    # --------------------------------------------------------

    def _allow(
        self,
        tool_name: str,
        args: Dict[str, Any],
        reason: str,
        reasons: List[str],
        checks: List[str],
        context: SessionContext,
        risk_level: ToolRiskLevel,
        is_tainted: bool,
        provenance_source: str,
    ) -> AgentGuardDecision:

        return self._build_decision(
            decision=SecurityDecisionType.ALLOW,
            tool_name=tool_name,
            args=args,
            reason=reason,
            reasons=reasons,
            checks=checks,
            context=context,
            risk_level=risk_level,
            is_tainted=is_tainted,
            provenance_source=provenance_source,
        )

    def _review(
        self,
        tool_name: str,
        args: Dict[str, Any],
        reason: str,
        reasons: List[str],
        checks: List[str],
        context: SessionContext,
        risk_level: ToolRiskLevel,
        is_tainted: bool,
        provenance_source: str,
    ) -> AgentGuardDecision:

        return self._build_decision(
            decision=SecurityDecisionType.REVIEW,
            tool_name=tool_name,
            args=args,
            reason=reason,
            reasons=reasons,
            checks=checks,
            context=context,
            risk_level=risk_level,
            is_tainted=is_tainted,
            provenance_source=provenance_source,
        )

    def _block(
        self,
        tool_name: str,
        args: Dict[str, Any],
        reason: str,
        reasons: List[str],
        checks: List[str],
        context: Optional[SessionContext] = None,
        risk_level: ToolRiskLevel = ToolRiskLevel.CRITICAL,
        is_tainted: bool = True,
        provenance_source: str = "unknown",
    ) -> AgentGuardDecision:

        return self._build_decision(
            decision=SecurityDecisionType.BLOCK,
            tool_name=tool_name,
            args=args,
            reason=reason,
            reasons=reasons,
            checks=checks,
            context=context,
            risk_level=risk_level,
            is_tainted=is_tainted,
            provenance_source=provenance_source,
        )

    def _build_decision(
        self,
        decision: SecurityDecisionType,
        tool_name: str,
        args: Dict[str, Any],
        reason: str,
        reasons: List[str],
        checks: List[str],
        context: Optional[SessionContext],
        risk_level: ToolRiskLevel,
        is_tainted: bool,
        provenance_source: str,
    ) -> AgentGuardDecision:
        """
        Build consistent, frontend-friendly decisions and lineage.
        """

        safe_args = _safe_lineage_args(
            args
        )

        lineage: List[LineageNode] = []

        if context is not None:
            for index, item in enumerate(
                context.items,
                start=1,
            ):
                lineage.append(
                    LineageNode(
                        id=f"node-source-{index}",
                        type=(
                            "USER_PROMPT"
                            if item.is_trusted
                            else "DOCUMENT"
                        ),
                        label=(
                            f"{index}. Source Context "
                            f"({item.source_type})"
                        ),
                        details=(
                            f"Trusted={item.is_trusted}; "
                            f"characters={len(item.content)}"
                        ),
                        is_tainted=not item.is_trusted,
                    )
                )

        next_index = len(lineage) + 1

        lineage.extend(
            [
                LineageNode(
                    id=f"node-agent-{next_index}",
                    type="AGENT",
                    label=f"{next_index}. Agent Action Proposal",
                    details=(
                        f"The proposed tool '{tool_name}' "
                        "was submitted for evaluation."
                    ),
                    is_tainted=is_tainted,
                ),
                LineageNode(
                    id=f"node-request-{next_index + 1}",
                    type="TOOL_REQUEST",
                    label=f"{next_index + 1}. Tool Request",
                    details=(
                        f"Tool={tool_name}; "
                        f"risk={risk_level.value}; "
                        f"args={safe_args}"
                    ),
                    is_tainted=is_tainted,
                ),
                LineageNode(
                    id=f"node-decision-{next_index + 2}",
                    type="SECURITY_DECISION",
                    label=(
                        f"{next_index + 2}. AgentGuard Decision "
                        f"({decision.value})"
                    ),
                    details=reason,
                    is_tainted=is_tainted,
                ),
            ]
        )

        # Preserve caller-visible fields but never return raw
        # secret-bearing arguments in the lineage.
        return AgentGuardDecision(
            decision=decision,
            verdict=decision.value,
            tool_name=tool_name,
            tool_args=args,
            provenance_source=provenance_source,
            is_tainted=is_tainted,
            risk_level=risk_level,
            reason=reason,
            reasons=reasons,
            checks_fired=checks,
            action_lineage=lineage,
        )


# ============================================================
# 7. Pending Approval Model
# ============================================================

class PendingApproval(BaseModel):
    """
    Representation of a persisted human approval request.

    The action hash binds approval to one exact tool and
    argument combination.
    """

    approval_id: str = Field(
        default_factory=lambda: f"appr-{uuid.uuid4().hex[:12]}"
    )

    tool_name: str

    tool_args: Dict[str, Any]

    args_hash: str = ""

    reason: str

    risk_level: ToolRiskLevel

    provenance_source: str

    created_at: str = Field(
        default_factory=lambda: _utc_now().isoformat()
    )

    status: str = "PENDING"


# ============================================================
# 8. Human Approval Gateway
# ============================================================

class MCPGateway:
    """
    Persistent, hash-bound, single-use approval workflow.

    The public methods are intended for the FastAPI approval
    endpoints and the AgentGuard analysis workflow.
    """

    def __init__(self) -> None:

        self.pending_approvals: Dict[
            str,
            PendingApproval,
        ] = {}

        self._lock = RLock()

        self._sync_from_db()

    # --------------------------------------------------------
    # Refresh Pending Approval Cache
    # --------------------------------------------------------

    def _sync_from_db(self) -> None:

        rows = get_all_pending_approvals()

        refreshed: Dict[
            str,
            PendingApproval,
        ] = {}

        for row in rows:
            try:
                approval = PendingApproval(
                    approval_id=row["approval_id"],
                    tool_name=row["tool_name"],
                    tool_args=row["tool_args"],
                    args_hash=row["args_hash"],
                    reason=row["reason"],
                    risk_level=_safe_risk(
                        row["risk_level"]
                    ),
                    provenance_source=row[
                        "provenance_source"
                    ],
                    created_at=row["created_at"],
                    status=row["status"],
                )

                refreshed[
                    approval.approval_id
                ] = approval

            except Exception:
                # Invalid historical records are never exposed
                # as executable approvals.
                logger.warning(
                    "Skipping malformed approval record."
                )

        with self._lock:
            self.pending_approvals = refreshed

    # --------------------------------------------------------
    # Create a Human Review Request
    # --------------------------------------------------------

    def queue_for_human_review(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        reason: str,
        risk_level: Any,
        provenance_source: str,
    ) -> PendingApproval:
        """
        Save an action that has already received REVIEW.

        This method does not authorize or execute the action.
        """

        if not isinstance(tool_args, dict):
            raise ValueError(
                "Tool arguments must be a JSON object."
            )

        try:
            from .agent_logic import GUARDED_TOOL_REGISTRY
        except ImportError:
            from agent_logic import GUARDED_TOOL_REGISTRY

        if tool_name not in GUARDED_TOOL_REGISTRY:
            raise ValueError(
                "Unknown tools cannot enter the approval queue."
            )

        approval_id = (
            f"appr-{uuid.uuid4().hex[:12]}"
        )

        risk = _safe_risk(
            risk_level
        )

        args_hash = save_pending_approval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            reason=reason,
            risk_level=risk.value,
            provenance_source=provenance_source,
        )

        approval = PendingApproval(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            args_hash=args_hash,
            reason=reason,
            risk_level=risk,
            provenance_source=provenance_source,
        )

        with self._lock:
            self.pending_approvals[
                approval.approval_id
            ] = approval

        return approval

    # --------------------------------------------------------
    # Approve an Exact Action
    # --------------------------------------------------------

    def approve_tool_call(
        self,
        approval_id: str,
        expected_hash: Optional[str] = None,
        canonical_args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process a human approval request.

        Verifies:
        - Approval exists and has not expired.
        - Expected hash is supplied and matches.
        - Any supplied arguments match the original hash.
        - Tool is registered.
        - Approval can be claimed only once.
        - The security gateway re-evaluates the exact action.

        An approval does not bypass policy enforcement.
        """

        self._sync_from_db()

        approval = self.pending_approvals.get(
            approval_id
        )

        if approval is None:
            raise KeyError(
                "Approval ID was not found, expired, "
                "or was already processed."
            )

        if (
            not expected_hash
            or expected_hash != approval.args_hash
        ):
            raise ValueError(
                "ARGUMENT_TAMPERING_REJECTED: "
                "The approval hash is missing or does not match."
            )

        try:
            created_at = datetime.fromisoformat(
                approval.created_at.replace(
                    "Z",
                    "+00:00",
                )
            )

            if created_at.tzinfo is None:
                created_at = created_at.replace(
                    tzinfo=timezone.utc
                )

            expired = (
                _utc_now() - created_at
            ) > timedelta(minutes=10)

        except (ValueError, TypeError, OverflowError):
            expired = True

        if expired:
            update_approval_status(
                approval_id,
                "EXPIRED",
            )

            with self._lock:
                self.pending_approvals.pop(
                    approval_id,
                    None,
                )

            raise ValueError(
                "APPROVAL_EXPIRED: Approval requests "
                "are valid for 10 minutes."
            )

        effective_args = (
            canonical_args
            if canonical_args is not None
            else approval.tool_args
        )

        if not isinstance(effective_args, dict):
            raise ValueError(
                "ARGUMENT_TAMPERING_REJECTED: "
                "Arguments must be a JSON object."
            )

        try:
            computed_hash = compute_canonical_hash(
                approval.tool_name,
                effective_args,
            )
        except Exception as exc:
            raise ValueError(
                "ARGUMENT_TAMPERING_REJECTED: "
                "Arguments could not be canonically serialized."
            ) from exc

        if computed_hash != approval.args_hash:
            raise ValueError(
                "ARGUMENT_TAMPERING_REJECTED: "
                "The action arguments differ from the approved proposal."
            )

        try:
            from .agent_logic import GUARDED_TOOL_REGISTRY
        except ImportError:
            from agent_logic import GUARDED_TOOL_REGISTRY

        tool = GUARDED_TOOL_REGISTRY.get(
            approval.tool_name
        )

        if tool is None:
            raise ValueError(
                "UNKNOWN_TOOL_APPROVAL_REJECTED: "
                "Unregistered tools cannot be executed."
            )

        # Atomically claim the approval before re-evaluation
        # to prevent duplicate processing.
        if not claim_pending_approval(
            approval_id
        ):
            self._sync_from_db()

            raise ValueError(
                "APPROVAL_ALREADY_USED: "
                "This approval is no longer pending."
            )

        try:
            reviewer_context = SessionContext(
                items=[
                    ContextItem(
                        id="human-review",
                        source_type="human_reviewer",
                        content=(
                            "A human reviewer approved this exact "
                            "hash-bound action."
                        ),
                        is_trusted=True,
                    )
                ]
            )

            decision, execution_result = tool.invoke_guarded(
                tool_args=effective_args,
                session_context=reviewer_context,
                detected_injection_text=None,
                human_approved=True,
            )

            allowed = (
                decision.decision
                == SecurityDecisionType.ALLOW
            )

            final_status = (
                "APPROVED"
                if allowed
                else "BLOCKED"
            )

            update_approval_status(
                approval_id,
                final_status,
            )

            log_audit_event(
                approval_id=approval_id,
                tool_name=approval.tool_name,
                tool_args=effective_args,
                decision=(
                    "APPROVED"
                    if allowed
                    else "BLOCKED_BY_POLICY"
                ),
                result=execution_result,
            )

            with self._lock:
                self.pending_approvals.pop(
                    approval_id,
                    None,
                )

            return {
                "approval_id": approval_id,
                "tool_name": approval.tool_name,
                "args": effective_args,
                "decision": (
                    "APPROVED"
                    if allowed
                    else "BLOCKED"
                ),
                "policy_decision": decision.decision.value,
                "result": execution_result,
                "timestamp": _utc_now().isoformat(),
            }

        except Exception:
            # Once claimed, a failed approval attempt must not
            # become available for a second execution attempt.
            try:
                update_approval_status(
                    approval_id,
                    "FAILED",
                )
            except Exception:
                logger.exception(
                    "Could not persist failed approval status."
                )

            with self._lock:
                self.pending_approvals.pop(
                    approval_id,
                    None,
                )

            logger.exception(
                "Approval processing failed."
            )

            raise

    # --------------------------------------------------------
    # Reject a Human Approval Request
    # --------------------------------------------------------

    def reject_tool_call(
        self,
        approval_id: str,
    ) -> Dict[str, Any]:

        self._sync_from_db()

        approval = self.pending_approvals.get(
            approval_id
        )

        if approval is None:
            raise KeyError(
                "Approval ID was not found, expired, "
                "or was already processed."
            )

        if not claim_pending_approval(
            approval_id
        ):
            self._sync_from_db()

            raise ValueError(
                "APPROVAL_ALREADY_USED: "
                "This approval is no longer pending."
            )

        try:
            update_approval_status(
                approval_id,
                "REJECTED",
            )

            result = (
                "The reviewer rejected the action. "
                "No tool was executed."
            )

            log_audit_event(
                approval_id=approval_id,
                tool_name=approval.tool_name,
                tool_args=approval.tool_args,
                decision="REJECTED",
                result=result,
            )

            return {
                "approval_id": approval_id,
                "tool_name": approval.tool_name,
                "args": approval.tool_args,
                "decision": "REJECTED",
                "policy_decision": "BLOCK",
                "result": result,
                "timestamp": _utc_now().isoformat(),
            }

        except Exception:
            try:
                update_approval_status(
                    approval_id,
                    "FAILED",
                )
            except Exception:
                logger.exception(
                    "Could not persist rejection failure."
                )

            raise

        finally:
            with self._lock:
                self.pending_approvals.pop(
                    approval_id,
                    None,
                )

    # --------------------------------------------------------
    # Retrieve Pending Approvals
    # --------------------------------------------------------

    def get_pending_list(
        self,
    ) -> List[PendingApproval]:

        self._sync_from_db()

        return sorted(
            self.pending_approvals.values(),
            key=lambda item: item.created_at,
        )


# ============================================================
# 9. Shared Instances
# ============================================================

policy_engine = PolicyEngine()

security_gateway = SecurityGateway(
    engine=policy_engine
)

mcp_gateway = MCPGateway()


# ============================================================
# 10. Public Module API
# ============================================================

__all__ = [
    "DEFAULT_FALLBACK_POLICY",
    "PolicyConfigurationError",
    "PolicyEngine",
    "SecurityGateway",
    "security_gateway",
    "policy_engine",
    "PendingApproval",
    "MCPGateway",
    "mcp_gateway",
    "AuditLogger",
    "audit_logger",
]