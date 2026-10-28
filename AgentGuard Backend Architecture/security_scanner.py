"""Evidence-based local security triage and OSV dependency lookup.

This scanner reports only patterns actually present in supplied text or manifests.
It does not infer line/page locations for PDF text, invent CVEs, or claim compliance.
Dependency advisories are queried from OSV and retain their source IDs/URLs.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx

SCANNER_VERSION = "1.0.0"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Patterns are intentionally narrow to reduce false positives. Captured secrets
# are never returned; evidence is redacted before it leaves this module.
_RULES = [
    ("AG-SECRET-PRIVATE-KEY", "Private key material present", "Critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I), "CWE-321"),
    ("AG-SECRET-AWS-ACCESS-ID", "AWS access key identifier pattern", "High", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CWE-798"),
    ("AG-SECRET-GITHUB-TOKEN", "GitHub personal access token pattern", "High", re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"), "CWE-798"),
    ("AG-SECRET-SLACK-TOKEN", "Slack token pattern", "High", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "CWE-798"),
    ("AG-SECRET-STRIPE-SECRET", "Stripe secret-key pattern", "High", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "CWE-798"),
    ("AG-CONFIG-TLS-VERIFY-DISABLED", "TLS certificate verification appears disabled", "High", re.compile(r"(?:verify\s*=\s*False|verify_ssl\s*:\s*false|ssl_verify\s*:\s*false)", re.I), "CWE-295"),
    ("AG-CONFIG-DEBUG-ENABLED", "Debug mode appears enabled", "Medium", re.compile(r"(?:^|[\s,{])(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1)(?:\s|$|[,}#])", re.M), "CWE-489"),
    ("AG-CONFIG-WILDCARD-CORS", "Wildcard CORS origin appears configured", "Medium", re.compile(r"(?:Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\])", re.I), "CWE-942"),
    ("AG-CONFIG-WILDCARD-IAM", "Wildcard IAM action/resource pattern appears present", "High", re.compile(r"(?:\"Action\"\s*:\s*\[?\s*\"\*\"|\"Resource\"\s*:\s*\"\*\")", re.I), "CWE-732"),
    ("AG-CODE-UNSAFE-EVAL", "Dynamic eval/exec call pattern", "High", re.compile(r"\b(?:eval|exec)\s*\("), "CWE-95"),
    ("AG-CODE-UNSAFE-PICKLE", "Python pickle deserialization call pattern", "High", re.compile(r"\bpickle\.(?:load|loads)\s*\("), "CWE-502"),
    ("AG-CODE-SHELL-TRUE", "Subprocess shell=True pattern", "High", re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^\n)]*\bshell\s*=\s*True\b"), "CWE-78"),
    ("AG-CODE-YAML-UNSAFE-LOAD", "Potential unsafe yaml.load call", "Medium", re.compile(r"\byaml\.load\s*\([^\n]*\)(?![^\n]*(?:SafeLoader|CSafeLoader))"), "CWE-502"),
]
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def _redact_line(line: str) -> str:
    # Keep enough context to identify the type of secret without echoing it.
    out = line
    for _, _, _, pattern, _ in _RULES:
        out = pattern.sub("[REDACTED_MATCH]", out)
    out = re.sub(r"(?i)(password|secret|token|api[_-]?key)\s*([:=])\s*([^\s,;]+)", r"\1\2[REDACTED]", out)
    return out[:240]


def scan_text(text: str, source_name: str = "supplied_text") -> Dict[str, Any]:
    """Scan extracted text for narrow secret/configuration patterns.

    Line numbers refer to the text passed to the scanner, not PDF page numbers.
    """
    text = text or ""
    findings: List[Dict[str, Any]] = []
    seen = set()
    lines = text.splitlines() or [text]
    for rule_id, title, severity, pattern, cwe in _RULES:
        for line_no, line in enumerate(lines, start=1):
            match = pattern.search(line)
            if not match:
                continue
            identity = (rule_id, line_no)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append({
                "findingId": f"{rule_id}-{line_no}",
                "ruleId": rule_id,
                "title": title,
                "severity": severity,
                "cwe": cwe,
                "sourceName": source_name[:255],
                "textLine": line_no,
                "evidence": _redact_line(line.strip()),
                "remediation": _remediation(rule_id),
                "findingType": "static_text_pattern",
                "verified": False,
            })
    findings.sort(key=lambda item: (-_SEVERITY_RANK.get(item["severity"], 0), item["textLine"], item["ruleId"]))
    risk = findings[0]["severity"] if findings else None
    return {
        "scannerVersion": SCANNER_VERSION,
        "sourceName": source_name[:255],
        "findings": findings,
        "findingCount": len(findings),
        "riskLevel": risk,
        "checkedAt": int(time.time()),
        "limitations": [
            "Heuristic text-pattern triage; findings require human validation.",
            "Line numbers refer to extracted text and are not PDF page/line locations.",
            "This scan does not run a full CVE database, binary, source-code, or runtime assessment.",
        ],
    }


def _remediation(rule_id: str) -> str:
    mapping = {
        "AG-SECRET-PRIVATE-KEY": "Remove the private key from shared material, rotate it if exposed, and store it in a dedicated secret manager.",
        "AG-SECRET-AWS-ACCESS-ID": "Treat as potentially exposed; rotate/revoke the credential and review provider audit logs. The pattern alone does not prove the matching secret is valid.",
        "AG-SECRET-GITHUB-TOKEN": "Revoke or rotate the token and review repository/account audit events.",
        "AG-SECRET-SLACK-TOKEN": "Revoke or rotate the token and review workspace audit events.",
        "AG-SECRET-STRIPE-SECRET": "Rotate the key in the provider dashboard and review recent API activity.",
        "AG-CONFIG-TLS-VERIFY-DISABLED": "Enable certificate verification and configure the correct trust store rather than bypassing verification.",
        "AG-CONFIG-DEBUG-ENABLED": "Disable debug mode in deployed environments and ensure stack traces/configuration are not exposed.",
        "AG-CONFIG-WILDCARD-CORS": "Restrict origins to explicitly trusted applications and avoid wildcard origins when credentials are used.",
        "AG-CONFIG-WILDCARD-IAM": "Apply least-privilege actions and resource scopes, then validate the effective policy.",
    }
    return mapping.get(rule_id, "Review this finding and validate it against the deployment context.")


_POLICY_CONTROLS: List[Tuple[str, str, re.Pattern[str]]] = [
    ("authentication_and_access_control", "Authentication and access control", re.compile(r"\b(authentication|authorization|access control|least privilege|rbac|mfa|multi.factor)\b", re.I)),
    ("encryption_in_transit", "Encryption in transit", re.compile(r"\b(tls\s*1\.[23]|https|m?tls|encryption in transit)\b", re.I)),
    ("encryption_at_rest", "Encryption at rest", re.compile(r"\b(encryption at rest|encrypted at rest|aes[- ]?256|kms)\b", re.I)),
    ("audit_logging", "Audit logging", re.compile(r"\b(audit log|audit trail|security logging|immutable log)\b", re.I)),
    ("incident_response", "Incident response", re.compile(r"\b(incident response|incident handling|response playbook|breach response)\b", re.I)),
    ("retention_and_deletion", "Retention and deletion", re.compile(r"\b(retention policy|retention period|data deletion|right to erasure|purge data)\b", re.I)),
    ("backup_and_recovery", "Backup and recovery", re.compile(r"\b(backup|disaster recovery|recovery point|recovery time)\b", re.I)),
]


def assess_policy_evidence(text: str) -> Dict[str, Any]:
    """Return document mentions as evidence signals, not compliance verdicts."""
    text = text or ""
    controls = []
    for control_id, label, pattern in _POLICY_CONTROLS:
        match = pattern.search(text)
        if match:
            start, end = match.span()
            excerpt = text[max(0, start - 100):min(len(text), end + 160)].replace("\n", " ").strip()[:260]
            excerpt = _redact_line(excerpt)
            controls.append({"controlId": control_id, "label": label, "status": "evidence_mention_found", "excerpt": excerpt})
        else:
            controls.append({"controlId": control_id, "label": label, "status": "not_found_in_supplied_text", "excerpt": None})
    return {
        "controls": controls,
        "observedCount": sum(c["status"] == "evidence_mention_found" for c in controls),
        "controlCount": len(controls),
        "disclaimer": "Text mentions are not proof of implementation. Missing mentions do not establish non-compliance; this is not a formal audit or certification.",
    }


def _normalise_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def parse_dependency_manifest(filename: str, raw: bytes) -> Dict[str, Any]:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds the 2 MB upload limit.")
    name = (filename or "").replace("\\", "/").split("/")[-1].lower()
    text = raw.decode("utf-8-sig", errors="strict")
    packages: Dict[Tuple[str, str], Dict[str, str]] = {}
    skipped: List[Dict[str, str]] = []

    if (name.startswith("requirements") and name.endswith(".txt")) or name.endswith("requirements.txt"):
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "http:", "https:", "git+")):
                continue
            # Exact pins only are safe to resolve deterministically.
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9_.+!-]*)\s*(?:;.*)?$", line)
            if not match:
                skipped.append({"line": str(line_no), "reason": "Not an exact package==version pin; skipped to avoid guessing installed versions."})
                continue
            pkg, version = match.groups()
            packages[(_normalise_package_name(pkg), version)] = {"name": pkg, "version": version, "ecosystem": "PyPI"}
    elif name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("Manifest is not valid JSON.") from exc
        if name == "package.json":
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = obj.get(section, {})
                if not isinstance(deps, dict):
                    continue
                for pkg, raw_version in deps.items():
                    version = str(raw_version).strip()
                    if re.fullmatch(r"(?:=)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
                        version = version.removeprefix("=")
                        packages[(_normalise_package_name(pkg), version)] = {"name": pkg, "version": version, "ecosystem": "npm"}
                    else:
                        skipped.append({"package": str(pkg), "reason": "package.json version is a range/tag, not an installed exact version; use package-lock.json for accurate results."})
        else:
            lock_version = obj.get("lockfileVersion")
            if not lock_version:
                raise ValueError("package-lock.json is missing lockfileVersion.")
            items = obj.get("packages", {})
            if isinstance(items, dict) and items:
                for path, info in items.items():
                    if not path or "node_modules/" not in path or not isinstance(info, dict):
                        continue
                    pkg_path = path.rsplit("node_modules/", 1)[-1]
                    version = str(info.get("version", "")).strip()
                    if pkg_path and version and re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
                        packages[(_normalise_package_name(pkg_path), version)] = {"name": pkg_path, "version": version, "ecosystem": "npm"}
            else:
                deps = obj.get("dependencies", {})
                if isinstance(deps, dict):
                    def walk(deps_dict: dict):
                        for pkg, info in deps_dict.items():
                            if not isinstance(info, dict):
                                continue
                            version = str(info.get("version", "")).strip()
                            if version and re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
                                packages[(_normalise_package_name(pkg), version)] = {"name": pkg, "version": version, "ecosystem": "npm"}
                            walk(info.get("dependencies", {}))
                    walk(deps)
    else:
        raise ValueError("Supported files are requirements.txt, package.json, package-lock.json, or npm-shrinkwrap.json.")

    if not packages and not skipped:
        raise ValueError("No exact dependency versions were found in the supplied manifest.")
    return {"packages": list(packages.values()), "skipped": skipped, "sourceName": name}


def _cvss_v3_base_score(vector: str) -> Optional[float]:
    """Calculate CVSS v3.0/v3.1 base score from a valid base vector."""
    try:
        parts = vector.split("/")
        if not parts[0].startswith(("CVSS:3.0", "CVSS:3.1")):
            return None
        metrics = {item.split(":", 1)[0]: item.split(":", 1)[1] for item in parts[1:] if ":" in item}
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]]
        ac = {"L": .77, "H": .44}[metrics["AC"]]
        scope = metrics["S"]
        pr_map = {"U": {"N": .85, "L": .62, "H": .27}, "C": {"N": .85, "L": .68, "H": .50}}
        pr = pr_map[scope][metrics["PR"]]
        ui = {"N": .85, "R": .62}[metrics["UI"]]
        impact_coeff = {"N": 0.0, "L": .22, "H": .56}
        c = impact_coeff[metrics["C"]]
        i = impact_coeff[metrics["I"]]
        a = impact_coeff[metrics["A"]]
        isc = 1 - ((1-c) * (1-i) * (1-a))
        if scope == "U":
            impact = 6.42 * isc
        else:
            impact = 7.52 * (isc - .029) - 3.25 * ((isc - .02) ** 15)
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        score = min(impact + exploitability, 10) if scope == "U" else min(1.08 * (impact + exploitability), 10)
        # CVSS Roundup: ceiling to one decimal, not ordinary round().
        return min(10.0, (int(score * 10 + 0.000001) + (0 if abs(score * 10 - int(score * 10)) < 0.000001 else 1)) / 10)
    except (KeyError, ValueError, IndexError):
        return None


async def query_osv_advisories(packages: List[Dict[str, str]], client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Query OSV in bounded batches. Provider/network failures are never treated as clean."""
    if not packages:
        return {"status": "NO_EXACT_VERSIONS", "scannedPackages": [], "findings": [], "skipped": []}
    owns_client = client is None
    active_client = client or httpx.AsyncClient(timeout=15.0, follow_redirects=False)
    scanned: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    failed = False
    try:
        for offset in range(0, len(packages), 100):
            batch = packages[offset:offset + 100]
            queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]} for p in batch]
            try:
                response = await active_client.post(OSV_QUERY_BATCH_URL, json={"queries": queries}, headers={"Accept": "application/json"})
                response.raise_for_status()
                data = response.json()
            except (httpx.HTTPError, ValueError):
                failed = True
                scanned.extend({**p, "status": "lookup_unavailable"} for p in batch)
                continue
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(batch):
                failed = True
                scanned.extend({**p, "status": "invalid_provider_response"} for p in batch)
                continue
            for package, result in zip(batch, results):
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                scanned.append({**package, "status": "advisories_found" if vulns else "no_advisory_returned"})
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    aliases = [a for a in vuln.get("aliases", []) if isinstance(a, str)]
                    cvss_vector = None
                    for severity in vuln.get("severity", []) or []:
                        if isinstance(severity, dict):
                            score_string = str(severity.get("score") or "")
                            if score_string.startswith("CVSS:3.1/"):
                                cvss_vector = score_string
                                break
                    cvss_score = _cvss_v3_base_score(cvss_vector) if cvss_vector else None
                    refs = [r.get("url") for r in vuln.get("references", []) if isinstance(r, dict) and isinstance(r.get("url"), str)]
                    vuln_id = str(vuln.get("id") or "OSV-UNKNOWN")
                    cve_ids = [a for a in aliases if a.startswith("CVE-")]
                    cvss_severity = None
                    if cvss_score is not None:
                        cvss_severity = "None" if cvss_score == 0 else "Low" if cvss_score < 4 else "Medium" if cvss_score < 7 else "High" if cvss_score < 9 else "Critical"
                    findings.append({
                        "findingId": vuln_id, "advisoryId": vuln_id, "aliases": aliases, "cveIds": cve_ids,
                        "package": package["name"], "ecosystem": package["ecosystem"], "installedVersion": package["version"],
                        "summary": str(vuln.get("summary") or vuln.get("details") or "OSV advisory; provider supplied no short summary.")[:1000],
                        "published": vuln.get("published"), "modified": vuln.get("modified"), "cvssVector": cvss_vector,
                        "cvssV3BaseScore": cvss_score, "cvssSeverity": cvss_severity,
                        "severitySource": "CVSS v3.1 base score calculated from OSV-provided vector" if cvss_vector and cvss_score is not None else None,
                        "references": refs[:10], "source": "https://osv.dev/", "verifiedFromProvider": True,
                    })
    finally:
        if owns_client:
            await active_client.aclose()
    if failed:
        return {"status": "PARTIAL" if findings or any(x.get("status") == "no_advisory_returned" for x in scanned) else "UNAVAILABLE",
                "source": "OSV.dev", "scannedPackages": scanned, "findings": findings,
                "error": "OSV could not return a valid response for every batch; unresolved packages are not treated as clean.",
                "checkedAt": int(time.time()), "limitations": ["A missing advisory response is not a clean result.", "Only exact versions are queried."]}
    return {"status": "FINDINGS" if findings else "NO_ADVISORIES_RETURNED", "source": "OSV.dev", "scannedPackages": scanned, "findings": findings, "skipped": [], "checkedAt": int(time.time()), "limitations": ["No returned advisory does not prove that a dependency is secure.", "Only exact versions in the supported manifest formats are queried.", "Advisory database coverage and scoring depend on upstream OSV records."]}


async def scan_dependency_manifest(filename: str, raw: bytes, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    parsed = parse_dependency_manifest(filename, raw)
    report = await query_osv_advisories(parsed["packages"], client=client)
    report["sourceName"] = parsed["sourceName"]
    report["skipped"] = parsed["skipped"]
    if report.get("status") == "NO_ADVISORIES_RETURNED" and parsed["skipped"]:
        report["status"] = "PARTIAL"
    return report

# Structured control evidence assessment. This produces evidence coverage, not a
# legal/regulatory compliance score or certification.
_COMPLIANCE_EVIDENCE_CONTROLS = [
    ("GOV-01", "GOVERN", "Security policy and accountable ownership", re.compile(r"\b(security policy|security owner|accountable security|security governance|risk appetite)\b", re.I)),
    ("GOV-02", "GOVERN", "Third-party and supply-chain risk", re.compile(r"\b(vendor risk|third.party risk|supply.chain risk|supplier assessment|third.party assessment)\b", re.I)),
    ("ID-01", "IDENTIFY", "Asset and software inventory", re.compile(r"\b(asset inventory|software inventory|service inventory|sbom|software bill of materials)\b", re.I)),
    ("ID-02", "IDENTIFY", "Vulnerability management and risk prioritization", re.compile(r"\b(vulnerability management|dependency scanning|cve scanning|risk prioritization|patch management)\b", re.I)),
    ("PR-01", "PROTECT", "Identity, authentication, and access control", re.compile(r"\b(multi.factor|\bmfa\b|authentication|authorization|role.based access|least privilege|access control)\b", re.I)),
    ("PR-02", "PROTECT", "Data protection and encryption", re.compile(r"\b(encryption at rest|encryption in transit|tls 1\.[23]|key management|data classification)\b", re.I)),
    ("PR-03", "PROTECT", "Secure development and input validation", re.compile(r"\b(secure development|secure sdlc|code review|input validation|threat modeling|dependency pinning)\b", re.I)),
    ("DE-01", "DETECT", "Security logging and monitoring", re.compile(r"\b(security logging|audit log|audit trail|centralized logging|security monitoring)\b", re.I)),
    ("DE-02", "DETECT", "Detection and alerting", re.compile(r"\b(alerting|intrusion detection|anomaly detection|security alert|detection rule)\b", re.I)),
    ("RS-01", "RESPOND", "Incident response process", re.compile(r"\b(incident response|incident handling|response playbook|security incident process)\b", re.I)),
    ("RS-02", "RESPOND", "Incident escalation and communications", re.compile(r"\b(escalation path|incident communication|breach notification|incident reporting)\b", re.I)),
    ("RC-01", "RECOVER", "Backups and recovery testing", re.compile(r"\b(backup testing|restore testing|disaster recovery|recovery point objective|recovery time objective)\b", re.I)),
    ("RC-02", "RECOVER", "Continuity and recovery lessons", re.compile(r"\b(business continuity|recovery plan|lessons learned|post.incident review)\b", re.I)),
]


def calculate_cvss_v31(vector: str) -> Dict[str, Any]:
    """Calculate CVSS v3.1 BASE score from a complete, structurally valid base vector.

    Temporal/environmental metrics are rejected here so the returned score has an
    unambiguous meaning. A full environmental score requires additional context.
    """
    import re
    value = (vector or "").strip()
    match = re.fullmatch(
        r"CVSS:3\.1/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R)/S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)",
        value,
    )
    if not match:
        raise ValueError("Provide a complete CVSS:3.1 BASE vector in canonical metric order (AV/AC/PR/UI/S/C/I/A). Temporal and environmental vectors are not accepted by this base-score endpoint.")
    score = _cvss_v3_base_score(value)
    if score is None:
        raise ValueError("The CVSS v3.1 vector could not be scored.")
    severity = "None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"
    return {
        "standard": "CVSS v3.1",
        "scoreType": "base_score",
        "vector": value,
        "baseScore": score,
        "severity": severity,
        "scoreSource": "Calculated from the supplied valid CVSS v3.1 base vector using the FIRST specification equations.",
        "limitations": ["This is a CVSS base score, not a risk score for a specific deployment.", "Environmental and temporal scores are not calculated by this endpoint."],
    }


def assess_compliance_evidence(text: str, framework: str = "nist_csf_2_0") -> Dict[str, Any]:
    """Map supplied evidence text to a controlled checklist with explicit caveats."""
    value = (text or "")[:200_000]
    framework = (framework or "nist_csf_2_0").strip().lower()
    if framework not in {"nist_csf_2_0", "agentguard_baseline_v1"}:
        raise ValueError("framework must be nist_csf_2_0 or agentguard_baseline_v1.")
    controls = []
    for control_id, function, label, pattern in _COMPLIANCE_EVIDENCE_CONTROLS:
        # Explicit gap phrases are distinct from absence of evidence.
        negative_pattern = re.compile(
            r"\b(?:not implemented|not configured|disabled|missing|no process|no policy|not monitored|not enforced|not tested)\b",
            re.I,
        )
        match = pattern.search(value)
        excerpt = None
        status = "not_evidenced"
        if match:
            start, end = match.span()
            excerpt = _redact_line(value[max(0, start - 90):min(len(value), end + 130)].replace("\n", " "))
            surrounding = value[max(0, start - 140):min(len(value), end + 180)]
            status = "explicit_gap" if negative_pattern.search(surrounding) else "evidence_mentioned"
        controls.append({
            "controlId": control_id,
            "function": function,
            "label": label,
            "status": status,
            "evidenceExcerpt": excerpt,
            "evidenceMethod": "keyword_context_match",
        })
    total = len(controls)
    evidenced = sum(item["status"] == "evidence_mentioned" for item in controls)
    explicit_gaps = sum(item["status"] == "explicit_gap" for item in controls)
    not_evidenced = sum(item["status"] == "not_evidenced" for item in controls)
    # Count evidence-only coverage; don't penalize silence as a confirmed violation.
    coverage = round((evidenced / total) * 100, 1) if total else 0.0
    return {
        "status": "COMPLETED",
        "framework": "NIST CSF 2.0-aligned evidence checklist" if framework == "nist_csf_2_0" else "AgentGuard Security Baseline v1",
        "frameworkId": framework,
        "controls": controls,
        "controlCount": total,
        "evidenceMentionedCount": evidenced,
        "explicitGapCount": explicit_gaps,
        "notEvidencedCount": not_evidenced,
        "evidenceCoveragePercent": coverage,
        "scoreType": "documented_evidence_coverage_not_compliance_score",
        "limitations": [
            "This is a deterministic text-evidence checklist, not a formal compliance certification, legal attestation, or audit opinion.",
            "Mentioning a control does not prove it is implemented or effective; explicit gaps require validation.",
            "Not evidenced means the supplied text did not contain a matching signal; it does not establish non-compliance.",
            "NIST CSF 2.0 does not prescribe a single universal percentage score. The percentage shown is AgentGuard's evidence-coverage metric only.",
        ],
    }


_BASELINE_SCORE_VALUES = {
    "implemented": 1.0,
    "partially_implemented": 0.5,
    "not_implemented": 0.0,
    "not_assessed": 0.0,
}
_BASELINE_STATUSES = set(_BASELINE_SCORE_VALUES) | {"not_applicable"}

def get_agentguard_baseline_controls() -> List[Dict[str, str]]:
    """Return the fixed, equal-weight AgentGuard Baseline v1 control list."""
    return [
        {"controlId": control_id, "function": function, "label": label}
        for control_id, function, label, _pattern in _COMPLIANCE_EVIDENCE_CONTROLS
    ]

def score_agentguard_baseline(assessments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Score explicit self-assessed implementation states against a fixed baseline.

    This is a reproducible AgentGuard-defined implementation score, not a NIST,
    ISO, SOC 2, regulatory, or certification score. Every in-scope control has
    equal weight. Unprovided controls default to not_assessed (zero points); N/A
    controls are excluded only when a non-trivial rationale is supplied.
    """
    by_id: Dict[str, Dict[str, Any]] = {}
    known_ids = {item[0] for item in _COMPLIANCE_EVIDENCE_CONTROLS}
    for item in assessments or []:
        if not isinstance(item, dict):
            raise ValueError("Every assessment must be an object.")
        control_id = str(item.get("controlId") or "").strip()
        if control_id not in known_ids:
            raise ValueError(f"Unknown AgentGuard Baseline control: {control_id or '(empty)'}.")
        if control_id in by_id:
            raise ValueError(f"Duplicate assessment for control {control_id}.")
        state = str(item.get("status") or "not_assessed").strip().lower()
        if state not in _BASELINE_STATUSES:
            raise ValueError(f"Invalid status for {control_id}. Allowed statuses: {', '.join(sorted(_BASELINE_STATUSES))}.")
        rationale = _redact_line(str(item.get("rationale") or "").strip()) if item.get("rationale") else ""
        if state == "not_applicable" and len(rationale.strip()) < 10:
            raise ValueError(f"Control {control_id}: provide at least 10 characters of rationale before marking it not applicable.")
        note = _redact_line(str(item.get("evidenceNote") or "").strip()) if item.get("evidenceNote") else ""
        by_id[control_id] = {"status": state, "rationale": rationale[:240], "evidenceNote": note[:240]}

    controls: List[Dict[str, Any]] = []
    points = 0.0
    denominator = 0
    counts = {status: 0 for status in sorted(_BASELINE_STATUSES)}
    for control_id, function, label, _pattern in _COMPLIANCE_EVIDENCE_CONTROLS:
        assessment = by_id.get(control_id, {"status": "not_assessed", "rationale": "", "evidenceNote": ""})
        state = assessment["status"]
        counts[state] += 1
        excluded = state == "not_applicable"
        if not excluded:
            denominator += 1
            points += _BASELINE_SCORE_VALUES[state]
        controls.append({
            "controlId": control_id, "function": function, "label": label,
            "status": state, "pointsEarned": None if excluded else _BASELINE_SCORE_VALUES[state],
            "excludedFromDenominator": excluded,
            "rationale": assessment.get("rationale") or None,
            "evidenceNote": assessment.get("evidenceNote") or None,
        })
    score = round(points / denominator * 100, 1) if denominator else None
    if score is None:
        band = "Not scorable: all controls marked not applicable"
    elif score >= 85:
        band = "Strong self-assessed implementation; validate evidence"
    elif score >= 70:
        band = "Managed implementation; improvement opportunities remain"
    elif score >= 40:
        band = "Partial implementation; material gaps remain"
    else:
        band = "Low self-assessed implementation; significant gaps remain"
    return {
        "status": "SCORED" if score is not None else "NOT_SCORABLE",
        "frameworkId": "agentguard_baseline_v1",
        "framework": "AgentGuard Security Baseline v1 (defined equal-weight checklist)",
        "scoreType": "agentguard_baseline_self_assessed_implementation_score",
        "scorePercent": score, "scoreBand": band,
        "scoringMethod": {
            "implemented": 1.0, "partially_implemented": 0.5,
            "not_implemented": 0.0, "not_assessed": 0.0,
            "not_applicable": "excluded from denominator only with documented rationale",
            "weighting": "equal weight per in-scope control",
        },
        "controlCount": len(controls), "inScopeControlCount": denominator,
        "pointsEarned": round(points, 2), "maximumPoints": denominator,
        "statusCounts": counts, "controls": controls,
        "limitations": [
            "This is an AgentGuard-defined, user-self-assessed implementation score; it is not an official NIST CSF score, compliance certification, legal attestation, or independent audit opinion.",
            "Control status and evidence notes are user supplied and are not independently verified by this scoring function.",
            "NIST CSF 2.0 does not prescribe one universal compliance percentage; use the separate evidence assessment for NIST CSF-aligned text signals.",
            "Not assessed controls receive zero points. Not-applicable controls are excluded only when a rationale is provided.",
        ],
    }

