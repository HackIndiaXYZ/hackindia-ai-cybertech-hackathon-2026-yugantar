"""Bounded, in-memory codebase archive triage for AgentGuard.

The scanner never extracts an uploaded archive to disk. It checks source/config
text with explicit heuristic rules and queries OSV only for exact dependency
versions found in recognized manifests. It is not a full semantic SAST, binary,
malware, runtime, or reachability analysis.
"""
from __future__ import annotations

import io
import json
import re
import tomllib
import zipfile
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET

import yaml

from security_scanner import (
    MAX_MANIFEST_BYTES,
    parse_dependency_manifest,
    query_osv_advisories,
    scan_text,
)

MAX_CODEBASE_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_CODEBASE_ENTRIES = 2000
MAX_CODEBASE_UNPACKED_BYTES = 80 * 1024 * 1024
MAX_SINGLE_SOURCE_BYTES = 1 * 1024 * 1024
MAX_SCANNED_SOURCE_FILES = 1200
MAX_MANIFESTS = 100

_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    ".next", "dist", "build", "coverage", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "vendor", "target", "bin", "obj",
}
_SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".go", ".rs", ".rb", ".php", ".cs", ".c", ".h", ".cpp",
    ".hpp", ".swift", ".kt", ".kts", ".scala", ".sh", ".ps1", ".bat",
    ".yml", ".yaml", ".json", ".toml", ".xml", ".ini", ".conf", ".config",
    ".env", ".properties", ".tf", ".tfvars", ".sql", ".html", ".md",
}
_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
    "yarn.lock", "pyproject.toml", "poetry.lock", "pipfile.lock", "cargo.lock",
    "go.sum", "gemfile.lock", "composer.lock", "pom.xml", "gradle.lockfile",
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _exact_version(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.startswith("=="):
        value = value[2:].strip()
    if re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", value):
        return value.removeprefix("v")
    return None


def _extra_manifest_packages(filename: str, raw: bytes) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Parse lock formats that don't fit the original small-manifest parser."""
    name = PurePosixPath(filename.replace("\\", "/")).name.lower()
    text = raw.decode("utf-8-sig", errors="strict")
    packages: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    skipped: List[Dict[str, str]] = []

    def add(pkg: Any, version: Any, ecosystem: str) -> None:
        if not isinstance(pkg, str) or not isinstance(version, str):
            return
        clean_version = _exact_version(version)
        clean_name = pkg.strip()
        if clean_name and clean_version:
            key = (ecosystem, _norm(clean_name), clean_version)
            packages[key] = {"name": clean_name, "version": clean_version, "ecosystem": ecosystem}
        elif clean_name:
            skipped.append({"package": clean_name[:180], "reason": "Dependency version is not an exact stable version and was not guessed."})

    if name == "poetry.lock":
        obj = tomllib.loads(text)
        for item in obj.get("package", []):
            if isinstance(item, dict): add(item.get("name"), item.get("version"), "PyPI")
    elif name == "pyproject.toml":
        # Only literal exact versions are queried; extras, ranges, VCS and path deps are skipped.
        obj = tomllib.loads(text)
        poetry = obj.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies", "group"):
            node = poetry.get(section, {}) if isinstance(poetry, dict) else {}
            if section == "group" and isinstance(node, dict):
                node = {k: v for group in node.values() if isinstance(group, dict) for k, v in group.get("dependencies", {}).items()}
            if isinstance(node, dict):
                for pkg, spec in node.items():
                    if str(pkg).lower() == "python": continue
                    version = spec if isinstance(spec, str) else spec.get("version") if isinstance(spec, dict) else None
                    if isinstance(version, str) and version.startswith("=="):
                        add(pkg, version[2:], "PyPI")
                    elif version:
                        skipped.append({"package": str(pkg), "reason": "pyproject version is not an exact == pin; use a lockfile for resolved versions."})
    elif name == "pipfile.lock":
        obj = json.loads(text)
        for section in ("default", "develop"):
            values = obj.get(section, {})
            if isinstance(values, dict):
                for pkg, spec in values.items():
                    if isinstance(spec, dict): add(pkg, spec.get("version"), "PyPI")
    elif name == "cargo.lock":
        obj = tomllib.loads(text)
        for item in obj.get("package", []):
            if isinstance(item, dict) and item.get("source", "").startswith("registry+"):
                add(item.get("name"), item.get("version"), "crates.io")
    elif name == "go.sum":
        for line in text.splitlines():
            pieces = line.strip().split()
            if len(pieces) < 2: continue
            module, version = pieces[0], pieces[1].removesuffix("/go.mod")
            if version.startswith("v") and re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                add(module, version[1:], "Go")
    elif name == "gemfile.lock":
        in_specs = False
        for line in text.splitlines():
            if line.strip() == "specs:": in_specs = True; continue
            if in_specs and line and not line.startswith(" ") and not line.startswith("\t"):
                in_specs = False
            if in_specs:
                match = re.match(r"^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
                if match: add(match.group(1), match.group(2), "RubyGems")
    elif name == "composer.lock":
        obj = json.loads(text)
        for section in ("packages", "packages-dev"):
            for item in obj.get(section, []) if isinstance(obj.get(section, []), list) else []:
                if isinstance(item, dict): add(item.get("name"), str(item.get("version", "")).removeprefix("v"), "Packagist")
    elif name == "pom.xml":
        root = ET.fromstring(text)
        def child_text(elem: ET.Element, child_name: str) -> Optional[str]:
            for child in elem:
                if child.tag.rsplit("}", 1)[-1] == child_name:
                    return (child.text or "").strip()
            return None
        for elem in root.iter():
            if elem.tag.rsplit("}", 1)[-1] == "dependency":
                group = child_text(elem, "groupId")
                artifact = child_text(elem, "artifactId")
                version = child_text(elem, "version")
                if group and artifact and version and not version.startswith("${"):
                    add(f"{group}:{artifact}", version, "Maven")
    elif name == "gradle.lockfile":
        for line in text.splitlines():
            match = re.match(r"^([^:#\s]+):([^:#\s]+):([^=\s]+)=", line.strip())
            if match:
                group, artifact, version = match.groups()
                add(f"{group}:{artifact}", version, "Maven")
    elif name.endswith(".csproj"):
        root = ET.fromstring(text)
        for elem in root.iter():
            if elem.tag.rsplit("}", 1)[-1] == "PackageReference":
                pkg = elem.attrib.get("Include") or elem.attrib.get("Update")
                version = elem.attrib.get("Version")
                if not version:
                    for child in elem:
                        if child.tag.rsplit("}", 1)[-1] == "Version": version = (child.text or "").strip()
                if pkg and version: add(pkg, version, "NuGet")
    elif name == "pnpm-lock.yaml":
        obj = yaml.safe_load(text) or {}
        packages_node = obj.get("packages", {})
        if isinstance(packages_node, dict):
            for key in packages_node.keys():
                key = str(key).lstrip("/")
                # pnpm v6/v9 lock keys: package@version or @scope/name@version.
                match = re.match(r"^(@[^/]+/[^@]+|[^@/]+)@([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)", key)
                if match:
                    add(match.group(1), match.group(2), "npm")
    elif name == "yarn.lock":
        current_names: List[str] = []
        current_version: Optional[str] = None
        def flush_yarn() -> None:
            if current_version:
                for pkg in current_names: add(pkg, current_version, "npm")
        for line in text.splitlines() + [""]:
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                flush_yarn()
                current_version = None
                header = line.rstrip().removesuffix(":")
                current_names = []
                # Header can list multiple selector forms separated by comma.
                for raw_selector in re.findall(r'"([^"\n]+)"|([^,]+)', header):
                    selector = (raw_selector[0] or raw_selector[1]).strip()
                    m = re.match(r"^(@[^/]+/[^@]+|[^@]+)@", selector)
                    if m: current_names.append(m.group(1))
            else:
                match = re.match(r'^\s+version\s+["\']([^"\']+)["\']', line)
                if match: current_version = match.group(1)
        flush_yarn()
    else:
        return [], []

    return list(packages.values()), skipped


def _safe_archive_path(raw_name: str) -> Optional[str]:
    name = raw_name.replace("\\", "/")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    if any(part in _SKIP_DIRS for part in path.parts):
        return None
    if name.startswith("/") or "\x00" in name:
        return None
    return str(path)


async def scan_codebase_archive(filename: str, raw: bytes, client=None) -> Dict[str, Any]:
    """Scan ZIP project source text and recognized dependency locks in memory."""
    import time
    if not (filename or "").lower().endswith(".zip"):
        raise ValueError("Upload a .zip archive of the codebase.")
    if not raw or len(raw) > MAX_CODEBASE_ARCHIVE_BYTES:
        raise ValueError("Codebase ZIP must be between 1 byte and 25 MB.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("Uploaded codebase is not a valid ZIP archive.") from exc

    findings: List[Dict[str, Any]] = []
    dependencies: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    skipped_manifests: List[Dict[str, str]] = []
    scanned_source_files = 0
    scanned_bytes = 0
    skipped_source_files = 0
    found_manifests: List[str] = []
    try:
        infos = archive.infolist()
        if len(infos) > MAX_CODEBASE_ENTRIES:
            raise ValueError(f"Archive contains more than {MAX_CODEBASE_ENTRIES} entries.")
        if sum(max(0, item.file_size) for item in infos) > MAX_CODEBASE_UNPACKED_BYTES:
            raise ValueError("Archive expands beyond the 80 MB safety limit.")
        for info in infos:
            if info.is_dir():
                continue
            safe_path = _safe_archive_path(info.filename)
            if safe_path is None:
                skipped_source_files += 1
                continue
            if info.file_size < 0 or info.file_size > max(MAX_SINGLE_SOURCE_BYTES, MAX_MANIFEST_BYTES):
                skipped_source_files += 1
                continue
            suffix = PurePosixPath(safe_path).suffix.lower()
            basename = PurePosixPath(safe_path).name.lower()
            is_requirements = basename.startswith("requirements") and basename.endswith(".txt")
            is_manifest = basename in _MANIFEST_NAMES or is_requirements or basename.endswith(".csproj")
            is_source = suffix in _SOURCE_SUFFIXES and info.file_size <= MAX_SINGLE_SOURCE_BYTES
            if not is_manifest and not is_source:
                continue
            if is_manifest and len(found_manifests) >= MAX_MANIFESTS:
                skipped_manifests.append({"manifest": safe_path, "reason": "Manifest count safety limit reached."})
                continue
            if is_source and scanned_source_files >= MAX_SCANNED_SOURCE_FILES and not is_manifest:
                skipped_source_files += 1
                continue
            try:
                content = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                skipped_source_files += 1
                continue
            scanned_bytes += len(content)
            if scanned_bytes > MAX_CODEBASE_UNPACKED_BYTES:
                raise ValueError("Read content exceeded the archive uncompressed-size limit.")

            if is_manifest:
                found_manifests.append(safe_path)
                try:
                    if basename in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "package.json", "package-lock.json", "npm-shrinkwrap.json"} or (basename.startswith("requirements") and basename.endswith(".txt")):
                        parsed = parse_dependency_manifest(basename, content)
                        parsed_packages, parsed_skipped = parsed["packages"], parsed["skipped"]
                    else:
                        parsed_packages, parsed_skipped = _extra_manifest_packages(basename, content)
                    for package in parsed_packages:
                        key = (package["ecosystem"], _norm(package["name"]), package["version"])
                        dependencies[key] = package
                    for item in parsed_skipped:
                        skipped_manifests.append({"manifest": safe_path, **item})
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError, ET.ParseError) as exc:
                    skipped_manifests.append({"manifest": safe_path, "reason": f"Could not parse this manifest ({type(exc).__name__}); no versions were guessed."})

            if is_source and not (b"\x00" in content[:4096]):
                try:
                    text = content.decode("utf-8-sig", errors="strict")
                except UnicodeDecodeError:
                    skipped_source_files += 1
                    continue
                scanned_source_files += 1
                result = scan_text(text[:200_000], source_name=safe_path)
                for finding in result["findings"]:
                    finding["findingId"] = f"{safe_path}:{finding['findingId']}"
                    finding["findingType"] = "heuristic_source_code_pattern"
                    finding["sourcePath"] = safe_path
                    finding["verified"] = False
                    findings.append(finding)
            elif is_source:
                skipped_source_files += 1
    finally:
        archive.close()

    package_list = list(dependencies.values())
    package_report = await query_osv_advisories(package_list, client=client)
    dependency_findings = package_report.get("findings", []) if isinstance(package_report.get("findings"), list) else []
    severity_counts = {key: 0 for key in ("Critical", "High", "Medium", "Low")}
    for finding in findings:
        sev = finding.get("severity")
        if sev in severity_counts: severity_counts[sev] += 1
    for item in dependency_findings:
        score = item.get("cvssV3BaseScore")
        if isinstance(score, (int, float)):
            sev = "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"
            item["cvssSeverity"] = sev
        else:
            item["cvssSeverity"] = None
    all_findings = findings + dependency_findings
    status = package_report.get("status", "NO_EXACT_VERSIONS")
    overall = "COMPLETED" if status not in {"UNAVAILABLE"} else "PARTIAL"
    if skipped_source_files or skipped_manifests or package_report.get("skipped") or status == "PARTIAL":
        overall = "PARTIAL"
    source_findings_total = len(findings)
    dependency_findings_total = len(dependency_findings)
    # Bound response/history size for archives containing many repeated patterns.
    findings = findings[:250]
    dependency_findings = dependency_findings[:500]
    all_findings = findings + dependency_findings
    return {
        "status": overall,
        "source": "AgentGuard bounded source triage + OSV.dev dependency advisories",
        "sourceName": PurePosixPath(filename).name[:255],
        "archiveBytes": len(raw),
        "archiveEntries": len(infos),
        "sourceFilesScanned": scanned_source_files,
        "sourceBytesScanned": scanned_bytes,
        "skippedFiles": skipped_source_files,
        "manifestCount": len(found_manifests),
        "manifests": found_manifests[:MAX_MANIFESTS],
        "packagesQueried": len(package_list),
        "dependencyStatus": package_report.get("status"),
        "sourceCodeFindings": findings,
        "dependencyFindings": dependency_findings,
        "findings": all_findings,
        "findingCount": source_findings_total + dependency_findings_total,
        "sourceFindingCount": source_findings_total,
        "dependencyFindingCount": dependency_findings_total,
        "sourceFindingsTruncated": source_findings_total > len(findings),
        "dependencyFindingsTruncated": dependency_findings_total > len(dependency_findings),
        "severityCounts": severity_counts,
        "skippedManifests": skipped_manifests[:200],
        "providerError": package_report.get("error"),
        "checkedAt": int(time.time()),
        "limitations": [
            "Source findings are narrow static text-pattern signals; they are not confirmed exploitable vulnerabilities and receive no invented CVSS score.",
            "Dependency advisories come from OSV.dev for exact versions found in supported manifests. A missing advisory does not prove safety.",
            "Binary artifacts, generated/vendor folders, node_modules, virtual environments, and files over per-file limits are skipped.",
            "This is not a semantic SAST engine, malware scanner, reachability analysis, runtime test, or security certification.",
        ],
    }
