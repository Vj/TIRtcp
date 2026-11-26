"""
TIRtcp Static Audit Module: Hybrid Software Composition Analysis (SCA)
Combines Syft SBOM + Trivy/Grype managed package scanning with binary string
version fingerprinting for native C/C++ libraries (OpenSSL, zlib, libcurl, SQLite).
Maps to check_id: TCP-SCA-001
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

MAX_BINARY_BYTES = 50 * 1024 * 1024
NATIVE_EXTS = {".exe", ".dll", ".sys", ".so", ".dylib"}

# ---------------------------------------------------------------------------
# Native C/C++ Library Fingerprints & Baseline Minimum Safe Versions
# Tuple: (Library Name, Regex Pattern, Minimum Maintained/Safe Version Tuple, Advisory Note)
# ---------------------------------------------------------------------------
NATIVE_LIB_SIGNATURES: List[Tuple[str, Pattern[str], Tuple[int, ...], str]] = [
    (
        "OpenSSL",
        re.compile(r"\bOpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b"),
        (3, 0, 15),
        "OpenSSL 1.0.2, 1.1.1, and early 3.0.x branches are EOL or exposed to high-severity CVEs.",
    ),
    (
        "libcurl",
        re.compile(r"\blibcurl/([0-9]+\.[0-9]+\.[0-9]+)\b"),
        (8, 10, 0),
        "Older libcurl releases are affected by SOCKS5 heap overflow (CVE-2023-38545) and HTTP/2 flaws.",
    ),
    (
        "zlib",
        re.compile(r"\b(?:inflate|deflate)\s+([0-9]+\.[0-9]+\.[0-9]+)\s+Copyright 1995-"),
        (1, 3, 1),
        "zlib versions prior to 1.3.1 are affected by memory corruption vulnerabilities (e.g., CVE-2022-37434).",
    ),
    (
        "SQLite",
        re.compile(r"\bSQLite\s+(?:version\s+)?(3\.[0-9]+\.[0-9]+)\b"),
        (3, 46, 0),
        "Outdated embedded SQLite engines expose local client databases to memory safety and FTS5 flaws.",
    ),
    (
        "libexpat",
        re.compile(r"\bexpat_([0-9]+\.[0-9]+\.[0-9]+)\b"),
        (2, 6, 3),
        "Older libexpat XML parsers suffer from integer overflow and billion-laughs DoS vulnerabilities.",
    ),
    (
        "libssh2",
        re.compile(r"\blibssh2/([0-9]+\.[0-9]+\.[0-9]+)\b"),
        (1, 11, 0),
        "Legacy libssh2 builds are vulnerable to out-of-bounds read and key-exchange flaws.",
    ),
]


def _parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Convert '1.1.1k' or '8.10.0' into a comparable integer tuple (1, 1, 1)."""
    numeric_parts = re.findall(r"[0-9]+", ver_str)
    return tuple(int(p) for p in numeric_parts[:4])


def _is_version_outdated(detected: str, minimum_safe: Tuple[int, ...]) -> bool:
    det_tuple = _parse_version_tuple(detected)
    if not det_tuple:
        return False
    # Pad shorter tuples with zeros for fair comparison
    max_len = max(len(det_tuple), len(minimum_safe))
    det_padded = det_tuple + (0,) * (max_len - len(det_tuple))
    min_padded = minimum_safe + (0,) * (max_len - len(minimum_safe))
    return det_padded < min_padded


def _map_trivy_severity(sev_str: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(sev_str.upper(), Severity.INFO)


def _run_cmd(cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


DEFAULT_BASELINES_PATH = Path(__file__).resolve().parents[3] / "config" / "baselines.yaml"


def load_native_baselines(baselines_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = baselines_path or DEFAULT_BASELINES_PATH
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    libs: List[Dict[str, Any]] = []
    for lib_name, cfg in (data.get("native_libraries") or {}).items():
        libs.append(
            {
                "name": lib_name,
                "pattern": re.compile(cfg["pattern"]),
                "severity": Severity.HIGH if cfg.get("severity", "").lower() == "high" else Severity.MEDIUM,
                "advisory": cfg.get("advisory", ""),
                "branches": cfg.get("branches", []),
            }
        )
    return libs


def _evaluate_branch_version(detected: str, branches: List[Dict[str, Any]]) -> Tuple[bool, str, str]:
    """
    Returns (is_vulnerable, baseline_label, status_reason).
    Matches the most specific branch prefix first (e.g., '3.1.' over '3.').
    """
    sorted_branches = sorted(branches, key=lambda b: len(b.get("prefix", "")), reverse=True)
    for br in sorted_branches:
        prefix = br.get("prefix", "")
        if detected.startswith(prefix):
            status = br.get("status", "supported").lower()
            min_safe = br.get("min_safe", "0.0.0")
            min_tuple = _parse_version_tuple(min_safe)
            if status == "eol":
                return True, f"EOL branch ({prefix}x)", f"Release branch {prefix}x is End-of-Life (EOL)."
            if _is_version_outdated(detected, min_tuple):
                return True, min_safe, f"Version {detected} is below branch minimum {min_safe}."
            return False, min_safe, "Supported"
    return False, "unknown", "Unmapped branch"

# ---------------------------------------------------------------------------
# Stage 1: Managed Packages via Syft SBOM + Trivy / Grype
# ---------------------------------------------------------------------------
def _scan_managed_packages(
    target_path: Path,
    compliance_refs: List[Any],
) -> Tuple[List[Finding], bool]:
    """
    Returns (findings, scanner_executed_successfully).
    Prefers Syft SBOM -> Trivy/Grype, or falls back to direct Trivy/Grype fs scan.
    """
    syft_bin = shutil.which("syft")
    trivy_bin = shutil.which("trivy")
    grype_bin = shutil.which("grype")

    if not trivy_bin and not grype_bin:
        return [
            Finding(
                check_id="TCP-SCA-001",
                title="Managed Package Vulnerability Scanner Unavailable",
                category="Supply Chain & Dependencies",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(target_path),
                summary=(
                    "Neither 'trivy' nor 'grype' is installed on PATH; managed dependency CVE scanning "
                    "(JAR, NuGet, npm) was skipped while native DLL string fingerprinting still ran."
                ),
                evidence={
                    "syft_installed": bool(syft_bin),
                    "trivy_installed": False,
                    "grype_installed": False,
                },
                remediation="Install Syft and Trivy (or Grype) to enable SBOM generation and CVE matching.",
                compliance_support=compliance_refs,
            )
        ], False

    findings: List[Finding] = []
    sbom_file: Optional[Path] = None

    try:
        # Generate CycloneDX SBOM first if Syft is available
        if syft_bin:
            tmp = tempfile.NamedTemporaryFile(suffix=".cdx.json", delete=False)
            tmp.close()
            sbom_file = Path(tmp.name)
            rc, _, _ = _run_cmd([syft_bin, str(target_path), "-o", f"cyclonedx-json={sbom_file}"])
            if rc != 0 or not sbom_file.exists() or sbom_file.stat().st_size == 0:
                sbom_file = None

        # Prefer Trivy
        if trivy_bin:
            cmd = (
                [trivy_bin, "sbom", "--format", "json", "--quiet", str(sbom_file)]
                if sbom_file
                else [trivy_bin, "fs", "--format", "json", "--quiet", str(target_path)]
            )
            rc, out, err = _run_cmd(cmd)
            if rc == 0 and out.strip():
                data = json.loads(out)
                for result in data.get("Results", []):
                    artifact_target = result.get("Target", str(target_path))
                    for vuln in result.get("Vulnerabilities", []) or []:
                        cve_id = vuln.get("VulnerabilityID", "UNKNOWN-CVE")
                        pkg_name = vuln.get("PkgName", "unknown-package")
                        installed_ver = vuln.get("InstalledVersion", "unknown")
                        fixed_ver = vuln.get("FixedVersion", "Not specified")
                        sev = _map_trivy_severity(vuln.get("Severity", "MEDIUM"))

                        findings.append(
                            Finding(
                                check_id="TCP-SCA-001",
                                title=f"Vulnerable Dependency: {pkg_name} {installed_ver} ({cve_id})",
                                category="Supply Chain & Dependencies",
                                status=FindingStatus.FAIL,
                                severity=sev,
                                confidence=Confidence.HIGH,
                                affected_asset=f"{target_path} -> {artifact_target}",
                                summary=vuln.get("Title") or vuln.get("Description", "")[:240],
                                evidence={
                                    "scanner": "trivy" + ("+syft" if sbom_file else ""),
                                    "cve_id": cve_id,
                                    "package": pkg_name,
                                    "installed_version": installed_ver,
                                    "fixed_version": fixed_ver,
                                },
                                remediation=f"Upgrade {pkg_name} from {installed_ver} to {fixed_ver}.",
                                compliance_support=compliance_refs,
                            )
                        )
                return findings, True

        # Fallback to Grype
        if grype_bin:
            scan_target = f"sbom:{sbom_file}" if sbom_file else str(target_path)
            rc, out, _ = _run_cmd([grype_bin, scan_target, "-o", "json"])
            if rc == 0 and out.strip():
                data = json.loads(out)
                for match in data.get("matches", []):
                    vuln = match.get("vulnerability", {})
                    art = match.get("artifact", {})
                    cve_id = vuln.get("id", "UNKNOWN-CVE")
                    pkg_name = art.get("name", "unknown-package")
                    installed_ver = art.get("version", "unknown")
                    fixes = vuln.get("fix", {}).get("versions", [])
                    fixed_ver = ", ".join(fixes) if fixes else "Not specified"
                    sev = _map_trivy_severity(vuln.get("severity", "MEDIUM"))

                    findings.append(
                        Finding(
                            check_id="TCP-SCA-001",
                            title=f"Vulnerable Dependency: {pkg_name} {installed_ver} ({cve_id})",
                            category="Supply Chain & Dependencies",
                            status=FindingStatus.FAIL,
                            severity=sev,
                            confidence=Confidence.HIGH,
                            affected_asset=str(target_path),
                            summary=vuln.get("description", "")[:240],
                            evidence={
                                "scanner": "grype" + ("+syft" if sbom_file else ""),
                                "cve_id": cve_id,
                                "package": pkg_name,
                                "installed_version": installed_ver,
                                "fixed_version": fixed_ver,
                            },
                            remediation=f"Upgrade {pkg_name} from {installed_ver} to {fixed_ver}.",
                            compliance_support=compliance_refs,
                        )
                    )
                return findings, True

    finally:
        if sbom_file and sbom_file.exists():
            try:
                sbom_file.unlink()
            except OSError:
                pass

    return findings, False


# ---------------------------------------------------------------------------
# Stage 2: Native C/C++ Binary String & Version Fingerprinting
# ---------------------------------------------------------------------------
def _fingerprint_native_binaries(
    target_path: Path,
    compliance_refs: List[Any],
) -> Tuple[List[Finding], int]:
    """
    Scan native PE/ELF/Mach-O binaries for embedded third-party C/C++ library
    version strings (OpenSSL, libcurl, zlib, SQLite, libexpat, libssh2).
    """
    findings: List[Finding] = []
    binaries_scanned = 0

    candidates: List[Path] = []
    if target_path.is_file():
        candidates.append(target_path)
    elif target_path.is_dir():
        for root, _, fnames in os.walk(target_path):
            for fname in fnames:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in NATIVE_EXTS:
                    candidates.append(fpath)

    for bin_path in candidates:
        try:
            size = bin_path.stat().st_size
            if size == 0 or size > MAX_BINARY_BYTES:
                continue
            raw = bin_path.read_bytes()
        except OSError:
            continue

        binaries_scanned += 1
        ascii_strings = "\n".join(
            m.decode("ascii", errors="ignore") for m in re.findall(rb"[\x20-\x7e]{6,}", raw)
        )

        for lib_name, pattern, min_safe_ver, advisory in NATIVE_LIB_SIGNATURES:
            detected_versions = sorted(set(pattern.findall(ascii_strings)))
            for ver in detected_versions:
                if _is_version_outdated(ver, min_safe_ver):
                    min_ver_str = ".".join(str(x) for x in min_safe_ver)
                    findings.append(
                        Finding(
                            check_id="TCP-SCA-001",
                            title=f"Outdated Native C/C++ Library Embedded: {lib_name} {ver}",
                            category="Supply Chain & Dependencies",
                            status=FindingStatus.FAIL,
                            severity=Severity.HIGH if lib_name in {"OpenSSL", "libcurl"} else Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            affected_asset=str(bin_path),
                            summary=(
                                f"Binary embeds or links against {lib_name} {ver} (below recommended "
                                f"baseline {min_ver_str}). {advisory}"
                            ),
                            evidence={
                                "detection_method": "native_binary_string_fingerprint",
                                "library": lib_name,
                                "detected_version": ver,
                                "minimum_baseline_version": min_ver_str,
                            },
                            remediation=(
                                f"Rebuild or update {bin_path.name} to link against {lib_name} "
                                f"{min_ver_str} or later."
                            ),
                            compliance_support=compliance_refs,
                        )
                    )

    return findings, binaries_scanned


def scan_dependencies_and_native_libs(
    target_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Run hybrid SCA:
    1. Syft SBOM + Trivy/Grype for managed packages (JAR, NuGet, npm)
    2. Native binary version fingerprinting for C/C++ libraries
    """
    compliance_refs = mapper.resolve("TCP-SCA-001")
    all_findings: List[Finding] = []

    managed_findings, managed_ok = _scan_managed_packages(target_path, compliance_refs)
    native_findings, binaries_scanned = _fingerprint_native_binaries(target_path, compliance_refs)

    all_findings.extend(managed_findings)
    all_findings.extend(native_findings)

    # Emit Verified Pass if at least one engine ran cleanly with zero vulnerabilities
    has_vuln_fail = any(f.status == FindingStatus.FAIL for f in all_findings)
    if not has_vuln_fail and (managed_ok or binaries_scanned > 0):
        all_findings.append(
            Finding(
                check_id="TCP-SCA-001",
                title="No Vulnerable Dependencies or Outdated Native Libraries Detected",
                category="Supply Chain & Dependencies",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM if not managed_ok else Confidence.HIGH,
                affected_asset=str(target_path),
                summary=(
                    f"Completed hybrid dependency check (managed_scanner={managed_ok}, "
                    f"native_binaries_fingerprinted={binaries_scanned}) with zero flagged issues."
                ),
                evidence={
                    "managed_scanner_ran": managed_ok,
                    "native_binaries_scanned": binaries_scanned,
                },
                compliance_support=compliance_refs,
            )
        )

    return all_findings