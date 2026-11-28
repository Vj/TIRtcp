"""
TIRtcp Static Audit Module: Code Signature, Timestamp & Revocation Verification
Maps to check_id: TCP-BIN-002
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    ComplianceRef,
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

SIGNABLE_EXTS = {".exe", ".dll", ".msi", ".sys", ".ocx", ".cab"}


def _collect_signable_targets(target_path: Path) -> List[Path]:
    targets: List[Path] = []
    if target_path.is_file():
        if target_path.suffix.lower() in SIGNABLE_EXTS:
            targets.append(target_path)
    elif target_path.is_dir():
        for root, _, fnames in os.walk(target_path):
            for fname in sorted(fnames):
                fp = Path(root) / fname
                if fp.suffix.lower() in SIGNABLE_EXTS:
                    targets.append(fp)
    return targets


def _verify_pe_windows(bin_path: Path, signtool: str) -> Dict[str, Any]:
    proc = subprocess.run(
        [signtool, "verify", "/pa", "/v", str(bin_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    combined = f"{proc.stdout}\n{proc.stderr}"
    valid = proc.returncode == 0
    has_timestamp = "timestamp" in combined.lower() and "no signature found" not in combined.lower()
    sha1_digest = bool(
        re.search(r"(Hash Algorithm:\s*sha1|Digest Algorithm:\s*sha1|1\.3\.14\.3\.2\.26)", combined, re.IGNORECASE)
    )
    return {
        "verifier": "signtool.exe",
        "valid": valid,
        "has_timestamp": has_timestamp,
        "sha1_digest": sha1_digest,
        "raw_output": combined[:1000],
    }


def _verify_pe_osslsigncode(bin_path: Path, osslsigncode: str) -> Dict[str, Any]:
    proc = subprocess.run(
        [osslsigncode, "verify", "-in", str(bin_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    combined = f"{proc.stdout}\n{proc.stderr}"
    valid = proc.returncode == 0 and "Succeeded" in combined
    has_timestamp = "Timestamp" in combined
    sha1_digest = bool(
        re.search(r"(Message digest algorithm\s*:\s*SHA1|1\.3\.14\.3\.2\.26)", combined, re.IGNORECASE)
    )
    return {
        "verifier": "osslsigncode",
        "valid": valid,
        "has_timestamp": has_timestamp,
        "sha1_digest": sha1_digest,
        "raw_output": combined[:1000],
    }


def _verify_macos_codesign(bin_path: Path, codesign: str) -> Dict[str, Any]:
    proc = subprocess.run(
        [codesign, "--verify", "--deep", "--strict", "--verbose=2", str(bin_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    combined = f"{proc.stdout}\n{proc.stderr}"
    valid = proc.returncode == 0
    return {
        "verifier": "codesign",
        "valid": valid,
        "has_timestamp": "Timestamp=" in combined,
        "sha1_digest": False,
        "raw_output": combined[:1000],
    }


def _verify_single_file(
    bin_path: Path,
    signtool: Optional[str],
    osslsigncode: Optional[str],
    codesign: Optional[str],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    check_id = "TCP-BIN-002"
    res: Optional[Dict[str, Any]] = None

    try:
        if signtool:
            res = _verify_pe_windows(bin_path, signtool)
        elif osslsigncode:
            res = _verify_pe_osslsigncode(bin_path, osslsigncode)
        elif codesign and platform.system() == "Darwin":
            res = _verify_macos_codesign(bin_path, codesign)
    except subprocess.TimeoutExpired:
        return [
            Finding(
                check_id=check_id,
                title=f"Code Signature Verification Timed Out ({bin_path.name})",
                category="Binary & Supply Chain Integrity",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                affected_asset=str(bin_path),
                summary="Signature verifier exceeded 30s timeout.",
                compliance_support=compliance_refs,
            )
        ]

    if res is None:
        return []

    findings: List[Finding] = []
    if not res["valid"]:
        findings.append(
            Finding(
                check_id=check_id,
                title="Unsigned Binary or Invalid Code Signature Chain",
                category="Binary & Supply Chain Integrity",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=str(bin_path),
                summary=f"Executable/library {bin_path.name} failed cryptographic Authenticode/codesign verification.",
                evidence=res,
                remediation="Sign all distributable executables, DLLs, and installers using a trusted code-signing certificate with RFC 3161 timestamping.",
                compliance_support=compliance_refs,
            )
        )
    else:
        if not res["has_timestamp"]:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Valid Code Signature Missing Trusted Timestamp",
                    category="Binary & Supply Chain Integrity",
                    status=FindingStatus.FAIL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_path),
                    summary="Signature lacks a countersignature timestamp and will fail validation once the signing certificate expires.",
                    evidence=res,
                    remediation="Re-sign binaries with an RFC 3161 trusted timestamp server.",
                    compliance_support=compliance_refs,
                )
            )
        if res.get("sha1_digest"):
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Code Signature Uses Deprecated SHA-1 Digest Algorithm",
                    category="Binary & Supply Chain Integrity",
                    status=FindingStatus.FAIL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_path),
                    summary="Authenticode signature uses collision-weak SHA-1 instead of SHA-256.",
                    evidence=res,
                    remediation="Re-sign binaries using SHA-256 (`/fd SHA256` in signtool).",
                    compliance_support=compliance_refs,
                )
            )
        if not findings:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Valid Code Signature & Timestamp Verified",
                    category="Binary & Supply Chain Integrity",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_path),
                    summary=f"Verified cryptographic signature chain and timestamp for {bin_path.name}.",
                    evidence=res,
                    compliance_support=compliance_refs,
                )
            )

    return findings


def scan_code_signatures(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Any = None,
) -> List[Finding]:
    check_id = "TCP-BIN-002"
    compliance_refs = mapper.resolve(check_id)
    targets = _collect_signable_targets(target_path)

    if not targets:
        return []

    signtool = shutil.which("signtool")
    osslsigncode = shutil.which("osslsigncode")
    codesign = shutil.which("codesign")

    if not (signtool or osslsigncode or (codesign and platform.system() == "Darwin")):
        return [
            Finding(
                check_id=check_id,
                title="Authenticode Verifier Unavailable",
                category="Binary & Supply Chain Integrity",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(target_path),
                summary=(
                    f"Found {len(targets)} signable binary/library file(s), but neither 'signtool.exe', "
                    "'osslsigncode', nor macOS 'codesign' was found on PATH."
                ),
                evidence={"signable_files_count": len(targets)},
                remediation="Install Windows SDK (signtool.exe) or osslsigncode to verify code signatures.",
                compliance_support=compliance_refs,
            )
        ]

    findings: List[Finding] = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as pool:
        future_map = {
            pool.submit(_verify_single_file, f, signtool, osslsigncode, codesign, compliance_refs): f
            for f in targets
        }
        for fut in as_completed(future_map):
            findings.extend(fut.result())

    return findings