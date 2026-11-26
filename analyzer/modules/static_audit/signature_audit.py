"""
TIRtcp Static Audit Module: Code Signing, Timestamping, and Revocation Verification.
Maps to check_id: TCP-BIN-002
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)


def _run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _verify_pe_windows(bin_path: Path, signtool: str) -> Dict[str, Any]:
    """Verify Authenticode signature, chain, timestamp, and revocation via signtool.exe."""
    rc, out, err = _run_cmd([signtool, "verify", "/pa", "/all", "/v", str(bin_path)])
    combined = f"{out}\n{err}"
    sha1_digest = bool(
    re.search(r"(Hash Algorithm:\s*sha1|Digest Algorithm:\s*sha1|1\.3\.14\.3\.2\.26)", combined, re.IGNORECASE)
    )
    has_timestamp = bool(
        re.search(r"(Timestamp Verified|The signature is timestamped)", combined, re.IGNORECASE)
    )
    revocation_issue = bool(
        re.search(r"(revoked|revocation function was unable to check)", combined, re.IGNORECASE)
    )
    untrusted_root = bool(
        re.search(r"(untrusted root|not trusted by the trust provider)", combined, re.IGNORECASE)
    )
    unsigned = bool(
        re.search(r"(No signature found|SignTool Error: No signature)", combined, re.IGNORECASE)
    )

    signer_match = re.search(r"Issued to:\s*(.+)", combined)
    issuer_match = re.search(r"Issued by:\s*(.+)", combined)
    expires_match = re.search(r"Expires:\s*(.+)", combined)

    return {
        "verifier": "signtool",
        "return_code": rc,
        "valid": rc == 0,
        "unsigned": unsigned,
        "has_timestamp": has_timestamp,
        "revocation_warning_or_failure": revocation_issue,
        "untrusted_root": untrusted_root,
        "signer": signer_match.group(1).strip() if signer_match else None,
        "issuer": issuer_match.group(1).strip() if issuer_match else None,
        "expires": expires_match.group(1).strip() if expires_match else None,
        "raw_excerpt": combined.strip()[:1200],
    }


def _verify_pe_osslsigncode(bin_path: Path, osslsigncode: str) -> Dict[str, Any]:
    """Cross-platform PE Authenticode verification via osslsigncode."""
    rc, out, err = _run_cmd([osslsigncode, "verify", "-in", str(bin_path)])
    combined = f"{out}\n{err}"
    sha1_digest = bool(
    re.search(r"(Hash Algorithm:\s*sha1|Digest Algorithm:\s*sha1|1\.3\.14\.3\.2\.26)", combined, re.IGNORECASE)
    )
    unsigned = "No signature found" in combined
    has_timestamp = bool(re.search(r"Timestamp\s*:\s*Verified|CounterSignature", combined, re.I))
    revocation_issue = bool(re.search(r"revoked|CRL", combined, re.I)) and rc != 0
    untrusted_root = bool(re.search(r"self signed|unable to get local issuer", combined, re.I))

    return {
        "verifier": "osslsigncode",
        "return_code": rc,
        "valid": rc == 0,
        "unsigned": unsigned,
        "has_timestamp": has_timestamp,
        "revocation_warning_or_failure": revocation_issue,
        "untrusted_root": untrusted_root,
        "raw_excerpt": combined.strip()[:1200],
    }


def _verify_macos_codesign(bin_path: Path, codesign: str) -> Dict[str, Any]:
    """Verify macOS Mach-O / .app bundle signature and timestamp."""
    rc, out, err = _run_cmd(
        [codesign, "--verify", "--deep", "--strict", "--verbose=2", str(bin_path)]
    )
    combined = f"{out}\n{err}"
    unsigned = "code object is not signed at all" in combined.lower()

    # Check detailed metadata including timestamp
    _, info_out, info_err = _run_cmd([codesign, "-dv", "--verbose=4", str(bin_path)])
    info_combined = f"{info_out}\n{info_err}"
    has_timestamp = "Timestamp=" in info_combined

    return {
        "verifier": "codesign",
        "return_code": rc,
        "valid": rc == 0,
        "unsigned": unsigned,
        "has_timestamp": has_timestamp,
        "revocation_warning_or_failure": "revoked" in combined.lower(),
        "untrusted_root": "not signed by apple" in combined.lower() and rc != 0,
        "raw_excerpt": f"{combined}\n{info_combined}".strip()[:1200],
    }


def _locate_windows_signtool() -> Optional[str]:
    found = shutil.which("signtool") or shutil.which("signtool.exe")
    if found:
        return found
    kits_root = Path(r"C:\Program Files (x86)\Windows Kits\10\bin")
    if kits_root.exists():
        candidates = sorted(kits_root.glob("**/x64/signtool.exe"), reverse=True)
        if candidates:
            return str(candidates[0])
    return None


def scan_code_signatures(
    target_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Validate code signatures, certificate chain trust, timestamps, and revocation status
    on executables, DLLs, and installers.
    """
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as pool:
        future_map = {pool.submit(_verify_single_file, f, signtool, osslsigncode, codesign): f for f in targets}
        for fut in as_completed(future_map):
            res = fut.result()
            if res is not None:
                findings.extend(res)

    check_id = "TCP-BIN-002"
    compliance_refs = mapper.resolve(check_id)
    findings: List[Finding] = []

    signtool = _locate_windows_signtool() if platform.system() == "Windows" else None
    osslsigncode = shutil.which("osslsigncode")
    codesign = shutil.which("codesign") if platform.system() == "Darwin" else None

    pe_exts = {".exe", ".dll", ".msi", ".sys"}
    targets: List[Path] = []
    if target_path.is_file():
        targets.append(target_path)
    elif target_path.is_dir():
        for root, _, files in os.walk(target_path):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in pe_exts or fpath.suffix.lower() == ".dylib":
                    targets.append(fpath)

    if not targets:
        return findings

    for bin_file in targets:
        ext = bin_file.suffix.lower()
        result: Optional[Dict[str, Any]] = None

        if ext in pe_exts:
            if signtool:
                result = _verify_pe_windows(bin_file, signtool)
            elif osslsigncode:
                result = _verify_pe_osslsigncode(bin_file, osslsigncode)
            else:
                findings.append(
                    Finding(
                        check_id=check_id,
                        title="Authenticode Verifier Unavailable",
                        category="Binary Integrity",
                        status=FindingStatus.TOOLING_GAP,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        affected_asset=str(bin_file),
                        summary="Neither 'signtool.exe' (Windows SDK) nor 'osslsigncode' is available on PATH.",
                        evidence={"platform": platform.system()},
                        remediation="Install Windows SDK (signtool.exe) or osslsigncode to verify PE signatures.",
                        compliance_support=compliance_refs,
                    )
                )
                break  # Avoid repeating the same tooling gap per file
        elif ext == ".dylib" and codesign:
            result = _verify_macos_codesign(bin_file, codesign)

        if result is None:
            continue

        # Evaluate verification outcomes
        if result["unsigned"]:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Unsigned Executable or Library Shipped in Client Package",
                    category="Binary Integrity",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH if ext in {".exe", ".msi"} else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_file),
                    summary="Binary lacks a digital signature, preventing OS and updater integrity validation.",
                    evidence=result,
                    remediation=(
                        "Sign all executables, DLLs, and installers using a trusted code-signing "
                        "certificate with an RFC 3161 trusted timestamp."
                    ),
                    compliance_support=compliance_refs,
                )
            )
        elif not result["valid"]:
            sev = Severity.HIGH if result["revocation_warning_or_failure"] else Severity.MEDIUM
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Invalid, Untrusted, or Revoked Code Signature",
                    category="Binary Integrity",
                    status=FindingStatus.FAIL,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_file),
                    summary=(
                        "Digital signature validation failed (broken hash, untrusted/self-signed root, "
                        "expired certificate without timestamp, or certificate revocation)."
                    ),
                    evidence=result,
                    remediation=(
                        "Re-sign the binary with a valid, non-revoked certificate issued by a publicly "
                        "trusted CA and include an RFC 3161 timestamp."
                    ),
                    compliance_support=compliance_refs,
                )
            )
        elif not result["has_timestamp"]:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Valid Code Signature Lacks Trusted Timestamp",
                    category="Binary Integrity",
                    status=FindingStatus.FAIL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_file),
                    summary=(
                        "Binary signature is currently valid, but lacks a cryptographic timestamp; "
                        "signature trust will fail once the signing certificate expires."
                    ),
                    evidence=result,
                    remediation="Include an RFC 3161 timestamp server URL (/tr and /td SHA256) during signing.",
                    compliance_support=compliance_refs,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Valid Code Signature and Trusted Timestamp Verified",
                    category="Binary Integrity",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_file),
                    summary="Binary has a valid digital signature, trusted chain, and valid timestamp.",
                    evidence=result,
                    compliance_support=compliance_refs,
                )
            )

    return findings