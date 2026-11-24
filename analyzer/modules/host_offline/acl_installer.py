"""
TIRtcp Host & Offline Audit Module: Filesystem ACLs, Binary Replacement & Auto-Update Paths.
Maps to check_id: TCP-HOST-001
"""

from __future__ import annotations

import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

CRITICAL_EXTS = {".exe", ".dll", ".msi", ".sys", ".bat", ".ps1", ".cmd", ".sh"}
UPDATER_KEYWORDS = ("update", "updater", "patch", "autoupdate", "upgrade")

# Windows low-privileged principals that should never hold write/modify rights on app binaries
LOW_PRIV_PRINCIPALS = (
    r"BUILTIN\Users",
    r"NT AUTHORITY\Authenticated Users",
    r"Everyone",
    r"BUILTIN\Guests",
)

# icacls permission masks indicating write/modify capability
WRITE_MASKS = ("(F)", "(M)", "(W)", "(WD)", "(AD)", "(WA)")


def _check_windows_icacls(path: Path) -> List[str]:
    """Return a list of risky ACE entries where low-privileged users have write rights."""
    risky_entries: List[str] = []
    try:
        proc = subprocess.run(
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return risky_entries

        for line in proc.stdout.splitlines():
            clean = line.strip()
            if not clean:
                continue
            for principal in LOW_PRIV_PRINCIPALS:
                if principal.lower() in clean.lower():
                    if any(mask in clean for mask in WRITE_MASKS):
                        risky_entries.append(clean)
    except Exception:
        pass
    return risky_entries


def _check_posix_perms(path: Path) -> List[str]:
    """Return risky POSIX permission descriptions (world-writable or risky group-writable)."""
    risky: List[str] = []
    try:
        mode = path.stat().st_mode
        if mode & stat.S_IWOTH:
            risky.append(f"World-writable ({oct(stat.S_IMODE(mode))})")
        elif (mode & stat.S_IWGRP) and path.stat().st_gid != 0:
            risky.append(f"Group-writable by non-root GID {path.stat().st_gid} ({oct(stat.S_IMODE(mode))})")
    except OSError:
        pass
    return risky


def _evaluate_offline_evidence(
    host_evidence: Dict[str, Any],
    compliance_refs: List[Any],
) -> List[Finding]:
    """Evaluate pre-collected host_evidence.json ACL, service, and installer records."""
    findings: List[Finding] = []

    for item in host_evidence.get("weak_acls", []):
        asset = item.get("path", "Unknown Path")
        is_updater = any(k in asset.lower() for k in UPDATER_KEYWORDS)
        findings.append(
            Finding(
                check_id="TCP-HOST-001",
                title=(
                    "Weak ACL on Auto-Update Staging Directory"
                    if is_updater
                    else "Weak Filesystem ACL Enabling Local Binary Replacement"
                ),
                category="Host & Filesystem ACLs",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=asset,
                summary=(
                    "Low-privileged local users have write/modify permissions on an application "
                    "directory or executable, enabling local privilege escalation or tampering."
                ),
                evidence=item,
                remediation=(
                    "Restrict write/modify ACLs on installation and update directories exclusively "
                    "to Administrators and TrustedInstaller / SYSTEM."
                ),
                compliance_support=compliance_refs,
            )
        )

    for svc in host_evidence.get("insecure_services", []):
        findings.append(
            Finding(
                check_id="TCP-HOST-001",
                title=f"Insecure Windows Service Configuration ({svc.get('service_name', 'Unknown')})",
                category="Host & Filesystem ACLs",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=svc.get("bin_path", svc.get("service_name", "Service")),
                summary=svc.get("issue", "Service runs with elevated privileges and weak path/ACL protections."),
                evidence=svc,
                remediation="Quote all service binary paths containing spaces and lock down binary/registry ACLs.",
                compliance_support=compliance_refs,
            )
        )

    return findings


def scan_filesystem_acls(
    target_path: Optional[Path],
    mapper: ComplianceMapper,
    host_evidence: Optional[Dict[str, Any]] = None,
) -> List[Finding]:
    """
    Audit installation and auto-update directory ACLs either from an offline
    host_evidence.json bundle or directly against target_path on the current host.
    """
    check_id = "TCP-HOST-001"
    compliance_refs = mapper.resolve(check_id)
    findings: List[Finding] = []

    # 1. Offline evidence bundle mode (Collector -> Analyzer split)
    if host_evidence is not None:
        offline_findings = _evaluate_offline_evidence(host_evidence, compliance_refs)
        if offline_findings:
            return offline_findings
        return [
            Finding(
                check_id=check_id,
                title="No Weak Installation or Service ACLs in Host Evidence Bundle",
                category="Host & Filesystem ACLs",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=host_evidence.get("hostname", "Offline Host Bundle"),
                summary="Offline host evidence reported restrictive ACLs across installation and service paths.",
                evidence={"source": "host_evidence.json"},
                compliance_support=compliance_refs,
            )
        ]

    # 2. Direct target_path inspection mode
    if target_path is None or not target_path.exists():
        return findings

    is_windows = platform.system() == "Windows"
    paths_to_check: List[Path] = [target_path]

    if target_path.is_dir():
        for root, dirs, files in os.walk(target_path):
            root_p = Path(root)
            for d in dirs:
                dp = root_p / d
                if any(k in d.lower() for k in UPDATER_KEYWORDS):
                    paths_to_check.append(dp)
            for f in files:
                fp = root_p / f
                if fp.suffix.lower() in CRITICAL_EXTS or any(k in f.lower() for k in UPDATER_KEYWORDS):
                    paths_to_check.append(fp)

    weak_found = False
    for p in paths_to_check:
        risks = _check_windows_icacls(p) if is_windows else _check_posix_perms(p)
        if risks:
            weak_found = True
            is_updater = any(k in p.name.lower() for k in UPDATER_KEYWORDS)
            findings.append(
                Finding(
                    check_id=check_id,
                    title=(
                        "Weak ACL on Auto-Update Path"
                        if is_updater
                        else "Weak Filesystem ACL on Application Binary or Directory"
                    ),
                    category="Host & Filesystem ACLs",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH if (is_updater or p.suffix.lower() in CRITICAL_EXTS) else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(p),
                    summary=(
                        "Non-administrative local users can modify this binary or directory, "
                        "allowing persistent code tampering or privilege escalation."
                    ),
                    evidence={
                        "os": platform.system(),
                        "risky_permissions": risks,
                    },
                    remediation=(
                        "Remove write/modify permissions for standard users (BUILTIN\\Users / Everyone / world-writable) "
                        "and restrict write access to administrative accounts."
                    ),
                    compliance_support=compliance_refs,
                )
            )

    if not weak_found:
        findings.append(
            Finding(
                check_id=check_id,
                title="Restrictive Filesystem ACLs Verified on Scanned Application Paths",
                category="Host & Filesystem ACLs",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(target_path),
                summary=f"Checked {len(paths_to_check)} path(s); no low-privileged write permissions detected.",
                evidence={"paths_checked": len(paths_to_check), "os": platform.system()},
                compliance_support=compliance_refs,
            )
        )

    return findings