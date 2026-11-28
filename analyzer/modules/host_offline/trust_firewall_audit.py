"""
TIRtcp Host Trust Anchor & Firewall Hardening Audit (TCP-HOST-003 / TCP-NET-002)
Evaluates host_evidence.json security_posture data collected by collector/collect_host.py:
  1. Non-standard / custom Trusted Root CA certificates (TLS MITM / trust-store poisoning risk)
  2. Broad inbound Windows Firewall rules permitting unsolicited connections to the thick client
  3. Cached Windows Credential Manager entries exposing target-related tokens/accounts
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)


def audit_trust_and_firewall(
    host_evidence: Dict[str, Any],
    target_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """Audit host trust store, firewall posture, and cached credential targets."""
    host_refs = mapper.resolve("TCP-HOST-001")
    net_refs = mapper.resolve("TCP-NET-001")
    findings: List[Finding] = []

    posture = host_evidence.get("security_posture") or {}
    custom_cas: List[Dict[str, Any]] = posture.get("custom_root_cas") or []
    fw_rules: List[Dict[str, Any]] = posture.get("firewall_rules") or []
    cred_targets: List[str] = posture.get("credential_targets") or []

    # 1. Custom / Enterprise / Rogue Trusted Root CA Certificates
    if custom_cas:
        subjects = [str(c.get("Subject", "Unknown CA")) for c in custom_cas[:15]]
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title=f"Non-Standard Trusted Root CA Certificate(s) Installed ({len(custom_cas)} Found)",
                category="Host & Trust Hardening",
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                affected_asset="Windows Trusted Root Certification Authorities",
                summary=(
                    f"Detected {len(custom_cas)} custom/non-standard Root CA certificate(s) in the host trust store. "
                    "If unauthorized, these enable transparent TLS interception unless the thick client enforces certificate/SPKI pinning."
                ),
                evidence={
                    "custom_root_ca_count": len(custom_cas),
                    "subjects_sample": subjects,
                },
                remediation=(
                    "Audit all non-standard Root CAs against approved corporate PKI inventory and implement "
                    "SPKI public-key pinning inside the thick client for sensitive API endpoints."
                ),
                compliance_support=net_refs,
            )
        )

    # 2. Overly Permissive Inbound Firewall Rules for Target App
    target_stem = target_path.stem.lower()
    risky_fw: List[Dict[str, Any]] = []
    for rule in fw_rules:
        direction = str(rule.get("Direction", "")).lower()
        action = str(rule.get("Action", "")).lower()
        prog = str(rule.get("Program", "")).lower()
        remote_addr = str(rule.get("RemoteAddress", "Any")).lower()
        if direction == "inbound" and action == "allow":
            if (target_stem and target_stem in prog) or remote_addr in ("any", "*"):
                risky_fw.append(rule)

    if risky_fw:
        findings.append(
            Finding(
                check_id="TCP-HOST-001",
                title=f"Broad Inbound Windows Firewall Rule(s) Associated with Client ({len(risky_fw)} Rule(s))",
                category="Host & Trust Hardening",
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                affected_asset=str(target_path),
                summary=(
                    "Thick client is permitted to accept unsolicited inbound network connections via Windows Firewall, "
                    "increasing remote attack surface if an embedded local HTTP/WebSocket listener binds to 0.0.0.0."
                ),
                evidence={"matching_inbound_rules": risky_fw[:10]},
                remediation="Remove unnecessary inbound firewall rules for client applications and bind local IPC listeners strictly to 127.0.0.1.",
                compliance_support=host_refs,
            )
        )

    # 3. Windows Credential Manager Target Check
    matching_creds = [t for t in cred_targets if target_stem and target_stem in t.lower()]
    if matching_creds:
        findings.append(
            Finding(
                check_id="TCP-HOST-001",
                title="Application Credentials Cached in Windows Credential Manager",
                category="Host & Trust Hardening",
                status=FindingStatus.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset="Windows Credential Manager",
                summary=(
                    f"Found {len(matching_creds)} Windows Credential Manager target(s) matching '{target_path.stem}'. "
                    "Verify credentials are scoped to the current user session and purged upon logout."
                ),
                evidence={"credential_targets": matching_creds[:10]},
                compliance_support=host_refs,
            )
        )

    if posture and not findings:
        findings.append(
            Finding(
                check_id="TCP-HOST-001",
                title="Host Trust Store & Firewall Hardening Checks Passed",
                category="Host & Trust Hardening",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset="Host Security Posture",
                summary="No unauthorized Root CAs or broad inbound client firewall rules detected in host evidence.",
                compliance_support=host_refs,
            )
        )

    return findings
