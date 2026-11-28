"""
TIRtcp Phase 4 Runtime API Hook Trace Analyzer
Consumes runtime_hooks.json emitted by scripts/frida_hook_harness.py.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

WRITABLE_DIR_RE = re.compile(r"(?i)(?:\\users\\|\\appdata\\|\\temp\\|\\programdata\\)")


def analyze_runtime_hooks(
    hooks_json_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    findings: List[Finding] = []
    if not hooks_json_path.exists():
        return findings

    try:
        bundle: Dict[str, Any] = json.loads(hooks_json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [
            Finding(
                check_id="TCP-MEM-001",
                title="Runtime Hook Trace Parse Error",
                category="Runtime Behaviour & Memory",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                affected_asset=str(hooks_json_path),
                summary=f"Failed to parse runtime_hooks.json: {exc}",
            )
        ]

    events: List[Dict[str, Any]] = bundle.get("events", [])
    target_exe = bundle.get("target_exe", str(hooks_json_path))

    # 1. DPAPI without optionalEntropy
    no_entropy = [e for e in events if e.get("category") == "dpapi" and not e.get("has_optional_entropy")]
    if no_entropy:
        findings.append(
            Finding(
                check_id="TCP-MGD-001",
                title="Runtime DPAPI Encryption Invoked Without Optional Entropy",
                category="Runtime Behaviour & Memory",
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                affected_asset=target_exe,
                summary=f"Observed {len(no_entropy)} CryptProtectData() call(s) with pOptionalEntropy=NULL; any process in the same user session can decrypt the blob.",
                evidence={"sample_calls": no_entropy[:10]},
                remediation="Supply application-specific optionalEntropy bytes to CryptProtectData / ProtectedData.Protect.",
                compliance_support=mapper.resolve("TCP-MGD-001"),
            )
        )

    # 2. DLL loaded at runtime from user-writable path
    writable_dlls = sorted(
        {
            e.get("path", "")
            for e in events
            if e.get("category") == "dll_load" and WRITABLE_DIR_RE.search(e.get("path", ""))
        }
    )
    if writable_dlls:
        findings.append(
            Finding(
                check_id="TCP-HOST-002",
                title="Runtime DLL Loaded From User-Writable Directory",
                category="Runtime Behaviour & Memory",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=target_exe,
                summary=f"Process dynamically loaded {len(writable_dlls)} DLL(s) from user-writable paths at runtime.",
                evidence={"writable_dll_loads": writable_dlls[:20]},
                remediation="Load DLLs exclusively from admin-protected directories with LOAD_LIBRARY_SEARCH_SYSTEM32.",
                compliance_support=mapper.resolve("TCP-HOST-002"),
            )
        )

    # 3. Cleartext WinHTTP requests observed at runtime
    cleartext_http = [e for e in events if e.get("category") == "winhttp" and not e.get("tls_enabled")]
    if cleartext_http:
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title="Cleartext HTTP Request Observed via WinHTTP Runtime Hook",
                category="Runtime Behaviour & Memory",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=target_exe,
                summary=f"Intercepted {len(cleartext_http)} WinHttpOpenRequest call(s) without WINHTTP_FLAG_SECURE.",
                evidence={"requests": cleartext_http[:15]},
                remediation="Pass WINHTTP_FLAG_SECURE to WinHttpOpenRequest and enforce HTTPS.",
                compliance_support=mapper.resolve("TCP-NET-001"),
            )
        )

    # 4. TLS chain validation errors observed
    chain_errors = [e for e in events if e.get("category") == "tls_validation" and not e.get("chain_valid")]
    if chain_errors:
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title="TLS Certificate Chain Validation Failure Observed at Runtime",
                category="Runtime Behaviour & Memory",
                status=FindingStatus.OBSERVATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                affected_asset=target_exe,
                summary=f"CertVerifyCertificateChainPolicy returned non-zero errors ({len(chain_errors)} time(s)); confirm the client aborted the connection rather than ignoring the error.",
                evidence={"chain_failures": chain_errors[:10]},
                compliance_support=mapper.resolve("TCP-NET-001"),
            )
        )

    if events and not findings:
        findings.append(
            Finding(
                check_id="TCP-MEM-001",
                title="Runtime API Hook Trace Reviewed With Zero High-Risk Behaviors Flagged",
                category="Runtime Behaviour & Memory",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=target_exe,
                summary=f"Evaluated {len(events)} runtime API hook event(s) with no unencrypted WinHTTP, writable DLL loads, or entropy-less DPAPI calls.",
                evidence={"events_analyzed": len(events)},
                compliance_support=mapper.resolve("TCP-MEM-001"),
            )
        )

    return findings