#!/usr/bin/env python3
"""
TIRtcp — Thick Client Penetration Testing & Compliance Scanner
Unified CLI Orchestrator (Phases 1–4)

Architecture:
  - Phase 1: Static Binary Hardening, Code Signatures, Secrets/DB/PDB/Log Leaks, Hybrid SCA, Host ACLs
  - Phase 2: Non-HTTP TLS Probing & Offline PCAP Wire-Protocol Analysis
  - Phase 3: Electron Fuses/ASAR Audit, Static IAT + Procmon DLL Hijack Parser, Offline IPC/COM/URI Audit
  - Phase 4: Authorization-Gated Post-Logout Memory Hygiene Inspection

Usage examples:
  # 1. Standard static & local folder audit (General / DPDP / CWE / ASVS profile)
  python -m analyzer.tirtcp --target "C:\\Program Files\\ClientApp" --engagement-id ENG-2026-01

  # 2. BFSI / Payment thick-client audit (+ PCI DSS v4.0.1 & RBI DPSC) with PCAP & TLS endpoints
  python -m analyzer.tirtcp --target ./ClientApp --compliance bfsi --engagement-id ENG-2026-02 \
      --pcap ./capture.pcap --endpoints api.bank.local:8443

  # 3. Full offline engagement bundle (Windows collector JSON + Procmon CSV + gated memory dump)
  python -m analyzer.tirtcp --target ./ClientApp --evidence ./host_evidence.json \
      --procmon-csv ./procmon.csv --memory-dump ./post_logout.dmp \
      --canary-markers "CanaryPass#2026" --authorized --engagement-id ENG-2026-03
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    ScanReport,
    Severity,
)
from analyzer.modules.host_offline.acl_installer import scan_filesystem_acls
from analyzer.modules.host_offline.dll_hijack_parser import parse_procmon_csv
from analyzer.modules.host_offline.ipc_uri_audit import audit_ipc_and_handlers
from analyzer.modules.network_protocol.pcap_analyzer import analyze_pcap_capture
from analyzer.modules.network_protocol.tls_inspector import inspect_tls_endpoints
from analyzer.modules.runtime_gated.memory_retention import analyze_post_logout_memory
from analyzer.modules.static_audit.binary_hardening import scan_binary_hardening
from analyzer.modules.static_audit.electron_unpack import scan_electron_app
from analyzer.modules.static_audit.sca_fingerprint import scan_dependencies_and_native_libs
from analyzer.modules.static_audit.secrets_db_audit import scan_secrets_db_and_debug
from analyzer.modules.static_audit.signature_audit import scan_code_signatures
from analyzer.modules.static_audit.managed_bytecode_audit import scan_managed_bytecode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tirtcp",
        description="TIRtcp: Thick Client Security & Compliance Assessment Orchestrator (Phases 1–4)",
    )

    # Core Target & Governance Arguments
    parser.add_argument(
        "--target",
        type=Path,
        required=True,
        help="Path to thick-client installation directory, executable, DLL, or installer.",
    )
    parser.add_argument(
        "--compliance",
        choices=["general", "bfsi"],
        default="general",
        help=(
            "Compliance scope: 'general' (CWE, ASVS, MASVS, DPDP, CERT-In informational) "
            "or 'bfsi' (+ PCI DSS v4.0.1 & RBI DPSC)."
        ),
    )
    parser.add_argument(
        "--engagement-id",
        type=str,
        default="UNASSIGNED-ENGAGEMENT",
        help="Engagement or audit reference ID logged in report headers and SARIF invocations.",
    )
    parser.add_argument(
        "--operator",
        type=str,
        default=None,
        help="Optional operator identifier for authorization audit logs.",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Explicit authorization flag required to unlock Phase 4 runtime/memory modules.",
    )

    # Phase 2: Network & Protocol Inputs
    parser.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="Optional path to offline PCAP/PCAPNG capture for wire-protocol & cleartext inspection.",
    )
    parser.add_argument(
        "--endpoints",
        nargs="*",
        default=[],
        help="Optional explicit host:port endpoints for non-HTTP TLS probing (e.g., broker.corp:8443).",
    )

    # Phase 3: Offline Host Collector & Procmon Inputs
    parser.add_argument(
        "--evidence",
        type=Path,
        default=None,
        help="Optional path to offline host_evidence.json produced by collector/collect_host.py.",
    )
    parser.add_argument(
        "--procmon-csv",
        type=Path,
        default=None,
        help="Optional path to exported Process Monitor (Procmon) CSV trace for DLL hijacking checks.",
    )

    # Phase 4: Gated Post-Logout Memory Hygiene Inputs
    parser.add_argument(
        "--memory-dump",
        type=Path,
        default=None,
        help="Optional path to post-logout diagnostic memory dump (.dmp) (requires --authorized).",
    )
    parser.add_argument(
        "--canary-markers",
        nargs="*",
        default=[],
        help="Synthetic QA credentials/tokens used during test login to verify post-logout memory zeroization.",
    )

    # Configuration & Output Paths
    parser.add_argument(
        "--compliance-map",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "config" / "compliance_map.yaml",
        help="Path to versioned compliance_map.yaml.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./reports"),
        help="Output directory for HTML, JSON, and SARIF reports (default: ./reports).",
    )
    return parser.parse_args()


def _run_stage(
    stage_label: str,
    check_id: str,
    target_asset: str,
    runner: Callable[[], List[Finding]],
    report: ScanReport,
) -> None:
    """Execute a scan module safely, converting unexpected runtime exceptions into Tooling Gap findings."""
    print(f"  -> {stage_label}...")
    try:
        results = runner()
        for finding in results:
            report.add_finding(finding)
    except Exception as exc:
        print(f"     [!] Warning in {stage_label}: {exc}", file=sys.stderr)
        report.add_finding(
            Finding(
                check_id=check_id,
                title=f"Module Execution Error ({stage_label})",
                category="Orchestrator Telemetry",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                affected_asset=target_asset,
                summary=f"Stage '{stage_label}' encountered an unexpected error and was isolated: {exc}",
                evidence={"exception_type": type(exc).__name__, "error": str(exc)},
            )
        )


def _validate_inputs(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    """Validate CLI file paths and load optional host_evidence.json before running modules."""
    if not args.target.exists():
        raise FileNotFoundError(f"Target path does not exist: {args.target}")

    if not args.compliance_map.exists():
        raise FileNotFoundError(f"Compliance map not found: {args.compliance_map}")

    if args.pcap is not None and not args.pcap.exists():
        raise FileNotFoundError(f"PCAP file not found: {args.pcap}")

    if args.procmon_csv is not None and not args.procmon_csv.exists():
        raise FileNotFoundError(f"Procmon CSV file not found: {args.procmon_csv}")

    host_evidence: Optional[Dict[str, Any]] = None
    if args.evidence is not None:
        if not args.evidence.exists():
            raise FileNotFoundError(f"Host evidence JSON not found: {args.evidence}")
        try:
            host_evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {args.evidence}: {exc}") from exc

    return host_evidence


def main() -> int:
    args = parse_args()

    try:
        host_evidence = _validate_inputs(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[!] Input Error: {exc}", file=sys.stderr)
        return 1

    mapper = ComplianceMapper(args.compliance_map, profile=args.compliance)

    report = ScanReport(
        target_name=args.target.name,
        engagement_id=args.engagement_id,
        compliance_profile=args.compliance,
        authorized_runtime=args.authorized,
        compliance_last_verified=mapper.last_verified,
    )

    print("=" * 72)
    print(f"TIRtcp Thick-Client Security & Compliance Scanner (v{report.tool_version})")
    print(f"Target Target      : {args.target}")
    print(f"Compliance Profile : {args.compliance.upper()} (Map Verified: {mapper.last_verified})")
    print(f"Engagement ID      : {args.engagement_id}")
    print(f"Runtime Auth Gate  : {'UNLOCKED (--authorized)' if args.authorized else 'LOCKED (Offline/Static Only)'}")
    print("=" * 72)

    # -------------------------------------------------------------------------
    # PHASE 1: Static Binary, Signatures, Secrets/DB/Logs, Hybrid SCA & ACLs
    # -------------------------------------------------------------------------
    print("\n[Phase 1] Static Binary, Secrets, Supply-Chain & Filesystem ACLs")
    _run_stage(
        "Binary exploit mitigations (PE/ELF/Mach-O)",
        "TCP-BIN-001",
        str(args.target),
        lambda: scan_binary_hardening(args.target, mapper),
        report,
    )
    _run_stage(
        "Digital signature, timestamp & revocation verification",
        "TCP-BIN-002",
        str(args.target),
        lambda: scan_code_signatures(args.target, mapper),
        report,
    )
    _run_stage(
        "Embedded DB strings, hardcoded secrets, PDB debug & PII log leaks",
        "TCP-SEC-001",
        str(args.target),
        lambda: scan_secrets_db_and_debug(args.target, mapper),
        report,
    )
    _run_stage(
        "Hybrid SCA (Syft/Trivy/Grype + native C/C++ DLL fingerprinting)",
        "TCP-SCA-001",
        str(args.target),
        lambda: scan_dependencies_and_native_libs(args.target, mapper),
        report,
    )
    _run_stage(
        "Filesystem & auto-update directory ACL audit",
        "TCP-HOST-001",
        str(args.target),
        lambda: scan_filesystem_acls(args.target, mapper, host_evidence=host_evidence),
        report,
    )

    # -------------------------------------------------------------------------
    # PHASE 2: Non-HTTP TLS & Offline PCAP Wire-Protocol Inspection
    # -------------------------------------------------------------------------
    print("\n[Phase 2] Network Transport & Wire-Protocol Analysis")
    _run_stage(
        "Non-HTTP TLS version, cipher & certificate inspection",
        "TCP-NET-001",
        str(args.target),
        lambda: inspect_tls_endpoints(args.target, mapper, explicit_endpoints=args.endpoints),
        report,
    )
    if args.pcap is not None:
        _run_stage(
            f"Offline PCAP wire-protocol & cleartext capture audit ({args.pcap.name})",
            "TCP-NET-001",
            str(args.pcap),
            lambda: analyze_pcap_capture(args.pcap, mapper),
            report,
        )

    # -------------------------------------------------------------------------
    # PHASE 3: Electron Fuses/ASAR, DLL Search-Order & Offline Host IPC/URI
    # -------------------------------------------------------------------------
    print("\n[Phase 3] Managed Frameworks, DLL Search-Order & Offline IPC/Handlers")
    _run_stage(
        "Electron Fuses, app.asar webPreferences & Chromium baseline audit",
        "TCP-ELEC-001",
        str(args.target),
        lambda: scan_electron_app(args.target, mapper),
        report,
    )
    _run_stage(
        "Static IAT & Procmon DLL search-order hijacking audit",
        "TCP-HOST-002",
        str(args.procmon_csv or args.target),
        lambda: parse_procmon_csv(
            procmon_csv_path=args.procmon_csv if args.procmon_csv else Path(),
            mapper=mapper,
            target_path=args.target,
            host_evidence=host_evidence,
        ),
        report,
    )
    _run_stage(
    ".NET assemblies (UAC manifest, deserialization, DPAPI) & Java JAR bytecode audit",
    "TCP-MGD-001",
    str(args.target),
    lambda: scan_managed_bytecode(args.target, mapper),
    report,
    )
    if host_evidence is not None:
        _run_stage(
            "Offline host Named Pipes, COM/DCOM, SYSTEM tasks & custom URI handlers",
            "TCP-IPC-001",
            str(args.evidence),
            lambda: audit_ipc_and_handlers(host_evidence, mapper),
            report,
        )

    # -------------------------------------------------------------------------
    # PHASE 4: Authorization-Gated Post-Logout Memory Hygiene
    # -------------------------------------------------------------------------
    if args.memory_dump is not None or args.authorized:
        print("\n[Phase 4] Authorization-Gated Runtime Memory Hygiene")
        _run_stage(
            "Post-logout process memory canary & token retention check",
            "TCP-MEM-001",
            str(args.memory_dump or "Runtime Memory Module"),
            lambda: analyze_post_logout_memory(
                dump_path=args.memory_dump,
                mapper=mapper,
                authorized_flag=args.authorized,
                engagement_id=args.engagement_id,
                canary_markers=args.canary_markers,
                operator=args.operator,
            ),
            report,
        )

    # -------------------------------------------------------------------------
    # Report Export & Executive Summary
    # -------------------------------------------------------------------------
    safe_stem = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in args.target.stem)
    written = report.write_outputs(args.output, base_name=f"tirtcp_{safe_stem}")
    counts = report.summary_counts()

    sev_breakdown = {s.value: 0 for s in Severity}
    for f in report.findings:
        if f.status in (FindingStatus.FAIL, FindingStatus.EVIDENCE_OF_RETENTION):
            sev_breakdown[f.severity.value] += 1

    print("\n" + "=" * 72)
    print("TIRtcp Assessment Summary")
    print("-" * 72)
    print(
        f"Status Breakdown   : Fail={counts['Fail']} | Verified Pass={counts['Verified Pass']} | "
        f"Retention Evidence={counts['Evidence of Retention']} | "
        f"Manual Required={counts['Manual Required']} | Tooling Gap={counts['Tooling Gap']}"
    )
    print(
        f"Actionable Severity: Critical={sev_breakdown['Critical']} | High={sev_breakdown['High']} | "
        f"Medium={sev_breakdown['Medium']} | Low={sev_breakdown['Low']} | Info={sev_breakdown['Info']}"
    )
    print("-" * 72)
    print(f"HTML Report        : {written['html'].resolve()}")
    print(f"JSON Findings      : {written['json'].resolve()}")
    print(f"SARIF v2.1.0       : {written['sarif'].resolve()}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())