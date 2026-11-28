"""Assessment coverage matrix: states, for every module, whether it RAN, was NOT APPLICABLE, or was SKIPPED for lack
of an input - and exactly which input unlocks it. A thin report must never be mistaken for a clean application."""
from __future__ import annotations

from typing import Any, Dict, List

from analyzer.core.schema import Confidence, Finding, FindingStatus, PlaybookRef, Severity


def build_coverage_finding(args: Any, ctx: Any, report: Any, host_evidence: Any, bundles: List[Dict[str, Any]]) -> Finding:
    ids = {f.check_id for f in report.findings}
    pes = [r for r in ctx.files if r.is_pe]
    is_single_file = args.target.is_file()
    rows: List[Dict[str, str]] = []
    

    def row(module: str, state: str, why: str, unlock: str = "") -> None:
        rows.append({"module": module, "state": state, "detail": why, "to_unlock": unlock})

    row("PE profile / Authenticode (offline) / capabilities", "RAN" if pes else "N/A", f"{len(pes)} PE file(s)")
    row("String & endpoint intelligence", "RAN", f"{len(ctx.files)} file(s) inventoried")
    row(".NET intelligence", "RAN" if any(c.startswith("TCP-INTEL-02") for c in ids) else "N/A (no managed assemblies found)", "")
    if bundles:
        row(".NET single-file bundle", "RAN", f"{sum(b['files'] for b in bundles)} embedded file(s) extracted")
    row("Binary hardening / signature chain / secrets / SCA", "RAN", "static")
    if is_single_file:
        row("Config, log, DB-file, sibling-DLL and updater-folder analysis", "LIMITED",
            "Target is a single file; config files, logs, local databases, plug-in DLLs and updater folders were not available.",
            "Point --target at the full installation directory (and the per-user data dirs: %APPDATA%, %LOCALAPPDATA%, %PROGRAMDATA%).")
    row("Electron / ASAR audit", "RAN" if any(c == "TCP-ELEC-001" for c in ids) else "N/A", "no Electron markers" if not any(c == "TCP-ELEC-001" for c in ids) else "")
    row("Filesystem ACL / IPC / COM / services / URI handlers", "RAN" if host_evidence else "SKIPPED", "host evidence supplied" if host_evidence else "No host evidence.",
        "Run collector/collect_host.py on the test machine and pass --evidence host_evidence.json")
    row("DLL search-order hijack (Procmon)", "RAN" if args.procmon_csv else "SKIPPED (static IAT only)", "",
        "Capture with scripts/dynamic_capture.ps1 (or Procmon) and pass --procmon-csv")
    row("Wire protocol / cleartext / TLS version in traffic", "RAN" if args.pcap else "SKIPPED", "",
        "Capture while using the client (pktmon/Wireshark) and pass --pcap")
    row("Active TLS inspection of endpoints", "SKIPPED (no-active-probe)" if args.no_active_probe else ("RAN (scope-gated)" if args.scope_file else "SKIPPED (no --scope-file: nothing is probed by default)"), "",
        "Provide --scope-file listing hosts you are authorised to test")
    row("Post-logout memory retention", "RAN" if (args.memory_dump and args.authorized) else "SKIPPED", "",
        "Take a dump after logout, supply --memory-dump --canary-markers --authorized")
    row("Dynamic behaviour (runtime API hooks, registry/file diffs, updater integrity, pinning, tamper tests)", "NOT AUTOMATED YET",
        "No static tool can observe runtime behaviour.", "Use scripts/dynamic_capture.ps1 + the manual playbooks attached to Observation findings")
    row(
    "Dynamic behaviour (Frida runtime API hooks)",
    "RAN" if (getattr(args, "runtime_hooks", None) and args.authorized) else "SKIPPED",
    "Frida runtime trace supplied" if getattr(args, "runtime_hooks", None) else "No runtime hook trace.",
    "Run scripts/frida_hook_harness.py --authorized and pass --runtime-hooks runtime_hooks.json",
    )
    not_run = [r for r in rows if not r["state"].startswith(("RAN", "N/A"))]
    return Finding(
        check_id="TCP-COV-001", title="Assessment Coverage Matrix (What Was And Was Not Tested)", category="Orchestrator Telemetry",
        status=FindingStatus.OBSERVATION, severity=Severity.INFO if not not_run else Severity.LOW, confidence=Confidence.HIGH,
        affected_asset=str(args.target),
        summary=f"{len([r for r in rows if r['state'].startswith('RAN')])} module(s) ran, {len(not_run)} limited/skipped. A short findings list on a thin input is NOT evidence of a secure application.",
        evidence={"matrix": rows}, remediation="",
        manual_playbook=PlaybookRef("TIRtcp", "Raise coverage", [f"{r['module']}: {r['to_unlock']}" for r in not_run if r["to_unlock"]]))
