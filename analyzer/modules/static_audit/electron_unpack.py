"""
TIRtcp Static Audit Module: Electron Application & Fuse Security Auditor
Inspects:
- Electron Fuses binary sentinel flags (RunAsNode, OnlyLoadAppFromAsar, AsarIntegrity, etc.)
- app.asar / unpacked resources for BrowserWindow webPreferences (nodeIntegration,
  contextIsolation, sandbox, webSecurity), <webview> usage, and custom protocol handlers
- Bundled Electron / Chromium baseline version
Maps to check_id: TCP-ELEC-001 (falls back cleanly if not present in compliance_map.yaml)
"""

from __future__ import annotations

import json
import os
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    ComplianceRef,
    ComplianceRelation,
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

# Official @electron/fuses v1 wire sentinel (32-byte ASCII marker)
FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"

# Fuse index order per @electron/fuses specification
FUSE_NAMES: List[Tuple[int, str, str, Severity]] = [
    (
        0,
        "RunAsNode",
        "ELECTRON_RUN_AS_NODE=1 allows arbitrary JS execution signed by the app's binary.",
        Severity.HIGH,
    ),
    (
        1,
        "EnableCookieEncryption",
        "Session cookies on disk are not encrypted using OS credential stores.",
        Severity.MEDIUM,
    ),
    (
        2,
        "EnableNodeOptionsEnvironmentVariable",
        "NODE_OPTIONS environment variable is honored, enabling preload script injection.",
        Severity.HIGH,
    ),
    (
        3,
        "EnableNodeCliInspectArguments",
        "--inspect / --remote-debugging-port CLI flags remain enabled in production builds.",
        Severity.MEDIUM,
    ),
    (
        4,
        "EnableEmbeddedAsarIntegrityValidation",
        "ASAR archive integrity validation is disabled, allowing local archive tampering.",
        Severity.MEDIUM,
    ),
    (
        5,
        "OnlyLoadAppFromAsar",
        "Electron falls back to unpacked app/ directories if app.asar is renamed or bypassed.",
        Severity.MEDIUM,
    ),
    (
        7,
        "GrantFileProtocolExtraPrivileges",
        "file:// pages keep extra privileges (fetch/XHR/storage), widening impact of any local-file XSS.",
        Severity.MEDIUM,
    ),
]

# Expected secure state: "0" = disabled, "1" = enabled
EXPECTED_FUSE_STATE: Dict[str, str] = {
    "RunAsNode": "0",
    "EnableCookieEncryption": "1",
    "EnableNodeOptionsEnvironmentVariable": "0",
    "EnableNodeCliInspectArguments": "0",
    "EnableEmbeddedAsarIntegrityValidation": "1",
    "OnlyLoadAppFromAsar": "1",
    "GrantFileProtocolExtraPrivileges": "0",
}

WEBPREF_PATTERNS: List[Tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "nodeIntegration Enabled",
        re.compile(r"\bnodeIntegration\s*:\s*(?:true\b|!0(?![0-9]))"),
        Severity.HIGH,
        "Renderer processes have direct access to Node.js APIs (child_process, fs), escalating XSS to RCE.",
    ),
    (
        "contextIsolation Disabled",
        re.compile(r"\bcontextIsolation\s*:\s*(?:false\b|!1(?![0-9]))"),
        Severity.HIGH,
        "Preload scripts share the global window context with untrusted web content.",
    ),
    (
        "Renderer Sandbox Disabled",
        re.compile(r"\bsandbox\s*:\s*(?:false\b|!1(?![0-9]))"),
        Severity.MEDIUM,
        "Chromium OS-level renderer sandboxing is explicitly disabled.",
    ),
    (
        "webSecurity (Same-Origin Policy) Disabled",
        re.compile(r"\bwebSecurity\s*:\s*(?:false\b|!1(?![0-9]))"),
        Severity.HIGH,
        "Disables Same-Origin Policy and allows mixed-content loading.",
    ),
    (
        "allowRunningInsecureContent Enabled",
        re.compile(r"\ballowRunningInsecureContent\s*:\s*(?:true\b|!0(?![0-9]))"),
        Severity.MEDIUM,
        "Allows HTTPS pages to load scripts and stylesheets over plaintext HTTP.",
    ),
    (
        "webviewTag Enabled or <webview> Embedded",
        re.compile(r"(?:\bwebviewTag\s*:\s*(?:true\b|!0(?![0-9]))|<webview\b)", re.IGNORECASE),
        Severity.MEDIUM,
        "<webview> tags run outside standard frame isolation and require strict navigation guards.",
    ),
]

CUSTOM_PROTOCOL_RE = re.compile(
    r"\b(?:protocol\.register(?:File|String|Buffer|Stream|Http)Protocol|app\.setAsDefaultProtocolClient)\s*\(\s*['\"]([^'\"]+)['\"]"
)
ELECTRON_VER_RE = re.compile(r"\bElectron/([0-9]+\.[0-9]+\.[0-9]+)\b")
MIN_SAFE_ELECTRON_MAJOR = 31


def _default_electron_compliance(mapper: ComplianceMapper) -> List[ComplianceRef]:
    refs = mapper.resolve("TCP-ELEC-001")
    if refs:
        return refs
    return [
        ComplianceRef(
            framework="CWE",
            version="4.16",
            control_id="CWE-693 / CWE-749",
            control_title="Protection Mechanism Failure / Exposed Dangerous Method or Function",
            relation=ComplianceRelation.DIRECT,
            scope="general",
        ),
        ComplianceRef(
            framework="OWASP_ASVS",
            version="4.0.3",
            control_id="V14.2.1",
            control_title="Application Hardening and Sandboxing Verification",
            relation=ComplianceRelation.SUPPORTS,
            scope="general",
        ),
    ]


def _inspect_electron_fuses(exe_path: Path) -> Optional[Dict[str, Any]]:
    """Parse the @electron/fuses binary sentinel structure inside the main executable."""
    try:
        data = exe_path.read_bytes()
    except OSError:
        return None

    idx = data.find(FUSE_SENTINEL)
    if idx == -1:
        return None

    # After the 32-byte sentinel: 1 byte fuse schema version, 1 byte fuse count, N ASCII bytes ('0'/'1'/'r')
    header_offset = idx + len(FUSE_SENTINEL)
    if header_offset + 2 >= len(data):
        return None

    fuse_version = data[header_offset]
    fuse_count = data[header_offset + 1]
    raw_states = data[header_offset + 2 : header_offset + 2 + fuse_count].decode("ascii", errors="replace")

    parsed_states: Dict[str, str] = {}
    misconfigured: List[Dict[str, str]] = []

    for f_idx, f_name, desc, sev in FUSE_NAMES:
        if f_idx < len(raw_states):
            state_char = raw_states[f_idx]
            parsed_states[f_name] = state_char
            expected = EXPECTED_FUSE_STATE[f_name]
            if state_char != expected and state_char != "r":
                misconfigured.append(
                    {
                        "fuse": f_name,
                        "current_state": state_char,
                        "recommended_state": expected,
                        "severity": sev.value,
                        "risk": desc,
                    }
                )

    return {
        "binary": str(exe_path),
        "fuse_schema_version": fuse_version,
        "fuse_count": fuse_count,
        "states": parsed_states,
        "misconfigured_fuses": misconfigured,
    }


def _read_asar_text_files(asar_path: Path, max_files: int = 2000) -> List[Tuple[str, str]]:
    """
    Pure-Python ASAR archive reader (Chromium Pickle header + JSON file table)
    extracting .js, .mjs, .cjs, .html, and package.json files without external CLI tools.
    """
    extracted: List[Tuple[str, str]] = []
    try:
        with asar_path.open("rb") as fh:
            header_size_buf = fh.read(16)
            if len(header_size_buf) < 16:
                return extracted
            # ASAR header starts with two uint32 Pickle size fields + uint32 alignment + uint32 json_len
            _, header_size, _, json_len = struct.unpack("<IIII", header_size_buf)
            if json_len == 0 or json_len > 20 * 1024 * 1024:
                return extracted

            raw_json = fh.read(json_len).decode("utf-8", errors="replace")
            header_obj = json.loads(raw_json)
            data_base_offset = 8 + header_size

            def _walk(node: Dict[str, Any], prefix: str) -> None:
                if len(extracted) >= max_files:
                    return
                files_map = node.get("files", {})
                for name, meta in files_map.items():
                    if name == "node_modules":
                        continue  # vendor code must not consume the file budget meant for first-party sources
                    rel = f"{prefix}/{name}" if prefix else name
                    if "files" in meta:
                        _walk(meta, rel)
                    elif "offset" in meta and "size" in meta:
                        ext = Path(name).suffix.lower()
                        if ext in {".js", ".mjs", ".cjs", ".html"} or name == "package.json":
                            size = int(meta["size"])
                            if 0 < size <= 2 * 1024 * 1024:
                                fh.seek(data_base_offset + int(meta["offset"]))
                                content = fh.read(size).decode("utf-8", errors="ignore")
                                extracted.append((rel, content))

            _walk(header_obj, "")
    except Exception:
        pass

    return extracted


def scan_electron_app(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Any = None,
) -> List[Finding]:
    """
    Audit an Electron thick-client directory for Fuses hardening, BrowserWindow
    webPreferences, custom protocol handlers, and bundled Chromium/Electron age.
    """
    check_id = "TCP-ELEC-001"
    compliance_refs = _default_electron_compliance(mapper)
    findings: List[Finding] = []

    if not target_path.exists():
        return findings

    search_root = target_path if target_path.is_dir() else target_path.parent
    asar_files = list(search_root.rglob("app.asar"))
    exe_files = [
        p for p in search_root.glob("*.exe")
        if not p.name.lower().startswith(("unins", "update", "squirrel"))
    ]

    # Detect if this target is actually an Electron app
    is_electron = bool(asar_files) or (search_root / "resources").is_dir()
    if not is_electron:
        return findings

    # 1. Inspect Electron Fuses in primary executables
    for exe in exe_files:
        fuse_res = _inspect_electron_fuses(exe)
        if not fuse_res:
            continue

        misconfigs = fuse_res["misconfigured_fuses"]
        if misconfigs:
            highest_sev = (
                Severity.HIGH
                if any(m["severity"] == "High" for m in misconfigs)
                else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Insecure Electron Fuses Configuration ({len(misconfigs)} Weak Fuse(s))",
                    category="Electron Runtime Hardening",
                    status=FindingStatus.FAIL,
                    severity=highest_sev,
                    confidence=Confidence.HIGH,
                    affected_asset=str(exe),
                    summary=(
                        "Main Electron executable leaves dangerous runtime fuses enabled or integrity "
                        f"fuses disabled: {', '.join(m['fuse'] for m in misconfigs)}."
                    ),
                    evidence=fuse_res,
                    remediation=(
                        "Configure @electron/fuses during packaging to disable RunAsNode, "
                        "EnableNodeOptionsEnvironmentVariable, and EnableNodeCliInspectArguments, "
                        "and enable OnlyLoadAppFromAsar and EnableEmbeddedAsarIntegrityValidation."
                    ),
                    compliance_support=compliance_refs,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Electron Fuses Hardened on Main Executable",
                    category="Electron Runtime Hardening",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=str(exe),
                    summary="All evaluated Electron runtime fuses match recommended hardened settings.",
                    evidence=fuse_res,
                    compliance_support=compliance_refs,
                )
            )

        # Check bundled Electron version string inside executable
        try:
            raw_exe = exe.read_bytes()
            ver_match = ELECTRON_VER_RE.search(raw_exe.decode("latin-1", errors="ignore"))
            if ver_match:
                ver_str = ver_match.group(1)
                major = int(ver_str.split(".")[0])
                if major < MIN_SAFE_ELECTRON_MAJOR:
                    findings.append(
                        Finding(
                            check_id=check_id,
                            title=f"Outdated Bundled Electron / Chromium Runtime (v{ver_str})",
                            category="Electron Runtime Hardening",
                            status=FindingStatus.FAIL,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            affected_asset=str(exe),
                            summary=(
                                f"Client ships with Electron {ver_str} (below supported baseline v{MIN_SAFE_ELECTRON_MAJOR}.x), "
                                "exposing the renderer to known Chromium V8/Blink vulnerabilities."
                            ),
                            evidence={"detected_electron_version": ver_str, "minimum_major": MIN_SAFE_ELECTRON_MAJOR},
                            remediation="Upgrade Electron to an actively supported stable release branch.",
                            compliance_support=compliance_refs,
                        )
                    )
        except OSError:
            pass

    # 2. Extract and Audit app.asar Contents
    for asar_path in asar_files:
        sources = _read_asar_text_files(asar_path)
        if not sources:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Unable to Unpack app.asar Archive",
                    category="Electron Runtime Hardening",
                    status=FindingStatus.TOOLING_GAP,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    affected_asset=str(asar_path),
                    summary="ASAR archive header could not be parsed cleanly.",
                    compliance_support=compliance_refs,
                )
            )
            continue

        custom_schemes: List[Dict[str, str]] = []
        webpref_hits = 0

        for rel_path, content in sources:
            # Skip third-party vendor bundles to minimize false positives
            if "node_modules/" in rel_path.replace("\\", "/"):
                continue

            for title, pattern, sev, risk_desc in WEBPREF_PATTERNS:
                if pattern.search(content):
                    webpref_hits += 1
                    findings.append(
                        Finding(
                            check_id=check_id,
                            title=f"Insecure Electron BrowserWindow Configuration: {title}",
                            category="Electron Runtime Hardening",
                            status=FindingStatus.FAIL,
                            severity=sev,
                            confidence=Confidence.HIGH,
                            affected_asset=f"{asar_path} :: {rel_path}",
                            summary=risk_desc,
                            evidence={"internal_file": rel_path, "rule": title},
                            remediation=(
                                "Enforce contextIsolation: true, nodeIntegration: false, sandbox: true, "
                                "and webSecurity: true on all BrowserWindow instances, exposing only minimal "
                                "validated IPC bridges via contextBridge."
                            ),
                            compliance_support=compliance_refs,
                        )
                    )

            for scheme in CUSTOM_PROTOCOL_RE.findall(content):
                custom_schemes.append({"file": rel_path, "scheme": scheme})

        if custom_schemes:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Custom Protocol / Deep-Link Handler Registered in Electron App",
                    category="Electron Runtime Hardening",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(asar_path),
                    summary=(
                        f"Application registers {len(custom_schemes)} custom protocol handler(s). "
                        "Unvalidated protocol parameters can lead to path traversal or arbitrary argument injection."
                    ),
                    evidence={"registered_protocols": custom_schemes[:15]},
                    manual_playbook=PlaybookRef(
                        tool="Frida / Browser Deep-Link Test",
                        objective="Verify strict scheme allowlisting, path normalization, and origin checks on custom protocol handlers.",
                        steps=[
                            "Inspect the protocol callback handler in the unpacked main-process JS file.",
                            "Confirm that file protocol handlers resolve paths with path.resolve() and verify they remain inside an expected base directory.",
                            "Ensure external URLs passed via deep links are validated against an explicit domain allowlist before loading in BrowserWindow.",
                        ],
                    ),
                    compliance_support=compliance_refs,
                )
            )

        if webpref_hits == 0:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="No Insecure BrowserWindow webPreferences Detected in app.asar",
                    category="Electron Runtime Hardening",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    affected_asset=str(asar_path),
                    summary=f"Audited {len(sources)} internal file(s) inside app.asar with no insecure webPreferences matched.",
                    evidence={"files_inspected": len(sources)},
                    compliance_support=compliance_refs,
                )
            )

    return findings

ELECTRON_SOURCE_RULES: List[Tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "Unvalidated shell.openExternal() Call in Electron Main/Preload Script",
        re.compile(r"\bshell\.openExternal\s*\(\s*(?!['\"]https?://)[a-zA-Z0-9_$.]+", re.IGNORECASE),
        Severity.HIGH,
        "Passing unvalidated renderer or deep-link URLs to shell.openExternal() can trigger RCE via file://, smb://, or custom protocol handlers.",
        "Validate URL scheme against an explicit allowlist (https: only) before calling shell.openExternal().",
    ),
    (
        "Over-Broad IPC Bridge Exposed via contextBridge.exposeInMainWorld",
        re.compile(
            r"contextBridge\.exposeInMainWorld\s*\(\s*['\"][^'\"]+['\"]\s*,\s*\{[^}]{0,300}\b(?:ipcRenderer|require|child_process|fs)\b",
            re.DOTALL,
        ),
        Severity.HIGH,
        "Preload script exposes raw ipcRenderer or Node primitives to the renderer context, bypassing contextIsolation.",
        "Expose only narrow, single-purpose wrapper functions in contextBridge rather than raw ipcRenderer or Node modules.",
    ),
    (
        "ipcMain Handler Without Event Sender Frame/Origin Validation",
        re.compile(r"\bipcMain\.(?:handle|on)\s*\(\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        Severity.MEDIUM,
        "IPC handler registered in main process; verify event.senderFrame.url is validated against trusted origins.",
        "Validate event.senderFrame.url inside every ipcMain.handle/on listener before executing privileged actions.",
    ),
]


def _scan_electron_js_sources(
    app_dir: Path,
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    """Scan unpacked Electron main/preload JavaScript files for IPC bridge and openExternal flaws."""
    findings: List[Finding] = []
    if not app_dir.is_dir():
        return findings

    for js_file in app_dir.rglob("*.js"):
        if "node_modules" in js_file.parts or js_file.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            code = js_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for title, rx, sev, summary, remediation in ELECTRON_SOURCE_RULES:
            m = rx.search(code)
            if m:
                line_no = code[: m.start()].count("\n") + 1
                findings.append(
                    Finding(
                        check_id="TCP-ELEC-001",
                        title=title,
                        category="Electron & Chromium Hardening",
                        status=FindingStatus.FAIL if sev == Severity.HIGH else FindingStatus.MANUAL_REQUIRED,
                        severity=sev,
                        confidence=Confidence.MEDIUM,
                        affected_asset=f"{js_file} (line {line_no})",
                        summary=summary,
                        evidence={
                            "file": js_file.name,
                            "line": line_no,
                            "snippet": m.group(0)[:180],
                        },
                        remediation=remediation,
                        compliance_support=compliance_refs,
                    )
                )
    return findings