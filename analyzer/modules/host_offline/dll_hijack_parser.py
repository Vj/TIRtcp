"""
TIRtcp Host & Offline Audit Module: DLL Search-Order Hijacking Analyzer
Combines:
1. Static PE Import Address Table (IAT) & Delay-Load DLL resolution audit
2. Offline Process Monitor (Procmon) CSV log parser for 'NAME NOT FOUND' DLL lookups
Maps to check_id: TCP-HOST-002
"""

from __future__ import annotations

import csv
import ntpath
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

try:
    import pefile  # type: ignore
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# Core Windows KnownDLLs resolved directly from System32 by the kernel session manager
WINDOWS_KNOWN_DLLS: Set[str] = {
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "cfgmgr32.dll",
    "clbcatq.dll", "combase.dll", "comctl32.dll", "comdlg32.dll",
    "crypt32.dll", "cryptbase.dll", "gdi32.dll", "gdiplus.dll",
    "imm32.dll", "kernel32.dll", "kernelbase.dll", "msasn1.dll",
    "msctf.dll", "msvcrt.dll", "normaliz.dll", "nsi.dll",
    "ntdll.dll", "ole32.dll", "oleaut32.dll", "profapi.dll",
    "psapi.dll", "rpcrt4.dll", "sechost.dll", "setupapi.dll",
    "shcore.dll", "shell32.dll", "shlwapi.dll", "ucrtbase.dll",
    "user32.dll", "userenv.dll", "uxtheme.dll", "version.dll",
    "win32u.dll", "wininet.dll", "winmm.dll", "wintrust.dll",
    "wldap32.dll", "ws2_32.dll",
}

USER_WRITABLE_PATH_FRAGMENTS = (
    "\\users\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\public\\",
)
known_os_dlls = set(WINDOWS_KNOWN_DLLS)
if host_evidence:
    dll_env = host_evidence.get("dll_search_environment", {})
    known_os_dlls.update(d.lower() for d in dll_env.get("known_dlls", []))
    known_os_dlls.update(d.lower() for d in dll_env.get("system32_dlls", []))

def _is_path_writable(
    candidate_dir: str,
    weak_acl_paths: Set[str],
    app_dir_str: Optional[str],
) -> Tuple_Result:
    norm = candidate_dir.rstrip("\\/").lower()
    if any(norm == w or norm.startswith(w + "\\") for w in weak_acl_paths):
        return True, "Matched weak_acls entry in host_evidence.json"
    if any(frag in norm for frag in USER_WRITABLE_PATH_FRAGMENTS):
        return True, "Located inside standard user-writable directory tree"
    # NOTE: the install dir is only reported when host_evidence proves it is writable (weak_acls above);
    # assuming writability produced a HIGH finding for every optional-DLL probe in a default Program Files install.
    return False, ""


Tuple_Result = tuple[bool, str]


def _audit_static_iat(
    target_path: Path,
    weak_acl_paths: Set[str],
    compliance_refs: List[Any],
) -> List[Finding]:
    """Inspect PE Import and Delay-Import tables for missing local DLLs resolved via PATH."""
    findings: List[Finding] = []
    if not HAS_PEFILE or not target_path.exists():
        return findings

    app_dir = target_path if target_path.is_dir() else target_path.parent
    local_dlls = {p.name.lower() for p in app_dir.glob("*.dll")}
    exes = [target_path] if target_path.is_file() else list(app_dir.glob("*.exe"))

    for exe_path in exes:
        try:
            pe = pefile.PE(str(exe_path), fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                ]
            )
        except Exception:
            continue

        missing_non_system: List[Dict[str, str]] = []
        try:
            for attr, import_type in (
                ("DIRECTORY_ENTRY_IMPORT", "standard_import"),
                ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay_load_import"),
            ):
                entries = getattr(pe, attr, []) or []
                for entry in entries:
                    dll_name = entry.dll.decode("utf-8", errors="ignore").strip()
                    low = dll_name.lower()
                    # Skip API sets (api-ms-win-*, ext-ms-*) and core KnownDLLs
                    if low.startswith(("api-ms-win-", "ext-ms-")) or low in WINDOWS_KNOWN_DLLS:
                        continue
                    if low not in local_dlls:
                        missing_non_system.append(
                            {"dll": dll_name, "import_type": import_type}
                        )
        finally:
            pe.close()

        if missing_non_system:
            app_dir_writable = str(app_dir).rstrip("\\/").lower() in weak_acl_paths
            findings.append(
                Finding(
                    check_id="TCP-HOST-002",
                    title=f"External / Delay-Loaded DLLs Resolved via Search Path ({exe_path.name})",
                    category="Host & Runtime Loading",
                    status=FindingStatus.FAIL if app_dir_writable else FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.HIGH if app_dir_writable else Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_asset=str(exe_path),
                    summary=(
                        f"{exe_path.name} imports {len(missing_non_system)} non-KnownDLL library(ies) not bundled "
                        "in the application directory, causing Windows to search CWD and system PATH."
                    ),
                    evidence={
                        "missing_local_imports": missing_non_system[:25],
                        "app_dir_confirmed_writable": app_dir_writable,
                    },
                    remediation=(
                        "Bundle required third-party DLLs in the locked-down application directory, "
                        "call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), and avoid "
                        "unqualified LoadLibrary calls."
                    ),
                    compliance_support=compliance_refs,
                    manual_playbook=PlaybookRef(
                        tool="Procmon (Process Monitor)",
                        objective="Capture runtime LoadLibrary behavior and confirm whether any missing DLL resolves in a user-writable PATH folder.",
                        steps=[
                            f"Launch Procmon and set filters: Process Name is {exe_path.name}, Result is NAME NOT FOUND, Path ends with .dll.",
                            "Exercise all application workflows (login, plugins, file export, auto-update).",
                            "Export the filtered capture as CSV and re-run TIRtcp with --procmon-csv to pinpoint writable hijack candidates.",
                        ],
                    ),
                )
            )

    return findings


def parse_procmon_csv(
    procmon_csv_path: Path,
    mapper: ComplianceMapper,
    target_path: Optional[Path] = None,
    host_evidence: Optional[Dict[str, Any]] = None,
) -> List[Finding]:
    """
    Analyze both static PE IAT entries and an exported Process Monitor (Procmon) CSV
    for DLL search-order hijacking candidates (NAME NOT FOUND in writable directories).
    """
    check_id = "TCP-HOST-002"
    compliance_refs = mapper.resolve(check_id)
    findings: List[Finding] = []

    weak_acl_paths: Set[str] = set()
    if host_evidence:
        for item in host_evidence.get("weak_acls", []):
            p = item.get("path", "")
            if p:
                weak_acl_paths.add(p.rstrip("\\/").lower())

    # 1. Run Static IAT Audit if target_path is supplied
    if target_path and target_path.exists():
        findings.extend(_audit_static_iat(target_path, weak_acl_paths, compliance_refs))

    # 2. Parse Procmon CSV Export if supplied
    if not procmon_csv_path or not procmon_csv_path.exists():
        return findings

    app_dir_str = str(target_path if (target_path and target_path.is_dir()) else (target_path.parent if target_path else ""))
    hijack_candidates: Dict[str, Dict[str, Any]] = {}
    rows_parsed = 0

    try:
        with procmon_csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows_parsed += 1
                result = (row.get("Result") or "").strip().upper()
                operation = (row.get("Operation") or "").strip()
                path_val = (row.get("Path") or "").strip()
                proc_name = (row.get("Process Name") or "unknown.exe").strip()

                if result != "NAME NOT FOUND":
                    continue
                if not path_val.lower().endswith(".dll"):
                    continue
                if operation not in {"CreateFile", "Load Image", "QueryOpen", "QueryBasicInformationFile"}:
                    continue

                parent_dir = ntpath.dirname(path_val)  # Procmon paths are Windows paths even when analysed on Linux/macOS
                is_writable, reason = _is_path_writable(parent_dir, weak_acl_paths, app_dir_str)
                if is_writable:
                    key = f"{proc_name}::{path_val.lower()}"
                    hijack_candidates[key] = {
                        "process_name": proc_name,
                        "missing_dll_path": path_val,
                        "directory": parent_dir,
                        "operation": operation,
                        "writability_basis": reason,
                    }
    except Exception as exc:
        return [
            Finding(
                check_id=check_id,
                title="Procmon CSV Parse Error",
                category="Host & Runtime Loading",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                affected_asset=str(procmon_csv_path),
                summary=f"Failed to parse Procmon CSV export: {exc}",
                compliance_support=compliance_refs,
            )
        ]

    for candidate in hijack_candidates.values():
        findings.append(
            Finding(
                check_id=check_id,
                title=f"Runtime DLL Search-Order Hijack Candidate ({Path(candidate['missing_dll_path']).name})",
                category="Host & Runtime Loading",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=candidate["missing_dll_path"],
                summary=(
                    f"Process '{candidate['process_name']}' attempted to load missing DLL "
                    f"'{candidate['missing_dll_path']}' inside a writable directory ({candidate['writability_basis']})."
                ),
                evidence=candidate,
                remediation=(
                    "Use explicit absolute paths for LoadLibrary/LoadLibraryEx with "
                    "LOAD_LIBRARY_SEARCH_SYSTEM32, and lock down directory ACLs."
                ),
                compliance_support=compliance_refs,
            )
        )

    if rows_parsed > 0 and not hijack_candidates:
        findings.append(
            Finding(
                check_id=check_id,
                title="No Writable-Path DLL Hijacking Candidates in Procmon Trace",
                category="Host & Runtime Loading",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(procmon_csv_path),
                summary=f"Parsed {rows_parsed} Procmon event(s); zero NAME NOT FOUND DLL lookups occurred in writable paths.",
                evidence={"procmon_rows_parsed": rows_parsed},
                compliance_support=compliance_refs,
            )
        )

    return findings