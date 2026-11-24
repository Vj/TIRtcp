"""
TIRtcp Static Audit Module: Binary Exploit Mitigations (PE, ELF, Mach-O).
Maps to check_id: TCP-BIN-001
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

try:
    import lief  # type: ignore
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

try:
    import pefile  # type: ignore
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# PE DllCharacteristics bitmasks
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

# PE Machine types
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64


def _audit_pe_with_pefile(binary_path: Path) -> Dict[str, Any]:
    """Fallback PE parser using pefile when lief is not installed."""
    pe = pefile.PE(str(binary_path), fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics

        is_64bit = machine in (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64)
        is_x86 = machine == IMAGE_FILE_MACHINE_I386

        checks: Dict[str, bool] = {
            "DYNAMIC_BASE (ASLR)": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
            "NX_COMPAT (DEP)": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
            "GUARD_CF (CFG)": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        }

        if is_64bit:
            checks["HIGH_ENTROPY_VA (64-bit ASLR)"] = bool(
                dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            )

        if is_x86:
            no_seh = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH)
            has_seh_table = False
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
                cfg = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                se_table = getattr(cfg, "SEHandlerTable", 0)
                se_count = getattr(cfg, "SEHandlerCount", 0)
                has_seh_table = bool(se_table and se_count > 0)
            checks["SafeSEH (x86)"] = no_seh or has_seh_table

        missing = [name for name, enabled in checks.items() if not enabled]
        return {
            "format": "PE",
            "architecture": "x64/ARM64" if is_64bit else ("x86" if is_x86 else hex(machine)),
            "dll_characteristics_hex": hex(dll_chars),
            "evaluated_mitigations": checks,
            "missing_mitigations": missing,
        }
    finally:
        pe.close()


def _audit_with_lief(binary_path: Path) -> Optional[Dict[str, Any]]:
    """Primary cross-platform binary parser using LIEF."""
    binary = lief.parse(str(binary_path))
    if binary is None:
        return None

    # 1. Windows PE
    if isinstance(binary, lief.PE.Binary):
        header = binary.header
        opt = binary.optional_header
        dll_chars = opt.dll_characteristics

        is_64bit = binary.header.machine in (
            lief.PE.Header.MACHINE_TYPES.AMD64,
            lief.PE.Header.MACHINE_TYPES.ARM64,
        )
        is_x86 = binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386

        checks: Dict[str, bool] = {
            "DYNAMIC_BASE (ASLR)": opt.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE),
            "NX_COMPAT (DEP)": opt.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT),
            "GUARD_CF (CFG)": opt.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.GUARD_CF),
        }

        if is_64bit:
            checks["HIGH_ENTROPY_VA (64-bit ASLR)"] = opt.has(
                lief.PE.OptionalHeader.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA
            )

        if is_x86:
            no_seh = opt.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NO_SEH)
            has_seh_table = False
            if binary.has_configuration:
                cfg = binary.load_configuration
                se_table = getattr(cfg, "se_handler_table", 0)
                se_count = getattr(cfg, "se_handler_count", 0)
                has_seh_table = bool(se_table and se_count > 0)
            checks["SafeSEH (x86)"] = no_seh or has_seh_table

        missing = [name for name, enabled in checks.items() if not enabled]
        return {
            "format": "PE",
            "architecture": str(header.machine.name),
            "dll_characteristics_hex": hex(dll_chars),
            "evaluated_mitigations": checks,
            "missing_mitigations": missing,
        }

    # 2. Linux ELF
    if isinstance(binary, lief.ELF.Binary):
        checks = {
            "PIE (ASLR)": binary.is_pie,
            "NX (Non-Executable Stack)": binary.has_nx,
            "Stack Canary": binary.has_symbol("__stack_chk_fail"),
        }
        missing = [name for name, enabled in checks.items() if not enabled]
        return {
            "format": "ELF",
            "architecture": str(binary.header.machine_type.name),
            "evaluated_mitigations": checks,
            "missing_mitigations": missing,
        }

    # 3. macOS Mach-O
    if isinstance(binary, lief.MachO.Binary):
        checks = {
            "PIE (ASLR)": binary.is_pie,
            "Non-Executable Heap/Stack": not binary.header.has(
                lief.MachO.Header.FLAGS.ALLOW_STACK_EXECUTION
            ),
            "Stack Canary": binary.has_symbol("___stack_chk_fail"),
        }
        missing = [name for name, enabled in checks.items() if not enabled]
        return {
            "format": "Mach-O",
            "architecture": str(binary.header.cpu_type.name),
            "evaluated_mitigations": checks,
            "missing_mitigations": missing,
        }

    return None


def scan_binary_hardening(
    target_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Scan a binary file or installation directory of executables/DLLs/SOs
    for compiler exploit mitigations.
    """
    check_id = "TCP-BIN-001"
    compliance_refs = mapper.resolve(check_id)
    findings: List[Finding] = []

    if not HAS_LIEF and not HAS_PEFILE:
        return [
            Finding(
                check_id=check_id,
                title="Binary Hardening Parser Unavailable",
                category="Binary Hardening",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(target_path),
                summary="Neither 'lief' nor 'pefile' is installed in the analyzer Python environment.",
                evidence={"missing_packages": ["lief", "pefile"]},
                remediation="Install binary parsing libraries: pip install lief pefile",
                compliance_support=compliance_refs,
            )
        ]

    candidate_exts = {".exe", ".dll", ".sys", ".so", ".dylib"}
    targets: List[Path] = []
    if target_path.is_file():
        targets.append(target_path)
    elif target_path.is_dir():
        for root, _, files in os.walk(target_path):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in candidate_exts or os.access(fpath, os.X_OK):
                    targets.append(fpath)

    for bin_file in targets:
        try:
            result = (
                _audit_with_lief(bin_file)
                if HAS_LIEF
                else (_audit_pe_with_pefile(bin_file) if bin_file.suffix.lower() in {".exe", ".dll", ".sys"} else None)
            )
        except Exception as exc:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="Binary Header Parse Error",
                    category="Binary Hardening",
                    status=FindingStatus.TOOLING_GAP,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    affected_asset=str(bin_file),
                    summary=f"Could not parse binary headers: {exc}",
                    evidence={"error": str(exc)},
                    compliance_support=compliance_refs,
                )
            )
            continue

        if not result:
            continue

        missing = result["missing_mitigations"]
        if not missing:
            findings.append(
                Finding(
                    check_id=check_id,
                    title="All Expected Binary Exploit Mitigations Enabled",
                    category="Binary Hardening",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_file),
                    summary=(
                        f"{result['format']} ({result['architecture']}) binary implements all "
                        f"checked exploit mitigations."
                    ),
                    evidence=result,
                    compliance_support=compliance_refs,
                )
            )
        else:
            # Escalate severity if core ASLR or DEP/NX is missing
            core_missing = any(
                key in m for m in missing for key in ("DYNAMIC_BASE", "NX_COMPAT", "PIE", "NX (")
            )
            sev = Severity.MEDIUM if core_missing else Severity.LOW

            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Missing Binary Exploit Mitigations ({', '.join(missing)})",
                    category="Binary Hardening",
                    status=FindingStatus.FAIL,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_file),
                    summary=(
                        f"{result['format']} ({result['architecture']}) binary lacks "
                        f"{len(missing)} recommended compiler hardening flag(s): {', '.join(missing)}."
                    ),
                    evidence=result,
                    remediation=(
                        "Recompile binaries with full memory protection flags enabled: "
                        "MSVC (/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf, plus /SAFESEH on x86) "
                        "or GCC/Clang (-fPIE -pie -Wl,-z,noexecstack -fstack-protector-strong)."
                    ),
                    compliance_support=compliance_refs,
                )
            )

    return findings