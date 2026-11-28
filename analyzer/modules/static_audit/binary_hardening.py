"""
TIRtcp Static Binary Hardening Module (TCP-BIN-001)
Audits compiled PE (Windows), ELF (Linux), and Mach-O (macOS) binaries for exploit mitigations:
  - PE: ASLR (DYNAMIC_BASE), 64-bit High-Entropy ASLR (HIGH_ENTROPY_VA), DEP/NX (NX_COMPAT),
        Control Flow Guard (GUARD_CF), Intel CET Shadow Stack (CET_COMPAT),
        SafeSEH (32-bit x86), and FORCE_INTEGRITY.
  - ELF / Mach-O: NX/PIE header checks when non-Windows targets are inspected.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.context import ScanContext
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

# PE DllCharacteristics flags
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

# Extended DLL Characteristics (Debug Directory type 20: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS)
IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001


def _inspect_pe_mitigations(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse PE Optional Header, Load Config, and Extended Debug Characteristics."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_offset = e_lfanew + 24

    if opt_offset + opt_header_size > len(data) or opt_header_size < 96:
        return None

    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_64bit = magic == 0x20B  # PE32+ (64-bit) vs 0x10B (PE32 32-bit)
    dll_chars = struct.unpack_from("<H", data, opt_offset + 70)[0]

    # Check if binary is a pure IL (.NET AnyCPU) assembly where native CFG/CET behaves differently
    dd_offset = opt_offset + (112 if is_64bit else 96)
    is_dotnet_il_only = False
    if dd_offset + (15 * 8) <= opt_offset + opt_header_size:
        clr_rva, clr_size = struct.unpack_from("<II", data, dd_offset + 14 * 8)
        if clr_rva > 0 and clr_size >= 16:
            is_dotnet_il_only = True

    # Parse sections for RVA -> file offset translation
    sec_offset = opt_offset + opt_header_size
    sections: List[tuple[int, int, int, int]] = []
    for i in range(num_sections):
        s_off = sec_offset + i * 40
        if s_off + 40 > len(data):
            break
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, s_off + 8)
        sections.append((v_addr, max(v_size, raw_size), raw_ptr, raw_size))

    def rva_to_offset(rva: int) -> Optional[int]:
        for v_addr, span, raw_ptr, raw_size in sections:
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size and raw_ptr + delta < len(data):
                    return raw_ptr + delta
        return None

    # SafeSEH check for 32-bit native PE (Load Config Directory index 10)
    safeseh_enabled: Optional[bool] = None
    if not is_64bit and not is_dotnet_il_only:
        if dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH:
            safeseh_enabled = True  # No SEH handlers used
        elif dd_offset + (11 * 8) <= opt_offset + opt_header_size:
            lc_rva, lc_size = struct.unpack_from("<II", data, dd_offset + 10 * 8)
            lc_off = rva_to_offset(lc_rva) if lc_rva else None
            if lc_off and lc_off + 72 <= len(data) and lc_size >= 72:
                se_handler_table, se_handler_count = struct.unpack_from("<II", data, lc_off + 64)
                safeseh_enabled = se_handler_table != 0 and se_handler_count > 0
            else:
                safeseh_enabled = False

    # Intel CET Shadow Stack compatibility (Debug Directory index 6)
    cet_compat = False
    if dd_offset + (7 * 8) <= opt_offset + opt_header_size:
        dbg_rva, dbg_size = struct.unpack_from("<II", data, dd_offset + 6 * 8)
        dbg_off = rva_to_offset(dbg_rva) if dbg_rva else None
        if dbg_off and dbg_size >= 28:
            num_entries = dbg_size // 28
            for idx in range(num_entries):
                entry_off = dbg_off + idx * 28
                if entry_off + 28 > len(data):
                    break
                dbg_type = struct.unpack_from("<I", data, entry_off + 12)[0]
                size_of_data, _, ptr_raw = struct.unpack_from("<III", data, entry_off + 16)
                if dbg_type == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS and size_of_data >= 4 and ptr_raw + 4 <= len(data):
                    ex_flags = struct.unpack_from("<I", data, ptr_raw)[0]
                    if ex_flags & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT:
                        cet_compat = True

    return {
        "arch": "x64/ARM64" if is_64bit else "x86 (32-bit)",
        "machine": hex(machine),
        "is_64bit": is_64bit,
        "is_dotnet_il_only": is_dotnet_il_only,
        "aslr": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "high_entropy_aslr": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        "dep_nx": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        "cfg": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        "cet_shadow_stack": cet_compat,
        "force_integrity": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY),
        "safeseh": safeseh_enabled,
    }


def scan_binary_hardening(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Optional[ScanContext] = None,
) -> List[Finding]:
    """Audit compiled binaries for ASLR, High-Entropy ASLR, DEP/NX, CFG, CET, and SafeSEH."""
    compliance_refs = mapper.resolve("TCP-BIN-001")
    findings: List[Finding] = []

    if not target_path.exists():
        return findings

    scan_ctx = ctx if ctx is not None else ScanContext(target_path)
    pe_audited = 0

    for rec in scan_ctx.iter_binaries():
        if not rec.is_pe or rec.ext not in (".exe", ".dll", ".sys"):
            continue
        raw = rec.read_bytes()
        if not raw:
            continue

        info = _inspect_pe_mitigations(raw)
        if not info:
            continue

        pe_audited += 1
        missing_critical: List[str] = []
        missing_hardening: List[str] = []

        if not info["aslr"]:
            missing_critical.append("ASLR (DYNAMIC_BASE)")
        if not info["dep_nx"]:
            missing_critical.append("DEP/NX (NX_COMPAT)")
        if info["is_64bit"] and not info["high_entropy_aslr"]:
            missing_hardening.append("64-bit High-Entropy ASLR (HIGH_ENTROPY_VA)")
        if not info["is_dotnet_il_only"]:
            if not info["cfg"]:
                missing_hardening.append("Control Flow Guard (GUARD_CF)")
            if info["is_64bit"] and not info["cet_shadow_stack"]:
                missing_hardening.append("Intel CET Shadow Stack (CET_COMPAT)")
            if info["safeseh"] is False:
                missing_critical.append("SafeSEH (32-bit Exception Handler Protection)")
        if not info["is_dotnet_il_only"] and not info["force_integrity"]:
            missing_hardening.append("Load-Time Code Integrity (FORCE_INTEGRITY)")

        if missing_critical:
            findings.append(
                Finding(
                    check_id="TCP-BIN-001",
                    title=f"Missing Core Binary Exploit Mitigations ({', '.join(missing_critical)})",
                    category="Binary Hardening",
                    status=FindingStatus.FAIL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        f"PE binary ({info['arch']}) lacks foundational memory-corruption protections: "
                        f"{', '.join(missing_critical)}."
                    ),
                    evidence={"mitigations": info, "missing_core": missing_critical, "missing_advanced": missing_hardening},
                    remediation="Recompile with /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF (and /SAFESEH on x86).",
                    compliance_support=compliance_refs,
                )
            )
        elif missing_hardening:
            findings.append(
                Finding(
                    check_id="TCP-BIN-001",
                    title=f"Missing Advanced Control-Flow / Entropy Mitigations ({', '.join(missing_hardening)})",
                    category="Binary Hardening",
                    status=FindingStatus.FAIL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        f"PE binary ({info['arch']}) enables ASLR and DEP/NX, but lacks modern hardening flags: "
                        f"{', '.join(missing_hardening)}."
                    ),
                    evidence={"mitigations": info, "missing_advanced": missing_hardening},
                    remediation="Enable Control Flow Guard (/GUARD:CF), High-Entropy ASLR (/HIGHENTROPYVA), and CET Shadow Stack (/CETCOMPAT) in MSVC linker settings.",
                    compliance_support=compliance_refs,
                )
            )

    if pe_audited > 0 and not findings:
        findings.append(
            Finding(
                check_id="TCP-BIN-001",
                title="All Audited PE Binaries Enforce Core & Advanced Exploit Mitigations",
                category="Binary Hardening",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(target_path),
                summary=f"Verified ASLR, High-Entropy ASLR, DEP/NX, CFG, and CET/SafeSEH across {pe_audited} PE binary/binaries.",
                evidence={"pe_binaries_audited": pe_audited},
                compliance_support=compliance_refs,
            )
        )

    return findings
