"""
TIRtcp Static Audit Module: Managed Bytecode & Manifest Auditor (.NET & Java)
Inspects offline:
1. .NET Assemblies & Manifests (TCP-MGD-001):
   - UAC requestedExecutionLevel (requireAdministrator / highestAvailable)
   - Unsafe deserialization APIs (BinaryFormatter, SoapFormatter, NetDataContractSerializer, TypeNameHandling)
   - DPAPI ProtectedData.Protect usage & missing optional entropy indicators
   - CLR Strong-Name signing flag
2. Java JAR / WAR Archives (TCP-MGD-002):
   - ObjectInputStream / XMLDecoder / XStream deserialization sinks in .class constant pools
   - Exposed RMI / JMX registry creation
   - Disabled SSL/TLS hostname verification patterns
"""

from __future__ import annotations

import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

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

MAX_ARCHIVE_BYTES = 80 * 1024 * 1024

# .NET CLR Header flags
COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008

# .NET Unsafe Deserialization & Crypto API Patterns
DOTNET_DESERIALIZATION_SINKS: List[Tuple[str, re.Pattern[bytes], Severity]] = [
    (
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
        re.compile(rb"BinaryFormatter"),
        Severity.HIGH,
    ),
    (
        "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
        re.compile(rb"SoapFormatter"),
        Severity.HIGH,
    ),
    (
        "System.Runtime.Serialization.NetDataContractSerializer",
        re.compile(rb"NetDataContractSerializer"),
        Severity.HIGH,
    ),
    (
        "System.Web.UI.LosFormatter / ObjectStateFormatter",
        re.compile(rb"(?:LosFormatter|ObjectStateFormatter)"),
        Severity.HIGH,
    ),
]

DOTNET_JSON_TYPENAME_RE = re.compile(
    rb"TypeNameHandling\s*[:=]\s*(?:1|2|3|4|All|Objects|Arrays|Auto)\b"
)
DOTNET_DPAPI_RE = re.compile(rb"ProtectedData|CryptProtectData")
EMBEDDED_MANIFEST_RE = re.compile(
    rb"<assembly\b[^>]*xmlns=['\"]urn:schemas-microsoft-com:asm\.v1['\"].*?</assembly>",
    re.DOTALL,
)

# Java Class Constant-Pool Patterns
JAVA_SINKS: List[Tuple[str, re.Pattern[bytes], Severity, str]] = [
    (
        "Java Native Deserialization (ObjectInputStream.readObject)",
        re.compile(rb"java/io/ObjectInputStream.*readObject"),
        Severity.HIGH,
        "Untrusted serialized Java objects passed to ObjectInputStream.readObject can trigger gadget-chain RCE.",
    ),
    (
        "Java Beans XMLDecoder Deserialization",
        re.compile(rb"java/beans/XMLDecoder"),
        Severity.HIGH,
        "XMLDecoder executes arbitrary method invocations encoded in XML payloads.",
    ),
    (
        "XStream Deserialization Without Explicit Type Allowlist",
        re.compile(rb"com/thoughtworks/xstream/XStream"),
        Severity.MEDIUM,
        "XStream instances without explicit allowType* security frameworks are vulnerable to object injection.",
    ),
    (
        "Java RMI Registry Exposure (LocateRegistry.createRegistry)",
        re.compile(rb"java/rmi/registry/LocateRegistry.*createRegistry"),
        Severity.MEDIUM,
        "Local or network RMI registry creation can expose unauthenticated remote object bindings.",
    ),
    (
        "Disabled TLS Hostname Verification (ALLOW_ALL_HOSTNAME_VERIFIER)",
        re.compile(rb"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier"),
        Severity.HIGH,
        "Disables TLS server identity verification, enabling man-in-the-middle interception.",
    ),
]


def _resolve_managed_compliance(mapper: ComplianceMapper, check_id: str) -> List[ComplianceRef]:
    refs = mapper.resolve(check_id)
    if refs:
        return refs
    return [
        ComplianceRef(
            framework="CWE",
            version="4.16",
            control_id="CWE-502 / CWE-250",
            control_title="Deserialization of Untrusted Data / Execution with Unnecessary Privileges",
            relation=ComplianceRelation.DIRECT,
            scope="general",
        ),
        ComplianceRef(
            framework="OWASP_ASVS",
            version="4.0.3",
            control_id="V5.5.3 / V1.14.1",
            control_title="Safe Deserialization and Least-Privilege Client Execution",
            relation=ComplianceRelation.SUPPORTS,
            scope="general",
        ),
    ]


# ---------------------------------------------------------------------------
# Helpers: .NET CLR Header & Manifest Parser
# ---------------------------------------------------------------------------
def _inspect_clr_header(pe_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse PE COFF/Optional header and IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14)
    to confirm whether a PE binary is a .NET CLR assembly and extract CLR flags.
    """
    if len(pe_bytes) < 0x100 or pe_bytes[:2] != b"MZ":
        return None
    try:
        pe_offset = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        if pe_offset + 24 >= len(pe_bytes) or pe_bytes[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack_from("<H", pe_bytes, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from("<H", pe_bytes, pe_offset + 20)[0]
        opt_start = pe_offset + 24
        magic = struct.unpack_from("<H", pe_bytes, opt_start)[0]

        # DataDirectory[14] (COM Descriptor / CLR Runtime Header)
        # PE32 (0x10B): DataDirectory starts at opt_start + 96; index 14 is + 14*8 = +112 -> opt_start + 208
        # PE32+ (0x20B): DataDirectory starts at opt_start + 112; index 14 is + 14*8 = +112 -> opt_start + 224
        dd_offset = opt_start + (224 if magic == 0x020B else 208)
        if dd_offset + 8 > len(pe_bytes):
            return None

        clr_rva, clr_size = struct.unpack_from("<II", pe_bytes, dd_offset)
        if clr_rva == 0 or clr_size == 0:
            return None

        # Map clr_rva to file offset via section headers
        sec_table_start = opt_start + opt_header_size
        clr_file_offset: Optional[int] = None
        for i in range(num_sections):
            sec_off = sec_table_start + (i * 40)
            if sec_off + 40 > len(pe_bytes):
                break
            v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, sec_off + 8)
            span = max(v_size, raw_size)
            if v_addr <= clr_rva < v_addr + span:
                clr_file_offset = raw_ptr + (clr_rva - v_addr)
                break

        clr_flags = 0
        if clr_file_offset is not None and clr_file_offset + 20 <= len(pe_bytes):
            # COR20 header: cb (4), MajorRuntimeVersion (2), MinorRuntimeVersion (2), MetaData (8), Flags (4)
            clr_flags = struct.unpack_from("<I", pe_bytes, clr_file_offset + 16)[0]

        return {
            "is_dotnet": True,
            "clr_flags_hex": hex(clr_flags),
            "il_only": bool(clr_flags & COMIMAGE_FLAGS_ILONLY),
            "strong_name_signed": bool(clr_flags & COMIMAGE_FLAGS_STRONGNAMESIGNED),
        }
    except Exception:
        return None


def _parse_uac_execution_level(manifest_xml: bytes) -> Optional[str]:
    """Extract requestedExecutionLevel/@level from a Windows application manifest XML blob."""
    try:
        root = ET.fromstring(manifest_xml.decode("utf-8", errors="ignore"))
        for elem in root.iter():
            if elem.tag.endswith("requestedExecutionLevel"):
                return elem.attrib.get("level")
    except Exception:
        m = re.search(rb'requestedExecutionLevel[^>]*level=["\']([^"\']+)["\']', manifest_xml)
        if m:
            return m.group(1).decode("ascii", errors="ignore")
    return None


def _audit_dotnet_assembly(
    bin_path: Path,
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    try:
        if bin_path.stat().st_size > MAX_ARCHIVE_BYTES:
            return findings
        raw = bin_path.read_bytes()
    except OSError:
        return findings

    clr_info = _inspect_clr_header(raw)
    if not clr_info:
        return findings

    # 1. Check Embedded or Sidecar UAC Manifest for requireAdministrator
    manifest_bytes: Optional[bytes] = None
    m_match = EMBEDDED_MANIFEST_RE.search(raw)
    if m_match:
        manifest_bytes = m_match.group(0)
    else:
        sidecar = Path(f"{bin_path}.manifest")
        if sidecar.exists():
            try:
                manifest_bytes = sidecar.read_bytes()
            except OSError:
                pass

    if manifest_bytes:
        uac_level = _parse_uac_execution_level(manifest_bytes)
        if uac_level and uac_level.lower() in ("requireadministrator", "highestavailable"):
            findings.append(
                Finding(
                    check_id="TCP-MGD-001",
                    title=f".NET Application Requests Elevated UAC Privileges ({uac_level})",
                    category="Managed Code & Privilege Boundaries",
                    status=FindingStatus.FAIL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_path),
                    summary=(
                        f"Application manifest specifies requestedExecutionLevel='{uac_level}', "
                        "forcing the thick client to run with elevated privileges and expanding local attack surface."
                    ),
                    evidence={"uac_level": uac_level, "clr_info": clr_info},
                    remediation=(
                        "Set requestedExecutionLevel to 'asInvoker' in app.manifest and isolate any "
                        "administrative operations into a hardened, least-privilege broker service."
                    ),
                    compliance_support=compliance_refs,
                )
            )

    # 2. Check Unsafe .NET Deserialization APIs
    detected_sinks: List[str] = []
    highest_sink_sev = Severity.MEDIUM
    for sink_name, pattern, sev in DOTNET_DESERIALIZATION_SINKS:
        if pattern.search(raw):
            detected_sinks.append(sink_name)
            if sev == Severity.HIGH:
                highest_sink_sev = Severity.HIGH

    if DOTNET_JSON_TYPENAME_RE.search(raw):
        detected_sinks.append("Newtonsoft.Json TypeNameHandling != None")
        highest_sink_sev = Severity.HIGH

    if detected_sinks:
        findings.append(
            Finding(
                check_id="TCP-MGD-001",
                title=f"Unsafe .NET Deserialization API Referenced ({len(detected_sinks)} Sink(s))",
                category="Managed Code & Serialization",
                status=FindingStatus.FAIL,
                severity=highest_sink_sev,
                confidence=Confidence.HIGH,
                affected_asset=str(bin_path),
                summary=(
                    f"Assembly references dangerous .NET deserialization types ({', '.join(detected_sinks)}). "
                    "If reachable from IPC, files, or network streams, this can enable arbitrary code execution."
                ),
                evidence={"deserialization_sinks": detected_sinks, "clr_info": clr_info},
                remediation=(
                    "Replace BinaryFormatter/SoapFormatter with safe schema-bound serializers "
                    "(System.Text.Json or DataContractSerializer with known types) and set TypeNameHandling.None."
                ),
                compliance_support=compliance_refs,
                manual_playbook=PlaybookRef(
                    tool="dnSpy / ILSpy",
                    objective="Trace cross-references to Deserialize() calls and determine if untrusted input reaches the sink.",
                    steps=[
                        f"Open {bin_path.name} in dnSpy/ILSpy and search for references to {', '.join(detected_sinks)}.",
                        "Inspect the data source passed into .Deserialize() (network socket, Named Pipe, local file, or clipboard) to confirm exploitability.",
                    ],
                ),
            )
        )

    # 3. Check DPAPI Usage (ProtectedData.Protect) -> Manual Review for Optional Entropy
    if DOTNET_DPAPI_RE.search(raw):
        findings.append(
            Finding(
                check_id="TCP-MGD-001",
                title=".NET DPAPI (ProtectedData) Detected — Verify Additional Entropy & Scope",
                category="Managed Code & Local Cryptography",
                status=FindingStatus.MANUAL_REQUIRED,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                affected_asset=str(bin_path),
                summary=(
                    "Assembly invokes Windows DPAPI (ProtectedData). Without application-specific "
                    "optionalEntropy and CurrentUser scope, any process under the same user account can decrypt stored secrets."
                ),
                evidence={"api": "System.Security.Cryptography.ProtectedData", "clr_info": clr_info},
                remediation="Pass strong application-specific entropy bytes and use DataProtectionScope.CurrentUser.",
                compliance_support=compliance_refs,
                manual_playbook=PlaybookRef(
                    tool="dnSpy / ILSpy",
                    objective="Inspect ProtectedData.Protect() call sites for optionalEntropy and DataProtectionScope.",
                    steps=[
                        f"Locate ProtectedData.Protect calls inside {bin_path.name} using dnSpy.",
                        "Verify whether the second parameter (optionalEntropy) is non-null and whether DataProtectionScope.LocalMachine is avoided for per-user secrets.",
                    ],
                ),
            )
        )

    # 4. Check CLR Strong-Name Signing
    if not clr_info["strong_name_signed"]:
        findings.append(
            Finding(
                check_id="TCP-MGD-001",
                title=".NET Assembly Lacks Strong-Name Signature",
                category="Managed Code & Integrity",
                status=FindingStatus.FAIL,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                affected_asset=str(bin_path),
                summary="CLR header lacks COMIMAGE_FLAGS_STRONGNAMESIGNED, simplifying assembly replacement or IL patching.",
                evidence=clr_info,
                remediation="Sign .NET assemblies with a strong-name key pair alongside Authenticode signing.",
                compliance_support=compliance_refs,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Helpers: Java JAR / WAR Constant-Pool & Manifest Auditor
# ---------------------------------------------------------------------------
def _audit_java_archive(
    jar_path: Path,
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    try:
        if jar_path.stat().st_size > MAX_ARCHIVE_BYTES or not zipfile.is_zipfile(jar_path):
            return findings
    except OSError:
        return findings

    sink_hits: Dict[str, Dict[str, Any]] = {}
    classes_scanned = 0

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for entry in zf.infolist():
                if entry.is_dir() or not entry.filename.endswith(".class"):
                    continue
                if entry.file_size > 5 * 1024 * 1024:
                    continue

                classes_scanned += 1
                class_bytes = zf.read(entry.filename)

                for title, pattern, sev, risk_desc in JAVA_SINKS:
                    if pattern.search(class_bytes):
                        bucket = sink_hits.setdefault(
                            title,
                            {
                                "sink_title": title,
                                "severity": sev,
                                "risk": risk_desc,
                                "sample_classes": [],
                                "total_classes": 0,
                            },
                        )
                        bucket["total_classes"] += 1
                        if len(bucket["sample_classes"]) < 8:
                            bucket["sample_classes"].append(entry.filename)
    except Exception:
        return findings

    for info in sink_hits.values():
        findings.append(
            Finding(
                check_id="TCP-MGD-002",
                title=f"Java Archive References High-Risk API: {info['sink_title']}",
                category="Managed Code & Java Bytecode",
                status=FindingStatus.FAIL,
                severity=info["severity"],
                confidence=Confidence.MEDIUM,
                affected_asset=str(jar_path),
                summary=f"{info['risk']} Detected across {info['total_classes']} class file(s) in {jar_path.name}.",
                evidence={
                    "classes_scanned": classes_scanned,
                    "matching_class_count": info["total_classes"],
                    "sample_classes": info["sample_classes"],
                },
                remediation=(
                    "Avoid native Java deserialization of untrusted streams (use JSON/Protobuf), "
                    "enforce JEP 290 ObjectInputFilter allowlists, and enable strict TLS hostname verification."
                ),
                compliance_support=compliance_refs,
                manual_playbook=PlaybookRef(
                    tool="CFR / Jadx-GUI",
                    objective="Decompile the flagged .class files to verify whether user-controlled input reaches the sink.",
                    steps=[
                        f"Open {jar_path.name} in Jadx-GUI and navigate to: {', '.join(info['sample_classes'][:3])}.",
                        "Trace the input stream or network socket feeding the flagged API call.",
                    ],
                ),
            )
        )

    if classes_scanned > 0 and not sink_hits:
        findings.append(
            Finding(
                check_id="TCP-MGD-002",
                title="No Unsafe Java Deserialization, RMI, or TLS Bypass Sinks Detected",
                category="Managed Code & Java Bytecode",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(jar_path),
                summary=f"Inspected {classes_scanned} compiled .class file(s) in {jar_path.name} with zero risky sinks matched.",
                evidence={"classes_scanned": classes_scanned},
                compliance_support=compliance_refs,
            )
        )

    return findings


def scan_managed_bytecode(
    target_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Scan a target file or installation directory for .NET assemblies (.exe/.dll)
    and Java archives (.jar/.war) offline.
    """
    dotnet_refs = _resolve_managed_compliance(mapper, "TCP-MGD-001")
    java_refs = _resolve_managed_compliance(mapper, "TCP-MGD-002")
    findings: List[Finding] = []

    if not target_path.exists():
        return findings

    candidates: List[Path] = []
    if target_path.is_file():
        candidates.append(target_path)
    elif target_path.is_dir():
        for root, _, files in os.walk(target_path):
            for fname in files:
                fp = Path(root) / fname
                if fp.suffix.lower() in {".exe", ".dll", ".jar", ".war"}:
                    candidates.append(fp)

    for item in candidates:
        ext = item.suffix.lower()
        if ext in {".exe", ".dll"}:
            findings.extend(_audit_dotnet_assembly(item, dotnet_refs))
        elif ext in {".jar", ".war"}:
            findings.extend(_audit_java_archive(item, java_refs))

    return findings