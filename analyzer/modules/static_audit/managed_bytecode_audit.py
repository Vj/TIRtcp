"""
TIRtcp Static Audit Module: PE UAC Manifests, .NET Metadata (#US/TypeRef/MemberRef) & Java Bytecode
Inspects offline:
1. All Windows PE Executables (Native C/C++ & .NET) -> TCP-HOST-001 / TCP-MGD-001:
   - Embedded RT_MANIFEST or sidecar *.manifest requestedExecutionLevel (requireAdministrator / highestAvailable)
2. .NET CLR Assemblies (via dnfile when available, with CLR metadata fallback) -> TCP-MGD-001:
   - TypeRef / MemberRef inspection for BinaryFormatter, SoapFormatter, NetDataContractSerializer,
     JsonSerializerSettings.set_TypeNameHandling, Assembly.Load(byte[]), Process.Start, and
     ServicePointManager.set_ServerCertificateValidationCallback
   - #US (User Strings) stream scan for hardcoded credentials/secrets
   - DPAPI ProtectedData.Protect manual entropy/scope check
3. Java Archives (.jar / .war / .ear + nested BOOT-INF/lib & WEB-INF/lib JARs) -> TCP-MGD-002:
   - Spec-compliant JVM .class constant-pool parser (no raw-byte regex backtracking)
   - Detects ObjectInputStream.readObject, XMLDecoder, XStream, RMI LocateRegistry,
     custom X509TrustManager, and permissive HostnameVerifier implementations
"""

from __future__ import annotations

import io
import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
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

try:
    import dnfile  # type: ignore
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

MAX_FILE_BYTES = 80 * 1024 * 1024
MAX_NESTED_JAR_DEPTH = 3

EMBEDDED_MANIFEST_RE = re.compile(
    rb"<assembly\b[^>]*xmlns=['\"]urn:schemas-microsoft-com:asm\.v1['\"].*?</assembly>",
    re.DOTALL,
)

# .NET TypeRef / MemberRef Rules: (Rule Label, Type Substring, Member Name or None, Severity, Risk Summary)
DOTNET_METADATA_SINKS: List[Tuple[str, str, Optional[str], Severity, str]] = [
    (
        "BinaryFormatter Deserialization",
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
        "Deserialize",
        Severity.HIGH,
        "BinaryFormatter.Deserialize is vulnerable to arbitrary code execution on untrusted input.",
    ),
    (
        "SoapFormatter Deserialization",
        "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
        "Deserialize",
        Severity.HIGH,
        "SoapFormatter.Deserialize allows arbitrary type instantiation from untrusted XML streams.",
    ),
    (
        "NetDataContractSerializer Deserialization",
        "System.Runtime.Serialization.NetDataContractSerializer",
        "Deserialize",
        Severity.HIGH,
        "NetDataContractSerializer embeds CLR type metadata and can trigger RCE on untrusted payloads.",
    ),
    (
        "LosFormatter / ObjectStateFormatter Deserialization",
        "Formatter",
        "Deserialize",
        Severity.HIGH,
        "Unrestricted formatter deserialization sink referenced in assembly metadata.",
    ),
    (
        "Newtonsoft.Json TypeNameHandling Configuration",
        "Newtonsoft.Json.JsonSerializerSettings",
        "set_TypeNameHandling",
        Severity.HIGH,
        "Assembly configures JsonSerializerSettings.TypeNameHandling; non-None settings enable polymorphic type injection.",
    ),
    (
        "Dynamic In-Memory Assembly Loading (Assembly.Load)",
        "System.Reflection.Assembly",
        "Load",
        Severity.MEDIUM,
        "Assembly dynamically loads assemblies at runtime; verify payload integrity and origin validation.",
    ),
    (
        "TLS Certificate Validation Override (ServerCertificateValidationCallback)",
        "System.Net.ServicePointManager",
        "set_ServerCertificateValidationCallback",
        Severity.HIGH,
        "Assembly overrides global TLS certificate validation callbacks; verify it does not unconditionally return true.",
    ),
]

# #US (User Strings) Secret Patterns
US_SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], Severity]] = [
    (
        "Database Connection String in .NET #US Heap",
        re.compile(
            r"(?:Server|Data Source)\s*=[^;]+;.*?(?:User\s*ID|UID)\s*=[^;]+;.*?(?:Password|PWD)\s*=\s*([^;\"']+)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
    ),
    (
        "PEM Private Key in .NET #US Heap",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "JWT / Bearer Secret in .NET #US Heap",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
    ),
]

# Java Constant-Pool Sinks: (Rule Label, Class Internal Name, Method Name or None, Severity, Risk Description)
JAVA_CP_SINKS: List[Tuple[str, str, Optional[str], Severity, str]] = [
    (
        "Java Native Deserialization (ObjectInputStream.readObject)",
        "java/io/ObjectInputStream",
        "readObject",
        Severity.HIGH,
        "Untrusted serialized Java objects passed to ObjectInputStream.readObject can trigger gadget-chain RCE.",
    ),
    (
        "Java Beans XMLDecoder Deserialization",
        "java/beans/XMLDecoder",
        "readObject",
        Severity.HIGH,
        "XMLDecoder executes arbitrary method invocations encoded in XML payloads.",
    ),
    (
        "XStream Deserialization",
        "com/thoughtworks/xstream/XStream",
        "fromXML",
        Severity.MEDIUM,
        "XStream.fromXML without explicit allowType* security configuration permits object injection.",
    ),
    (
        "Java RMI Registry Creation (LocateRegistry.createRegistry)",
        "java/rmi/registry/LocateRegistry",
        "createRegistry",
        Severity.MEDIUM,
        "Local or network RMI registry creation can expose unauthenticated remote object bindings.",
    ),
    (
        "Custom X509TrustManager Implementation",
        "javax/net/ssl/X509TrustManager",
        None,
        Severity.MEDIUM,
        "Class implements or references X509TrustManager; verify checkServerTrusted enforces certificate validation.",
    ),
    (
        "Permissive TLS HostnameVerifier (ALLOW_ALL / Noop)",
        "HostnameVerifier",
        None,
        Severity.HIGH,
        "References permissive or custom HostnameVerifier; verify server hostname validation is not bypassed.",
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


def _redact(val: str) -> str:
    s = val.strip()
    if len(s) <= 4:
        return "****"
    if len(s) <= 8:
        return f"{s[:2]}****"
    return f"{s[:3]}****{s[-2:]}"


# ---------------------------------------------------------------------------
# 1. All-PE UAC Manifest Check (Native C/C++ & .NET)
# ---------------------------------------------------------------------------
def _parse_uac_execution_level(manifest_xml: bytes) -> Optional[str]:
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


def _audit_pe_uac_manifest(
    bin_path: Path,
    raw_bytes: bytes,
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    """Check embedded RT_MANIFEST or sidecar *.manifest on ALL PE executables (native & .NET)."""
    if bin_path.suffix.lower() != ".exe":
        return []

    manifest_bytes: Optional[bytes] = None
    source_kind = "embedded_manifest"
    m_match = EMBEDDED_MANIFEST_RE.search(raw_bytes)
    if m_match:
        manifest_bytes = m_match.group(0)
    else:
        sidecar = Path(f"{bin_path}.manifest")
        if sidecar.exists():
            try:
                manifest_bytes = sidecar.read_bytes()
                source_kind = "sidecar_manifest"
            except OSError:
                pass

    if not manifest_bytes:
        return []

    uac_level = _parse_uac_execution_level(manifest_bytes)
    if uac_level and uac_level.lower() in ("requireadministrator", "highestavailable"):
        return [
            Finding(
                check_id="TCP-MGD-001",
                title=f"Windows Executable Requests Elevated UAC Privileges ({uac_level})",
                category="Host & Privilege Boundaries",
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                affected_asset=str(bin_path),
                summary=(
                    f"Executable manifest specifies requestedExecutionLevel='{uac_level}' ({source_kind}), "
                    "forcing the desktop client to run elevated and widening local privilege-escalation impact."
                ),
                evidence={"uac_level": uac_level, "manifest_source": source_kind},
                remediation=(
                    "Set requestedExecutionLevel to 'asInvoker' in the application manifest and isolate "
                    "administrative tasks into a separate least-privilege service."
                ),
                compliance_support=compliance_refs,
            )
        ]
    return []


# ---------------------------------------------------------------------------
# 2. .NET CLR Metadata Inspection (dnfile TypeRef/MemberRef/#US + Fallback)
# ---------------------------------------------------------------------------
def _has_clr_header(pe_bytes: bytes) -> bool:
    if len(pe_bytes) < 0x100 or pe_bytes[:2] != b"MZ":
        return False
    try:
        pe_offset = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        if pe_offset + 26 >= len(pe_bytes) or pe_bytes[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return False
        opt_start = pe_offset + 24
        magic = struct.unpack_from("<H", pe_bytes, opt_start)[0]
        dd_offset = opt_start + (224 if magic == 0x020B else 208)
        if dd_offset + 8 > len(pe_bytes):
            return False
        clr_rva, clr_size = struct.unpack_from("<II", pe_bytes, dd_offset)
        return clr_rva != 0 and clr_size != 0
    except Exception:
        return False


def _audit_dotnet_with_dnfile(
    bin_path: Path,
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    """Inspect actual .NET TypeRef, MemberRef, and #US metadata tables via dnfile."""
    findings: List[Finding] = []
    pe = dnfile.dnPE(str(bin_path))
    try:
        if not hasattr(pe, "net") or pe.net is None or pe.net.mdtables is None:
            return findings

        md = pe.net.mdtables
        type_refs: Dict[int, str] = {}
        if md.TypeRef is not None:
            for idx, row in enumerate(md.TypeRef.rows, start=1):
                ns = str(row.TypeNamespace or "")
                name = str(row.TypeName or "")
                type_refs[idx] = f"{ns}.{name}".lstrip(".")

        member_refs: List[Tuple[str, str]] = []
        if md.MemberRef is not None:
            for row in md.MemberRef.rows:
                m_name = str(row.Name or "")
                parent_type = ""
                if getattr(row, "Class", None) is not None and row.Class.table is not None:
                    if row.Class.table.name == "TypeRef":
                        parent_type = type_refs.get(row.Class.row_index, "")
                member_refs.append((parent_type, m_name))

        # Match TypeRef / MemberRef pairs against known risky .NET sinks
        matched_sinks: List[Dict[str, str]] = []
        highest_sev = Severity.MEDIUM
        uses_dpapi = any("ProtectedData" in t for t in type_refs.values())

        for rule_title, type_sub, member_name, sev, risk_desc in DOTNET_METADATA_SINKS:
            for parent_type, m_name in member_refs:
                if type_sub in parent_type and (member_name is None or member_name == m_name):
                    matched_sinks.append(
                        {
                            "rule": rule_title,
                            "type": parent_type,
                            "member": m_name,
                            "risk": risk_desc,
                        }
                    )
                    if sev == Severity.HIGH:
                        highest_sev = Severity.HIGH
                    break

        if matched_sinks:
            findings.append(
                Finding(
                    check_id="TCP-MGD-001",
                    title=f"Risky .NET Metadata API Call(s) Referenced ({len(matched_sinks)} Sink(s))",
                    category="Managed Code & .NET Metadata",
                    status=FindingStatus.FAIL,
                    severity=highest_sev,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_path),
                    summary=(
                        f"CLR MemberRef metadata references {len(matched_sinks)} high-risk .NET API(s): "
                        f"{', '.join(s['rule'] for s in matched_sinks)}."
                    ),
                    evidence={"parser": "dnfile", "matched_member_refs": matched_sinks},
                    remediation=(
                        "Replace unsafe formatters with System.Text.Json / DataContractSerializer, enforce "
                        "TypeNameHandling.None, and validate TLS certificates and dynamic assemblies."
                    ),
                    compliance_support=compliance_refs,
                    manual_playbook=PlaybookRef(
                        tool="dnSpy / ILSpy",
                        objective="Inspect IL call sites for the flagged MemberRef APIs to trace input sources.",
                        steps=[
                            f"Open {bin_path.name} in dnSpy and analyze callers of: {', '.join(s['member'] for s in matched_sinks)}.",
                            "Verify whether untrusted network, file, or IPC data reaches deserialization or assembly-loading arguments.",
                        ],
                    ),
                )
            )

        if uses_dpapi:
            findings.append(
                Finding(
                    check_id="TCP-MGD-001",
                    title=".NET DPAPI (ProtectedData) Referenced — Verify Optional Entropy & Scope",
                    category="Managed Code & Local Cryptography",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=str(bin_path),
                    summary="Assembly TypeRef table imports System.Security.Cryptography.ProtectedData; confirm optionalEntropy is non-null.",
                    evidence={"parser": "dnfile", "type_ref": "System.Security.Cryptography.ProtectedData"},
                    remediation="Supply application-specific optionalEntropy bytes and use DataProtectionScope.CurrentUser.",
                    compliance_support=compliance_refs,
                )
            )

        # Scan #US (User Strings) stream for hardcoded secrets/connection strings
        us_stream = getattr(pe.net, "user_strings", None)
        if us_stream is not None:
            us_values: List[str] = []
            try:
                for item in us_stream:
                    s_val = str(getattr(item, "value", item) or "")
                    if len(s_val) >= 8:
                        us_values.append(s_val)
            except Exception:
                pass

            joined_us = "\n".join(us_values)
            for label, pattern, sev in US_SECRET_PATTERNS:
                hits = pattern.findall(joined_us)
                if hits:
                    findings.append(
                        Finding(
                            check_id="TCP-SEC-001",
                            title=f"Hardcoded Secret in .NET #US User-String Stream ({label})",
                            category="Secrets & Configuration",
                            status=FindingStatus.FAIL,
                            severity=sev,
                            confidence=Confidence.HIGH,
                            affected_asset=str(bin_path),
                            summary=f"Extracted {len(hits)} sensitive literal(s) from the .NET #US metadata heap.",
                            evidence={
                                "parser": "dnfile (#US)",
                                "pattern": label,
                                "redacted_samples": [_redact(str(h)) for h in hits[:5]],
                            },
                            remediation="Remove secrets from compiled C#/VB.NET string literals and retrieve short-lived credentials at runtime.",
                            compliance_support=mapper.resolve("TCP-SEC-001") or compliance_refs,
                        )
                    )
    finally:
        pe.close()

    return findings


def _audit_dotnet_assembly(
    bin_path: Path,
    raw_bytes: bytes,
    compliance_refs: List[ComplianceRef],
    mapper: ComplianceMapper,
) -> List[Finding]:
    if not _has_clr_header(raw_bytes):
        return []

    if HAS_DNFILE:
        try:
            return _audit_dotnet_with_dnfile(bin_path, compliance_refs)
        except Exception:
            pass

    # Fallback when dnfile is not installed: conservative TypeRef ASCII check + Tooling Gap notice
    findings: List[Finding] = [
        Finding(
            check_id="TCP-MGD-001",
            title="CLR Metadata Parser (dnfile) Unavailable — Fallback String Inspection Used",
            category="Managed Code & .NET Metadata",
            status=FindingStatus.TOOLING_GAP,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            affected_asset=str(bin_path),
            summary="Install 'dnfile' (`pip install dnfile`) for exact .NET TypeRef, MemberRef, and #US heap analysis.",
            evidence={"missing_package": "dnfile"},
            remediation="pip install dnfile",
            compliance_support=compliance_refs,
        )
    ]
    if b"System.Runtime.Serialization.Formatters.Binary" in raw_bytes and b"BinaryFormatter" in raw_bytes:
        findings.append(
            Finding(
                check_id="TCP-MGD-001",
                title="BinaryFormatter Namespace & Type Referenced in .NET Assembly",
                category="Managed Code & .NET Metadata",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                affected_asset=str(bin_path),
                summary="Assembly metadata contains both BinaryFormatter namespace and type tokens.",
                evidence={"parser": "fallback_clr_strings"},
                remediation="Replace BinaryFormatter with System.Text.Json or DataContractSerializer.",
                compliance_support=compliance_refs,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 3. Spec-Compliant Java .class Constant-Pool Parser & Nested JAR Walker
# ---------------------------------------------------------------------------
def _parse_java_class_constant_pool(class_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse JVM .class file constant pool (magic 0xCAFEBABE) per JVM Spec §4.4.
    Properly handles variable-length entries and 2-slot Long/Double tags (5 and 6).
    Returns extracted UTF-8 strings, Class names, and (ClassName, MethodName) pairs.
    """
    if len(class_bytes) < 10 or class_bytes[:4] != b"\xca\xfe\xba\xbe":
        return None

    try:
        cp_count = struct.unpack_from("!H", class_bytes, 8)[0]
        pos = 10
        utf8_pool: Dict[int, str] = {}
        class_name_idx: Dict[int, int] = {}
        name_and_type_idx: Dict[int, Tuple[int, int]] = {}
        method_refs: List[Tuple[int, int]] = []

        idx = 1
        while idx < cp_count and pos < len(class_bytes):
            tag = class_bytes[pos]
            pos += 1

            if tag == 1:  # CONSTANT_Utf8
                if pos + 2 > len(class_bytes):
                    break
                length = struct.unpack_from("!H", class_bytes, pos)[0]
                pos += 2
                utf8_pool[idx] = class_bytes[pos : pos + length].decode("utf-8", errors="replace")
                pos += length
            elif tag in (3, 4):  # Integer, Float
                pos += 4
            elif tag in (5, 6):  # Long, Double (occupies TWO constant-pool slots per JVM spec)
                pos += 8
                idx += 1
            elif tag == 7:  # CONSTANT_Class
                class_name_idx[idx] = struct.unpack_from("!H", class_bytes, pos)[0]
                pos += 2
            elif tag == 8:  # CONSTANT_String
                pos += 2
            elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                c_idx, nt_idx = struct.unpack_from("!HH", class_bytes, pos)
                if tag in (10, 11):
                    method_refs.append((c_idx, nt_idx))
                pos += 4
            elif tag == 12:  # CONSTANT_NameAndType
                n_idx, d_idx = struct.unpack_from("!HH", class_bytes, pos)
                name_and_type_idx[idx] = (n_idx, d_idx)
                pos += 4
            elif tag == 15:  # CONSTANT_MethodHandle
                pos += 3
            elif tag == 16:  # CONSTANT_MethodType
                pos += 2
            elif tag in (17, 18):  # Dynamic, InvokeDynamic
                pos += 4
            elif tag in (19, 20):  # Module, Package
                pos += 2
            else:
                # Unknown tag; abort cleanly rather than misaligning pool offsets
                break

            idx += 1

        resolved_classes = {
            utf8_pool[name_i] for name_i in class_name_idx.values() if name_i in utf8_pool
        }
        resolved_methods: Set[Tuple[str, str]] = set()
        for c_i, nt_i in method_refs:
            cls_name = utf8_pool.get(class_name_idx.get(c_i, -1), "")
            n_i, _ = name_and_type_idx.get(nt_i, (-1, -1))
            m_name = utf8_pool.get(n_i, "")
            if cls_name and m_name:
                resolved_methods.add((cls_name, m_name))

        return {
            "classes": resolved_classes,
            "methods": resolved_methods,
        }
    except Exception:
        return None


def _iter_jar_classes_recursive(
    archive_bytes: bytes,
    archive_label: str,
    depth: int = 0,
) -> Iterable[Tuple[str, bytes]]:
    """Yield (logical_class_path, class_bytes) across a JAR/WAR and nested BOOT-INF/WEB-INF JARs."""
    if depth > MAX_NESTED_JAR_DEPTH:
        return
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            for entry in zf.infolist():
                if entry.is_dir():
                    continue
                lower_name = entry.filename.lower()
                if lower_name.endswith(".class") and entry.file_size <= 5 * 1024 * 1024:
                    yield f"{archive_label}!/{entry.filename}", zf.read(entry.filename)
                elif lower_name.endswith((".jar", ".war")) and entry.file_size <= MAX_FILE_BYTES:
                    nested_bytes = zf.read(entry.filename)
                    yield from _iter_jar_classes_recursive(
                        nested_bytes, f"{archive_label}!/{entry.filename}", depth=depth + 1
                    )
    except Exception:
        return


def _audit_java_archive(
    jar_path: Path,
    raw_bytes: bytes,
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    if not zipfile.is_zipfile(io.BytesIO(raw_bytes)):
        return findings

    sink_hits: Dict[str, Dict[str, Any]] = {}
    classes_scanned = 0

    for logical_path, class_bytes in _iter_jar_classes_recursive(raw_bytes, jar_path.name):
        cp = _parse_java_class_constant_pool(class_bytes)
        if cp is None:
            continue
        classes_scanned += 1

        classes: Set[str] = cp["classes"]
        methods: Set[Tuple[str, str]] = cp["methods"]

        for rule_title, target_cls, target_method, sev, risk_desc in JAVA_CP_SINKS:
            matched = False
            if target_method is not None:
                matched = any(
                    target_cls in cls and m_name == target_method for cls, m_name in methods
                )
            else:
                matched = any(target_cls in cls for cls in classes)

            if matched:
                bucket = sink_hits.setdefault(
                    rule_title,
                    {
                        "sink_title": rule_title,
                        "severity": sev,
                        "risk": risk_desc,
                        "sample_classes": [],
                        "total_classes": 0,
                    },
                )
                bucket["total_classes"] += 1
                if len(bucket["sample_classes"]) < 8:
                    bucket["sample_classes"].append(logical_path)

    for info in sink_hits.values():
        findings.append(
            Finding(
                check_id="TCP-MGD-002",
                title=f"Java Constant Pool References High-Risk API: {info['sink_title']}",
                category="Managed Code & Java Bytecode",
                status=FindingStatus.FAIL,
                severity=info["severity"],
                confidence=Confidence.HIGH,
                affected_asset=str(jar_path),
                summary=f"{info['risk']} Detected across {info['total_classes']} class(es) in {jar_path.name} (including nested JARs).",
                evidence={
                    "parser": "jvm_constant_pool_v1",
                    "classes_scanned": classes_scanned,
                    "matching_class_count": info["total_classes"],
                    "sample_classes": info["sample_classes"],
                },
                remediation=(
                    "Avoid native Java deserialization of untrusted streams (use JSON/Protobuf), "
                    "enforce JEP 290 ObjectInputFilter allowlists, and enable strict TLS certificate/hostname verification."
                ),
                compliance_support=compliance_refs,
                manual_playbook=PlaybookRef(
                    tool="Jadx-GUI / CFR",
                    objective="Decompile the flagged .class entries to trace whether untrusted input reaches the sink.",
                    steps=[
                        f"Open {jar_path.name} in Jadx-GUI and inspect: {', '.join(info['sample_classes'][:3])}.",
                        "Verify whether external socket, file, or RMI payloads reach the flagged method.",
                    ],
                ),
            )
        )

    if classes_scanned > 0 and not sink_hits:
        findings.append(
            Finding(
                check_id="TCP-MGD-002",
                title="No Unsafe Java Deserialization, RMI, or TLS Bypass Sinks in Constant Pools",
                category="Managed Code & Java Bytecode",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(jar_path),
                summary=f"Parsed JVM constant pools for {classes_scanned} .class file(s) in {jar_path.name} with zero risky sinks matched.",
                evidence={"classes_scanned": classes_scanned, "nested_jars_checked": True},
                compliance_support=compliance_refs,
            )
        )

    return findings


def scan_managed_bytecode(
    target_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Audit:
    1. UAC manifests across ALL PE executables (native C/C++ & .NET)
    2. .NET CLR assemblies via dnfile (TypeRef, MemberRef, #US)
    3. Java archives (.jar/.war/.ear + nested JARs) via JVM constant-pool parsing
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
                if fp.suffix.lower() in {".exe", ".dll", ".jar", ".war", ".ear"}:
                    candidates.append(fp)

    for item in candidates:
        try:
            if item.stat().st_size == 0 or item.stat().st_size > MAX_FILE_BYTES:
                continue
            raw_bytes = item.read_bytes()
        except OSError:
            continue

        ext = item.suffix.lower()
        if ext in {".exe", ".dll"}:
            # 1. UAC manifest check runs on ALL PE executables (native + .NET)
            findings.extend(_audit_pe_uac_manifest(item, raw_bytes, dotnet_refs))
            # 2. .NET metadata table inspection
            findings.extend(_audit_dotnet_assembly(item, raw_bytes, dotnet_refs, mapper))
        elif ext in {".jar", ".war", ".ear"}:
            findings.extend(_audit_java_archive(item, raw_bytes, java_refs))

    return findings