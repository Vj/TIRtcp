"""
TIRtcp Unified Regression & Validation Suite (Phases 1–4).
Covers:
  1. Compliance Scoping & Guardrails (general vs. bfsi, PCI DSS v4.0.1, CERT-In informational)
  2. Static Binary Hardening (PE x64 vs. x86-only SafeSEH)
  3. Secrets, Direct DB Connection Strings, PDB Debug Artifacts & DPDP Log PII Leaks
  4. Hybrid SCA & Native C/C++ DLL Version Fingerprinting
  5. Offline Network PCAP Analyzer (Cleartext Auth, Direct DB Wire, Legacy TLS, HTTP Updaters)
  6. Electron Fuses, Pure-Python ASAR Unpacking & webPreferences
  7. Managed Bytecode (.NET CLR Manifest/Deserialization/DPAPI & Java JAR Constant-Pool Sinks)
  8. Host ACLs, Procmon DLL Search-Order Hijack CSV Parser & Offline IPC/COM/URI Audit
  9. Authorization Gate & Gated Post-Logout Memory Hygiene
 10. Multi-Format Report Projections (JSON, SARIF v2.1.0, HTML)

Run with: pytest -v tests/test_tirtcp.py
"""

from __future__ import annotations

import csv
import json
import os
import stat
import struct
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from analyzer.core.auth_gate import evaluate_authorization_gate
from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    ComplianceRelation,
    Confidence,
    FindingStatus,
    ScanReport,
    Severity,
)
from analyzer.modules.host_offline.acl_installer import scan_filesystem_acls
from analyzer.modules.host_offline.dll_hijack_parser import parse_procmon_csv
from analyzer.modules.host_offline.ipc_uri_audit import audit_ipc_and_handlers
from analyzer.modules.network_protocol.pcap_analyzer import analyze_pcap_capture
from analyzer.modules.runtime_gated.memory_retention import analyze_post_logout_memory
from analyzer.modules.static_audit.binary_hardening import (
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_NO_SEH,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    scan_binary_hardening,
)
from analyzer.modules.static_audit.electron_unpack import (
    FUSE_SENTINEL,
    scan_electron_app,
)
from analyzer.modules.static_audit.managed_bytecode_audit import scan_managed_bytecode
from analyzer.modules.static_audit.sca_fingerprint import scan_dependencies_and_native_libs
from analyzer.modules.static_audit.secrets_db_audit import scan_secrets_db_and_debug


@pytest.fixture
def compliance_map_path() -> Path:
    path = Path(__file__).resolve().parent.parent / "config" / "compliance_map.yaml"
    assert path.exists(), f"compliance_map.yaml not found at {path}"
    return path


# ---------------------------------------------------------------------------
# Shared Synthetic Binary & Archive Builders
# ---------------------------------------------------------------------------
def _build_minimal_pe(
    machine: int,
    dll_characteristics: int,
    *,
    is_dotnet: bool = False,
    clr_flags: int = 0x01,
    trailing_payload: bytes = b"",
) -> bytes:
    """Construct a syntactically valid Windows PE32 / PE32+ (optional .NET CLR header)."""
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    pe_sig = b"PE\x00\x00"
    is_64 = machine == IMAGE_FILE_MACHINE_AMD64
    opt_size = 0xF0 if is_64 else 0xE0

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        1,          # NumberOfSections
        0,
        0,
        0,
        opt_size,
        0x0102,
    )

    opt_header = bytearray(opt_size)
    struct.pack_into("<H", opt_header, 0, 0x020B if is_64 else 0x010B)
    struct.pack_into("<I", opt_header, 0x38, 0x1000)
    struct.pack_into("<I", opt_header, 0x3C, 0x0200)
    struct.pack_into("<I", opt_header, 0x50, 0x3000)
    struct.pack_into("<I", opt_header, 0x54, 0x0200)
    struct.pack_into("<H", opt_header, 0x46, dll_characteristics)

    # Set DataDirectory[14] (COM Descriptor / CLR Header) if is_dotnet=True
    if is_dotnet:
        dd14_offset = 224 if is_64 else 208
        struct.pack_into("<II", opt_header, dd14_offset, 0x1000, 0x48)

    sec_header = bytearray(40)
    sec_header[0:5] = b".text"
    struct.pack_into("<I", sec_header, 8, 0x400)    # VirtualSize
    struct.pack_into("<I", sec_header, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", sec_header, 16, 0x400)   # SizeOfRawData
    struct.pack_into("<I", sec_header, 20, 0x200)   # PointerToRawData

    header_block = (bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + bytes(sec_header)).ljust(
        0x200, b"\x00"
    )

    section_body = bytearray(0x400)
    if is_dotnet:
        # Minimal COR20 header at RVA 0x1000 (file offset 0x200)
        struct.pack_into("<IHH", section_body, 0, 0x48, 2, 5)
        struct.pack_into("<I", section_body, 16, clr_flags)

    return header_block + bytes(section_body) + trailing_payload


def _build_eth_ipv4_tcp_packet(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes
) -> bytes:
    eth_header = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    ip_total_len = 40 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 1234, 0, 64, 6, 0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 1, 1, (5 << 4), 0x18, 65535, 0, 0
    )
    frame = eth_header + ip_header + tcp_header + payload
    return struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame


def _build_pcap_file(packets: list[bytes]) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(packets)


def _build_asar_archive(files: dict[str, bytes]) -> bytes:
    file_table: dict[str, dict[str, object]] = {"files": {}}
    body_chunks: list[bytes] = []
    offset = 0
    for name, content in files.items():
        file_table["files"][name] = {"offset": str(offset), "size": len(content)}
        body_chunks.append(content)
        offset += len(content)

    json_bytes = json.dumps(file_table).encode("utf-8")
    padded_json = json_bytes + (b"\x00" * ((4 - (len(json_bytes) % 4)) % 4))
    header_size = 8 + len(padded_json)
    pickle_header = struct.pack("<IIII", 4, header_size, header_size - 4, len(json_bytes))
    return pickle_header + padded_json + b"".join(body_chunks)


# ---------------------------------------------------------------------------
# 1. Compliance Scope & Guardrail Tests
# ---------------------------------------------------------------------------
def test_compliance_profile_scoping(compliance_map_path: Path) -> None:
    general_mapper = ComplianceMapper(compliance_map_path, profile="general")
    bfsi_mapper = ComplianceMapper(compliance_map_path, profile="bfsi")

    gen_frameworks = {r.framework for r in general_mapper.resolve("TCP-BIN-002")}
    assert "CWE" in gen_frameworks
    assert "PCI_DSS" not in gen_frameworks
    assert "RBI_DPSC" not in gen_frameworks

    bfsi_frameworks = {r.framework: r.version for r in bfsi_mapper.resolve("TCP-BIN-002")}
    assert bfsi_frameworks.get("PCI_DSS") == "4.0.1"
    assert bfsi_frameworks.get("RBI_DPSC") == "2021"

    cert_in = [r for r in general_mapper.resolve("TCP-SEC-002") if r.framework == "CERT_IN"]
    assert len(cert_in) == 1
    assert cert_in[0].relation == ComplianceRelation.INFORMATIONAL_SUPPORT


# ---------------------------------------------------------------------------
# 2. Static Binary Hardening (x64 vs. x86 SafeSEH)
# ---------------------------------------------------------------------------
def test_binary_hardening_x64_and_x86(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="general")

    full_x64 = (
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_GUARD_CF
    )
    (tmp_path / "Hardened64.exe").write_bytes(_build_minimal_pe(IMAGE_FILE_MACHINE_AMD64, full_x64))
    (tmp_path / "Weak64.exe").write_bytes(_build_minimal_pe(IMAGE_FILE_MACHINE_AMD64, 0x0000))

    x86_no_safeseh = (
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_GUARD_CF
    )
    (tmp_path / "Weak32.exe").write_bytes(_build_minimal_pe(IMAGE_FILE_MACHINE_I386, x86_no_safeseh))
    (tmp_path / "Hardened32.exe").write_bytes(
        _build_minimal_pe(IMAGE_FILE_MACHINE_I386, x86_no_safeseh | IMAGE_DLLCHARACTERISTICS_NO_SEH)
    )

    by_asset = {Path(f.affected_asset).name: f for f in scan_binary_hardening(tmp_path, mapper)}
    assert by_asset["Hardened64.exe"].status == FindingStatus.VERIFIED_PASS
    assert by_asset["Weak64.exe"].status == FindingStatus.FAIL
    assert by_asset["Hardened32.exe"].status == FindingStatus.VERIFIED_PASS
    assert by_asset["Weak32.exe"].evidence["missing_mitigations"] == ["SafeSEH (x86)"]


# ---------------------------------------------------------------------------
# 3. Secrets, Direct DB Connection Strings, PDBs & DPDP Log PII Leaks
# ---------------------------------------------------------------------------
def test_secrets_db_pdb_and_log_leaks(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="bfsi")

    (tmp_path / "App.exe.config").write_text(
        '<add name="DB" connectionString="Server=10.20.30.40;User ID=sa_app;Password=SuperSecretDB#2026;" />',
        encoding="utf-8",
    )
    (tmp_path / "App.pdb").write_bytes(b"Microsoft C/C++ MSF 7.00\r\n")
    (tmp_path / "client.log").write_text(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload12345.sig98765\nPAN=ABCDE1234F\n",
        encoding="utf-8",
    )

    fails = [f for f in scan_secrets_db_and_debug(tmp_path, mapper) if f.status == FindingStatus.FAIL]
    db_f = [f for f in fails if "Direct Database Connection String" in f.title]
    assert len(db_f) == 1
    assert db_f[0].severity == Severity.CRITICAL
    assert "SuperSecretDB#2026" not in json.dumps(db_f[0].evidence)
    assert any("PDB" in f.title for f in fails)
    assert len([f for f in fails if "Sensitive Data or PII Logged Locally" in f.title]) == 2


# ---------------------------------------------------------------------------
# 4. Hybrid SCA & Native C/C++ DLL Version Fingerprinting
# ---------------------------------------------------------------------------
def test_native_dll_version_fingerprinting(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="general")
    (tmp_path / "crypto.dll").write_bytes(b"MZ\x90\x00OpenSSL 1.1.1k  25 Mar 2021\x00libcurl/7.68.0\x00")

    with patch("analyzer.modules.static_audit.sca_fingerprint.shutil.which", return_value=None):
        findings = scan_dependencies_and_native_libs(tmp_path, mapper)

    fails = [f for f in findings if f.status == FindingStatus.FAIL]
    assert len(fails) == 2
    assert any("OpenSSL 1.1.1k" in f.title for f in fails)
    assert any("libcurl 7.68.0" in f.title for f in fails)


# ---------------------------------------------------------------------------
# 5. Offline PCAP Wire-Protocol Analyzer
# ---------------------------------------------------------------------------
def test_pcap_analyzer_detects_wire_risks(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="bfsi")
    pkts = [
        _build_eth_ipv4_tcp_packet(
            "10.0.0.5", 5001, "10.0.0.10", 80,
            b"POST /login HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n",
        ),
        _build_eth_ipv4_tcp_packet(
            "10.0.0.5", 5002, "10.0.0.20", 1433, b"\x12\x01\x00\x2f\x00\x00\x01\x00" + b"\x00" * 16
        ),
        _build_eth_ipv4_tcp_packet(
            "10.0.0.5", 5003, "10.0.0.30", 8443, b"\x16\x03\x01\x00\x10" + b"\x01" * 16
        ),
        _build_eth_ipv4_tcp_packet(
            "10.0.0.5", 5004, "10.0.0.40", 80,
            b"GET /patch/Setup_2.0.exe HTTP/1.1\r\nHost: update.corp.local\r\n\r\n",
        ),
    ]
    pcap_file = tmp_path / "capture.pcap"
    pcap_file.write_bytes(_build_pcap_file(pkts))

    with patch("analyzer.modules.network_protocol.pcap_analyzer.HAS_SCAPY", False):
        fails = [f for f in analyze_pcap_capture(pcap_file, mapper) if f.status == FindingStatus.FAIL]

    assert len(fails) == 4


# ---------------------------------------------------------------------------
# 6. Electron Fuses & Pure-Python ASAR Unpacking
# ---------------------------------------------------------------------------
def test_electron_fuses_and_asar_audit(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="general")
    app_dir = tmp_path / "ElectronApp"
    res_dir = app_dir / "resources"
    res_dir.mkdir(parents=True)

    fuse_blob = FUSE_SENTINEL + bytes([1, 6]) + b"101000"
    (app_dir / "ElectronApp.exe").write_bytes(b"MZ\x90\x00" + fuse_blob + b"\x00Electron/24.1.0\x00")
    main_js = b"app.setAsDefaultProtocolClient('finapp'); new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });"
    (res_dir / "app.asar").write_bytes(_build_asar_archive({"main.js": main_js}))

    findings = scan_electron_app(app_dir, mapper)
    fails = [f for f in findings if f.status == FindingStatus.FAIL]
    assert any("Insecure Electron Fuses Configuration" in f.title for f in fails)
    assert any("nodeIntegration Enabled" in f.title for f in fails)
    assert any("contextIsolation Disabled" in f.title for f in fails)


# ---------------------------------------------------------------------------
# 7. Managed Bytecode (.NET CLR & Java JAR)
# ---------------------------------------------------------------------------
def test_managed_bytecode_dotnet_and_java(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="general")

    # .NET assembly with requireAdministrator manifest, BinaryFormatter, DPAPI, and no strong name
    manifest = (
        b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        b'<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></assembly>'
    )
    dotnet_bytes = _build_minimal_pe(
        IMAGE_FILE_MACHINE_AMD64,
        0x8160,
        is_dotnet=True,
        clr_flags=0x01,  # ILONLY only (not strong-name signed)
        trailing_payload=manifest + b"\x00BinaryFormatter\x00ProtectedData\x00",
    )
    (tmp_path / "DotNetClient.exe").write_bytes(dotnet_bytes)

    # Java JAR with ObjectInputStream.readObject sink
    jar_path = tmp_path / "legacy-client.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr("com/corp/NetClient.class", b"\xca\xfe\xba\xbejava/io/ObjectInputStream\x00readObject")

    findings = scan_managed_bytecode(tmp_path, mapper)
    fails = [f for f in findings if f.status == FindingStatus.FAIL]
    manuals = [f for f in findings if f.status == FindingStatus.MANUAL_REQUIRED]

    assert any("requireAdministrator" in f.title for f in fails)
    assert any("Unsafe .NET Deserialization API" in f.title for f in fails)
    assert any("Lacks Strong-Name Signature" in f.title for f in fails)
    assert any("Java Archive References High-Risk API" in f.title for f in fails)
    assert any("DPAPI" in f.title for f in manuals)


# ---------------------------------------------------------------------------
# 8. Host ACLs, Procmon DLL Hijack CSV & Offline IPC/COM/URI Audit
# ---------------------------------------------------------------------------
def test_host_acls_procmon_and_ipc(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="bfsi")

    procmon_csv = tmp_path / "trace.csv"
    with procmon_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["Time of Day", "Process Name", "PID", "Operation", "Path", "Result"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "Time of Day": "10:00:01",
                "Process Name": "Client.exe",
                "PID": "1234",
                "Operation": "Load Image",
                "Path": r"C:\Users\analyst\AppData\Local\Client\hijack.dll",
                "Result": "NAME NOT FOUND",
            }
        )

    dll_fails = [f for f in parse_procmon_csv(procmon_csv, mapper) if f.status == FindingStatus.FAIL]
    assert len(dll_fails) == 1

    mock_evidence = {
        "hostname": "CORP-VDI-01",
        "weak_acls": [{"path": r"C:\Program Files\Client\updater\upd.exe", "principal": r"BUILTIN\Users"}],
        "custom_uri_handlers": [{"scheme": "corpapp", "command": '"C:\\App.exe" %1', "unquoted_url_argument": True}],
        "scheduled_tasks": [{"task_name": r"\CorpSync", "task_to_run": r"C:\sync.exe", "run_as_user": "SYSTEM"}],
    }
    acl_fails = scan_filesystem_acls(None, mapper, host_evidence=mock_evidence)
    ipc_fails = [f for f in audit_ipc_and_handlers(mock_evidence, mapper) if f.status == FindingStatus.FAIL]
    assert len(acl_fails) == 1
    assert len(ipc_fails) == 2


# ---------------------------------------------------------------------------
# 9. Authorization Gate & Gated Post-Logout Memory Hygiene
# ---------------------------------------------------------------------------
def test_auth_gate_and_memory_retention(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="bfsi")
    canary = "CanarySecret#9988"
    dump_file = tmp_path / "logout.dmp"
    dump_file.write_bytes(
        canary.encode("utf-8") + b"\x00" + canary.encode("utf-8") + b"\x00" + canary.encode("utf-16le")
    )

    blocked = analyze_post_logout_memory(dump_file, mapper, authorized_flag=False, engagement_id="ENG-2026-01")
    assert blocked[0].status == FindingStatus.TOOLING_GAP

    assert evaluate_authorization_gate(True, "UNASSIGNED-ENGAGEMENT").allowed is False

    allowed = analyze_post_logout_memory(
        dump_file, mapper, authorized_flag=True, engagement_id="ENG-2026-01", canary_markers=[canary]
    )
    assert allowed[0].status == FindingStatus.EVIDENCE_OF_RETENTION
    assert allowed[0].confidence == Confidence.HIGH
    assert canary not in json.dumps(allowed[0].evidence)


# ---------------------------------------------------------------------------
# 10. Multi-Format Report Projections (JSON, SARIF v2.1.0, HTML)
# ---------------------------------------------------------------------------
def test_report_projections(tmp_path: Path, compliance_map_path: Path) -> None:
    mapper = ComplianceMapper(compliance_map_path, profile="bfsi")
    app_dir = tmp_path / "SampleClient"
    app_dir.mkdir()
    (app_dir / "SampleClient.exe").write_bytes(_build_minimal_pe(IMAGE_FILE_MACHINE_AMD64, 0x0000))

    report = ScanReport("SampleClient", "ENG-2026-TEST", "bfsi", authorized_runtime=False)
    for f in scan_binary_hardening(app_dir, mapper):
        report.add_finding(f)

    written = report.write_outputs(tmp_path / "reports", base_name="unified_test")
    assert json.loads(written["json"].read_text(encoding="utf-8"))["summary"]["Fail"] == 1
    assert json.loads(written["sarif"].read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "ENG-2026-TEST" in written["html"].read_text(encoding="utf-8")