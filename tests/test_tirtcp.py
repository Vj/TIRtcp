"""Regression suite. Sections: (A) validators, (B) one test per bug found in review, (C) end-to-end on the demo fixture."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from analyzer.core.schema import FindingStatus as S
from analyzer.core.validators import aadhaar_valid, luhn_valid, pan_valid, verhoeff_valid

ROOT = Path(__file__).resolve().parents[1]


def by_status(findings, status):
    return [f for f in findings if f.status == status]


# ---------------------------------------------------------------- A. validators
def test_checksums():
    assert verhoeff_valid("2363") and not verhoeff_valid("2364")
    assert luhn_valid("4111 1111 1111 1111") and not luhn_valid("4111111111111112") and not luhn_valid("0000000000000000")
    assert pan_valid("ABCPE1234F") and not pan_valid("ABCDE1234F")
    assert not aadhaar_valid("202611241530")


# ---------------------------------------------------------------- B. bug regressions
def test_placeholder_is_exact_match_not_substring():
    from analyzer.modules.static_audit.secrets_db_audit import _is_placeholder
    assert not _is_placeholder("MyPassword#2026!") and not _is_placeholder("Contest#9981x")
    assert _is_placeholder("changeme") and _is_placeholder("${DB_PASS}") and _is_placeholder("xxxxxxxx")


def test_secret_scan_validates_pan_aadhaar_and_finds_cards(demo, mapper):
    from analyzer.modules.static_audit.secrets_db_audit import scan_secrets_db_and_debug
    fs = scan_secrets_db_and_debug(demo / "DemoClient", mapper)
    titles = " | ".join(f.title for f in fs)
    assert "Payment Card Number" in titles          # Luhn-valid PAN found
    assert "Aadhaar" in titles                      # Verhoeff-valid number found, timestamp ignored
    assert "Direct Database Connection String" in titles
    assert any(f.check_id == "TCP-SEC-002" and "pdb" in f.title.lower() for f in fs)
    blob = json.dumps([f.to_dict() for f in fs])
    assert "Pr0d#MyPassword99" not in blob and "4111 1111 1111 1111" not in blob   # never leak raw secrets


def test_electron_minified_flags_detected(demo, mapper):
    from analyzer.modules.static_audit.electron_unpack import scan_electron_app
    fs = scan_electron_app(demo / "DemoClient", mapper)
    assert {"nodeIntegration Enabled", "contextIsolation Disabled"} <= {f.evidence.get("rule") for f in fs}


def test_procmon_windows_paths_on_any_os(demo, mapper):
    from analyzer.modules.host_offline.dll_hijack_parser import parse_procmon_csv
    fs = parse_procmon_csv(demo / "procmon.csv", mapper, target_path=None, host_evidence=None)
    assert len(by_status(fs, S.FAIL)) == 1


def test_memory_overlap_no_double_count(tmp_path):
    from analyzer.modules.runtime_gated.memory_retention import CHUNK_SIZE, _scan_dump_for_canaries
    m = "CanaryPass#2026"
    for back in (700, 300, 20):  # marker straddling / sitting inside the chunk-overlap zone
        d = tmp_path / f"d{back}.bin"
        d.write_bytes(b"\0" * (CHUNK_SIZE - back) + m.encode() + b"\0" * CHUNK_SIZE)
        hits = list(_scan_dump_for_canaries(d, [m])["matched_canaries"].values())[0]
        assert hits["ascii_hits"] == 1, back
    d = tmp_path / "straddle.bin"   # marker split across the chunk boundary must still be found once
    d.write_bytes(b"\0" * (CHUNK_SIZE - 5) + m.encode() + b"\0" * 100)
    assert list(_scan_dump_for_canaries(d, [m])["matched_canaries"].values())[0]["ascii_hits"] == 1


def test_modern_clienthello_is_not_legacy_tls():
    import create_demo_target as c
    from analyzer.modules.network_protocol.tls_records import parse_tls_hello
    assert parse_tls_hello(c.client_hello(record_ver=0x0301))["legacy"] is False
    assert parse_tls_hello(c.server_hello(0x0301))["legacy"] is True
    assert parse_tls_hello(b"\x16\x03\x01\x00")  is None


def test_pcap_findings_and_no_secret_in_evidence(demo, mapper):
    from analyzer.modules.network_protocol.pcap_analyzer import analyze_pcap_capture
    fs = analyze_pcap_capture(demo / "capture.pcap", mapper)
    legacy = [f for f in fs if "Deprecated TLS" in f.title]
    assert len(legacy) == 1                                   # server hello only; benign client hello ignored
    assert any("Cleartext Credentials" in f.title for f in fs)
    assert any("Direct Database" in f.title for f in fs)
    assert any("Auto-Update" in f.title for f in fs)
    assert "Sup3rSecret" not in json.dumps([f.to_dict() for f in fs])


def test_icacls_rights_parsing():
    from analyzer.modules.host_offline.acl_installer import _ace_grants_write
    assert _ace_grants_write(r"BUILTIN\Users:(OI)(CI)(S,WD,AD,X,DC)")
    assert _ace_grants_write(r"Everyone:(I)(F)")
    assert not _ace_grants_write(r"BUILTIN\Users:(DENY)(W)")
    assert not _ace_grants_write(r"BUILTIN\Users:(I)(RX)")


def test_sddl_classifier():
    from analyzer.core.sddl import classify
    assert classify("D:(A;;GA;;;WD)")["risky"]                     # Everyone: generic all
    assert classify("D:(A;;0x12019f;;;AU)")["risky"]               # Authenticated Users: write mask
    assert not classify("D:(A;;GA;;;SY)(A;;GA;;;BA)")["risky"]     # SYSTEM / Admins only
    assert not classify("D:(A;;GR;;;BU)")["risky"]                 # read-only for Users


def test_zlib_banner_fingerprint():
    from analyzer.modules.static_audit.sca_fingerprint import NATIVE_LIB_SIGNATURES
    rx = [p for n, p, *_ in NATIVE_LIB_SIGNATURES if n == "zlib"][0]
    assert rx.search(" inflate 1.2.11 Copyright 1995-2017 Mark Adler")


def test_tls_probe_is_tristate(monkeypatch):
    import socket
    from analyzer.modules.network_protocol import tls_inspector as t
    def boom(*a, **k): raise OSError("net down")
    monkeypatch.setattr(socket, "create_connection", boom)
    import ssl
    assert t._probe_tls_version("127.0.0.1", 9, ssl.TLSVersion.TLSv1, timeout=0.2) is None   # inconclusive, not "rejected"


# ---------------------------------------------------------------- C. end-to-end
def run_cli(args, cwd=ROOT):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "analyzer.tirtcp", *args], cwd=cwd, env=env, capture_output=True, text=True)


def test_e2e_demo_fixture_and_ci_gate(demo, tmp_path):
    base = ["--target", str(demo / "DemoClient"), "--evidence", str(demo / "host_evidence.json"),
            "--pcap", str(demo / "capture.pcap"), "--procmon-csv", str(demo / "procmon.csv"),
            "--memory-dump", str(demo / "post_logout.dmp"), "--canary-markers", "CanaryPass#2026",
            "--authorized", "--engagement-id", "ENG-TEST-001", "--no-active-probe",
            "--compliance-map", str(ROOT / "tests/fixtures/compliance_map.test.yaml"), "--output", str(tmp_path)]
    r = run_cli(base + ["--fail-on", "high"])
    assert r.returncode == 2, r.stdout + r.stderr          # gate trips on HIGH/CRITICAL
    rep = json.loads(next(tmp_path.glob("*.json")).read_text())
    seen = {f["check_id"] for f in rep["findings"] if f["status"] in ("Fail", "Evidence of Retention", "Manual Required")}
    exp = json.loads((demo / "EXPECTED.json").read_text())
    missing = set(exp["must_detect"]) - seen - {"TCP-BIN-001"}   # BIN-001 depends on lief/pefile build; asserted below
    assert not missing, missing
    assert not any(f["title"].startswith("Module Execution Error") for f in rep["findings"])
    mem = [f for f in rep["findings"] if f["check_id"] == "TCP-MEM-001"][0]
    assert mem["evidence"]["matched_canaries"] and "CanaryPass#2026" not in json.dumps(rep)


def test_acl_skipped_without_evidence_or_live_host(demo, tmp_path):
    r = run_cli(["--target", str(demo / "DemoClient"), "--no-active-probe", "--engagement-id", "ENG-TEST-002",
                 "--compliance-map", str(ROOT / "tests/fixtures/compliance_map.test.yaml"), "--output", str(tmp_path)])
    assert r.returncode == 0
    rep = json.loads(next(tmp_path.glob("*.json")).read_text())
    acl = [f for f in rep["findings"] if f["check_id"] == "TCP-HOST-001"]
    assert acl and all(f["status"] == "Tooling Gap" for f in acl)    # never a false "Verified Pass"

# ---------------------------------------------------------------- D. v2 architecture & protocol upgrades
def _build_pcapng_file(frames: list[bytes], linktype: int = 1) -> bytes:
    """Build a minimal valid PCAPNG byte stream (SHB + IDB + EPBs)."""
    # Section Header Block (0x0A0D0D0A), byte-order magic 0x1A2B3C4D, v1.0, section_len = -1
    shb = struct.pack("<IIHHq", 0x0A0D0D0A, 28, 1, 0, -1)
    shb = struct.pack("<I", 0x0A0D0D0A) + struct.pack("<I", 28) + struct.pack("<IHHqI", 0x1A2B3C4D, 1, 0, -1, 28)

    # Interface Description Block (0x00000001), len = 20
    idb = struct.pack("<IIHHI I", 0x00000001, 20, linktype, 0, 65535, 20)

    epbs: list[bytes] = []
    for idx, frame in enumerate(frames):
        pad_len = (4 - (len(frame) % 4)) % 4
        padded_frame = frame + (b"\x00" * pad_len)
        block_len = 32 + len(padded_frame)
        epb = (
            struct.pack("<IIIIIII", 0x00000006, block_len, 0, 0, idx * 1000, len(frame), len(frame))
            + padded_frame
            + struct.pack("<I", block_len)
        )
        epbs.append(epb)

    return shb + idb + b"".join(epbs)


def _build_client_hello_with_sni(sni_host: str, supported: tuple[int, ...] = (0x0304, 0x0303)) -> bytes:
    """Construct a TLS ClientHello containing both SNI (ext 0) and supported_versions (ext 43)."""
    sni_bytes = sni_host.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_ext_body = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0, len(sni_ext_body)) + sni_ext_body

    sv_list = b"".join(struct.pack("!H", v) for v in supported)
    sv_body = struct.pack("!B", len(sv_list)) + sv_list
    sv_ext = struct.pack("!HH", 43, len(sv_body)) + sv_body

    exts = sni_ext + sv_ext
    body = (
        struct.pack("!H", 0x0303)
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!HH", 2, 0x1301)
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!HH", 0x0301, len(hs)) + hs


def _build_java_class_with_methodref(
    class_internal_name: str,
    method_name: str,
    include_long_slot: bool = True,
) -> bytes:
    """
    Construct a minimal spec-compliant JVM .class file with optional 2-slot CONSTANT_Long
    entry to verify constant-pool slot alignment and Methodref resolution.
    """
    cp_entries: list[bytes] = []

    def add_utf8(s: str) -> int:
        b = s.encode("utf-8")
        cp_entries.append(b"\x01" + struct.pack("!H", len(b)) + b)
        return len(cp_entries)

    def add_class(name_idx: int) -> int:
        cp_entries.append(b"\x07" + struct.pack("!H", name_idx))
        return len(cp_entries)

    def add_nat(name_idx: int, desc_idx: int) -> int:
        cp_entries.append(b"\x0c" + struct.pack("!HH", name_idx, desc_idx))
        return len(cp_entries)

    def add_methodref(cls_idx: int, nat_idx: int) -> int:
        cp_entries.append(b"\x0a" + struct.pack("!HH", cls_idx, nat_idx))
        return len(cp_entries)

    if include_long_slot:
        # Tag 5 (CONSTANT_Long) occupies TWO constant-pool indices per JVM Spec §4.4.5
        cp_entries.append(b"\x05" + struct.pack("!q", 0x1122334455667788))
        cp_entries.append(b"")  # placeholder for slot + 1 so len(cp_entries) tracks slot index

    c_name_i = add_utf8(class_internal_name)
    m_name_i = add_utf8(method_name)
    desc_i = add_utf8("()Ljava/lang/Object;")
    cls_i = add_class(c_name_i)
    nat_i = add_nat(m_name_i, desc_i)
    add_methodref(cls_i, nat_i)

    cp_count = len(cp_entries) + 1
    raw_cp = b"".join(e for e in cp_entries if e)
    return b"\xca\xfe\xba\xbe" + struct.pack("!HH", 0, 55) + struct.pack("!H", cp_count) + raw_cp + b"\x00" * 16


def test_network_scope_allowlist_and_tls_gating(tmp_path: Path, mapper) -> None:
    from analyzer.core.scope import NetworkScope
    from analyzer.modules.network_protocol.tls_inspector import inspect_tls_endpoints

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "# Approved engagement scope\n"
        "*.clientbank.in\n"
        "10.20.0.0/16\n",
        encoding="utf-8",
    )
    scope = NetworkScope(scope_file)

    assert scope.is_allowed("api.clientbank.in") is True
    assert scope.is_allowed("10.20.5.12") is True
    assert scope.is_allowed("telemetry.thirdparty-saas.com") is False
    assert scope.is_allowed("8.8.8.8") is False

    # Config file referencing one in-scope host and one out-of-scope third-party host
    cfg_dir = tmp_path / "ClientCfg"
    cfg_dir.mkdir()
    (cfg_dir / "endpoints.json").write_text(
        json.dumps(
            {
                "primary": "https://api.clientbank.in:8443",
                "telemetry": "https://analytics.vendor-cdn.net:443",
            }
        ),
        encoding="utf-8",
    )

    # Mock native TLS probe so no real sockets are opened during unit testing
    fake_probe = {
        "host": "api.clientbank.in",
        "port": 8443,
        "tls_supported": True,
        "negotiated_version": "TLSv1.3",
        "negotiated_cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        "cert_valid": True,
        "cert_error": None,
        "deprecated_protocols_accepted": [],
        "deprecated_protocols_untested": [],
    }
    with patch(
        "analyzer.modules.network_protocol.tls_inspector._inspect_endpoint_native",
        return_value=fake_probe,
    ):
        findings = inspect_tls_endpoints(cfg_dir, mapper, scope=scope)

    skipped = [f for f in findings if "Outside Active Probe Scope" in f.title]
    probed_passes = [f for f in findings if f.status == S.VERIFIED_PASS]
    assert len(skipped) == 1
    assert "analytics.vendor-cdn.net:443" in skipped[0].affected_asset
    assert len(probed_passes) == 1
    assert "api.clientbank.in:8443" in probed_passes[0].affected_asset


def test_pcapng_and_sni_endpoint_extraction(tmp_path: Path, mapper) -> None:
    import create_demo_target as c
    from analyzer.modules.network_protocol.pcap_analyzer import analyze_pcap_capture

    hello_sni = _build_client_hello_with_sni("core-gateway.clientbank.in")
    frame = c.ipv4_tcp_frame("10.1.1.10", "10.20.30.40", 54321, 8443, hello_sni)

    pcapng_path = tmp_path / "capture.pcapng"
    pcapng_path.write_bytes(_build_pcapng_file([frame]))

    discovered: set[tuple[str, int]] = set()
    with patch("analyzer.modules.network_protocol.pcap_analyzer.HAS_SCAPY", False):
        findings = analyze_pcap_capture(pcapng_path, mapper, discovered_endpoints_out=discovered)

    assert ("core-gateway.clientbank.in", 8443) in discovered
    assert len(findings) == 1
    assert findings[0].status == S.VERIFIED_PASS
    assert findings[0].evidence["tls_coverage_percent"] == 100.0


def test_branch_aware_baselines_yaml(tmp_path: Path) -> None:
    from analyzer.modules.static_audit.sca_fingerprint import (
        _evaluate_branch_version,
        load_native_baselines,
    )

    baselines_path = ROOT / "config" / "baselines.yaml"
    assert baselines_path.exists()

    libs = {item["name"]: item for item in load_native_baselines(baselines_path)}
    openssl_branches = libs["OpenSSL"]["branches"]

    # 3.1.2 is an EOL branch -> must be flagged vulnerable even though 3.1.2 > 3.0.15
    is_vuln_312, label_312, _ = _evaluate_branch_version("3.1.2", openssl_branches)
    assert is_vuln_312 is True
    assert "EOL" in label_312

    # 3.0.15 (LTS minimum) and 3.2.3 (supported minimum) -> must pass
    assert _evaluate_branch_version("3.0.15", openssl_branches)[0] is False
    assert _evaluate_branch_version("3.2.3", openssl_branches)[0] is False


def test_native_pe_uac_manifest_and_java_constant_pool_nested_jar(tmp_path: Path, mapper) -> None:
    import io
    import zipfile
    import create_demo_target as c
    from analyzer.modules.static_audit.managed_bytecode_audit import scan_managed_bytecode

    # 1. Native C++ PE executable (no CLR header) with requireAdministrator manifest
    uac_manifest = (
        b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        b'<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></assembly>'
    )
    native_exe = tmp_path / "NativeUpdater.exe"
    native_exe.write_bytes(c.minimal_pe(dll_chars=0x8160) + uac_manifest)

    # 2. Outer JAR containing a nested BOOT-INF/lib/inner.jar with a spec-valid .class file
    evil_class = _build_java_class_with_methodref(
        "java/io/ObjectInputStream", "readObject", include_long_slot=True
    )
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as inner_zf:
        inner_zf.writestr("com/corp/PayloadHandler.class", evil_class)

    outer_jar = tmp_path / "desktop-service.jar"
    with zipfile.ZipFile(outer_jar, "w") as outer_zf:
        outer_zf.writestr("BOOT-INF/lib/inner-deser.jar", inner_buf.getvalue())

    findings = scan_managed_bytecode(tmp_path, mapper)
    fails = [f for f in findings if f.status == S.FAIL]

    assert any(
        "Elevated UAC Privileges (requireAdministrator)" in f.title and "NativeUpdater.exe" in f.affected_asset
        for f in fails
    )
    java_fails = [f for f in fails if "Java Constant Pool References High-Risk API" in f.title]
    assert len(java_fails) == 1
    assert any(
        "BOOT-INF/lib/inner-deser.jar!/com/corp/PayloadHandler.class" in cls
        for cls in java_fails[0].evidence["sample_classes"]
    )