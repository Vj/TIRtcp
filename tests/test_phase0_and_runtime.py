"""
Regression and integration tests for TIRtcp Phase 0 Intelligence,
Frida Runtime Hook Trace Audit, Decompiled Source Rules, KEV/EPSS SCA,
Root-Cause Correlation, and Baseline Retest Diffing.
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.context import ScanContext
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    ScanReport,
    Severity,
)
from analyzer.modules.runtime_memory.frida_trace_audit import analyze_runtime_hooks
from analyzer.modules.static_audit.decompile_semgrep_audit import _scan_decompiled_tree
from analyzer.modules.static_audit.offline_vuln_db import scan_offline_vulnerabilities
from analyzer.modules.static_audit.pe_profile import profile_findings
from analyzer.modules.static_audit.string_intel import scan_string_intel

FIXTURE_MAP = Path(__file__).resolve().parent / "fixtures" / "compliance_map.test.yaml"


def _mapper() -> ComplianceMapper:
    return ComplianceMapper(FIXTURE_MAP, profile="general")


def test_frida_runtime_hook_trace_detections(tmp_path: Path) -> None:
    hooks_file = tmp_path / "runtime_hooks.json"
    hooks_file.write_text(
        json.dumps(
            {
                "target_exe": "C:\\Program Files\\DemoApp\\DemoClient.exe",
                "events": [
                    {
                        "category": "dpapi",
                        "api": "CryptProtectData",
                        "description": "UserSessionSecret",
                        "has_optional_entropy": False,
                        "flags": 0,
                    },
                    {
                        "category": "dll_load",
                        "api": "LoadLibraryW",
                        "path": "C:\\Users\\testuser\\AppData\\Local\\Temp\\plugin_helper.dll",
                        "flags": 0,
                    },
                    {
                        "category": "winhttp",
                        "api": "WinHttpOpenRequest",
                        "method": "POST",
                        "path": "/api/v1/login",
                        "tls_enabled": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = analyze_runtime_hooks(hooks_file, _mapper())
    titles = [f.title for f in findings]

    assert any("Without Optional Entropy" in t for t in titles)
    assert any("User-Writable Directory" in t for t in titles)
    assert any("Cleartext HTTP Request" in t for t in titles)


def test_decompiled_source_builtin_rules(tmp_path: Path) -> None:
    cs_file = tmp_path / "TlsValidator.cs"
    cs_file.write_text(
        """
        using System.Net.Http;
        using System.Data.SqlClient;
        public class NetHelper {
            public void Init(HttpClientHandler h, string userInput) {
                h.ServerCertificateCustomValidationCallback = (req, cert, chain, errs) => true;
                var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + userInput);
            }
        }
        """,
        encoding="utf-8",
    )

    findings = _scan_decompiled_tree(
        src_dir=tmp_path,
        origin_asset="DemoClient.dll",
        mapper=_mapper(),
        semgrep_bin=None,
        semgrep_rules=None,
    )
    titles = [f.title for f in findings]
    assert any("Unconditionally Returns True" in t for t in titles)
    assert any("String Concatenation" in t for t in titles)


def test_offline_vuln_db_kev_escalation(tmp_path: Path) -> None:
    deps_file = tmp_path / "DemoClient.deps.json"
    deps_file.write_text(
        json.dumps(
            {
                "targets": {
                    ".NETCoreApp,Version=v8.0": {
                        "Newtonsoft.Json/12.0.3": {},
                        "SafeLib/2.0.0": {},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    vuln_db = tmp_path / "offline_vulns.json"
    vuln_db.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "cve": "CVE-2024-21907",
                        "ecosystem": "NuGet",
                        "package": "Newtonsoft.Json",
                        "fixed_version": "13.0.1",
                        "severity": "Medium",
                        "cisa_kev": True,
                        "epss": 0.85,
                        "summary": "StackOverflow DoS in Newtonsoft.Json.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    ctx = ScanContext(tmp_path)
    findings = scan_offline_vulnerabilities(ctx, _mapper(), vuln_db_path=vuln_db)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "[CISA KEV]" in findings[0].title


def test_root_cause_correlation_and_baseline_diff(tmp_path: Path) -> None:
    rep = ScanReport(
        target_name="DemoClient.exe",
        engagement_id="ENG-RETEST-01",
        compliance_profile="general",
        authorized_runtime=False,
    )
    rep.add_finding(
        Finding(
            check_id="TCP-INTEL-005",
            title="Elevated Execution Requested by Manifest (requireAdministrator)",
            category="Binary Intelligence",
            status=FindingStatus.FAIL,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_asset="C:\\App\\DemoClient.exe",
            summary="Manifest requests requireAdministrator.",
        )
    )
    rep.add_finding(
        Finding(
            check_id="TCP-MGD-001",
            title="Windows Executable Requests Elevated UAC Privileges",
            category="Managed Code",
            status=FindingStatus.FAIL,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_asset="C:\\App\\DemoClient.exe",
            summary="UAC requireAdministrator detected.",
        )
    )

    rep.correlate_root_causes()
    assert len(rep.findings) == 1
    assert "corroborated_by" in rep.findings[0].evidence

    # Save baseline and test retest diffing
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(rep.to_dict()), encoding="utf-8")

    # Add one new finding and re-diff
    rep.add_finding(
        Finding(
            check_id="TCP-SEC-001",
            title="Hardcoded AWS Access Key ID",
            category="Secrets",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset="C:\\App\\config.json",
            summary="Leaked key.",
        )
    )
    diff = rep.apply_baseline_diff(baseline_path)
    assert diff["persistent_actionable"] == 1
    assert diff["new_actionable"] == 1
    assert diff["fixed_since_baseline"] == 0


def test_pe_profile_and_string_intel_redaction(tmp_path: Path) -> None:
    import scripts.create_demo_target as demo

    exe = tmp_path / "SampleClient.exe"
    exe.write_bytes(demo.minimal_pe() + b"\x00http://legacy-api.corp.local/v1/auth\x00AKIAIOSFODNN7EXAMPLE\x00")
    ctx = ScanContext(tmp_path)

    pe_res = profile_findings(exe, _mapper())
    assert any(f.check_id == "TCP-INTEL-001" for f in pe_res)

    str_res = scan_string_intel(tmp_path, _mapper(), ctx=ctx)
    serialized = json.dumps([f.to_dict() for f in str_res])
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert any("Cleartext Endpoints" in f.title for f in str_res)

def test_binary_hardening_cfg_cet_and_high_entropy_aslr(tmp_path: Path) -> None:
    import scripts.create_demo_target as demo
    from analyzer.modules.static_audit.binary_hardening import scan_binary_hardening

    exe = tmp_path / "LegacyNative.exe"
    exe.write_bytes(demo.minimal_pe())
    ctx = ScanContext(tmp_path)

    findings = scan_binary_hardening(tmp_path, _mapper(), ctx=ctx)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.FAIL
    assert "ASLR" in findings[0].title or "Control Flow Guard" in findings[0].title


def test_non_http_wire_protocol_dissectors() -> None:
    from analyzer.modules.network_protocol.wire_dissectors import inspect_wire_protocols

    payloads = [
        {"dst": "10.0.0.12", "dst_port": 5432, "data": b"\x00\x00\x00\x21\x00\x03\x00\x00user\x00sa_admin\x00database\x00core\x00\x00"},
        {"dst": "10.0.0.15", "dst_port": 1883, "data": b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06client"},
        {"dst": "10.0.0.20", "dst_port": 50051, "data": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\napplication/grpc"},
    ]
    findings = inspect_wire_protocols(payloads, "session.pcap", _mapper())
    titles = [f.title for f in findings]
    assert any("PostgreSQL" in t for t in titles)
    assert any("MQTT" in t for t in titles)
    assert any("gRPC" in t for t in titles)


def test_html_report_renders_retest_resolved_and_priority_matrix(tmp_path: Path) -> None:
    rep1 = ScanReport(
        target_name="App.exe",
        engagement_id="ENG-1",
        compliance_profile="general",
        authorized_runtime=False,
    )
    rep1.add_finding(
        Finding(
            check_id="TCP-SEC-001",
            title="Legacy Hardcoded API Secret",
            category="Secrets",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset=r"C:\App\config.ini",
            summary="Old secret.",
        )
    )
    base_json = tmp_path / "base.json"
    base_json.write_text(json.dumps(rep1.to_dict()), encoding="utf-8")

    rep2 = ScanReport(
        target_name="App.exe",
        engagement_id="ENG-2",
        compliance_profile="general",
        authorized_runtime=False,
    )
    rep2.add_finding(
        Finding(
            check_id="TCP-NET-001",
            title="Cleartext Endpoint Discovered",
            category="Network",
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            affected_asset="http://api.local",
            summary="Cleartext HTTP.",
        )
    )
    rep2.apply_baseline_diff(base_json)
    out = rep2.write_outputs(tmp_path / "out", base_name="retest_check")
    html_txt = out["html"].read_text(encoding="utf-8")
    assert "Resolved Since Baseline (1 Fixed)" in html_txt
    assert "Immediate Remediation Priorities" in html_txt


def test_pdf_exporter_graceful_handling(tmp_path: Path) -> None:
    from analyzer.core.pdf_exporter import export_html_to_pdf

    sample_html = tmp_path / "sample.html"
    sample_html.write_text("<html><body><h1>TIRtcp</h1></body></html>", encoding="utf-8")
    res = export_html_to_pdf(sample_html)
    assert res is None or res.exists()


def test_remediation_roadmap_grouping() -> None:
    rep = ScanReport(
        target_name="Client.exe",
        engagement_id="ENG-ROADMAP",
        compliance_profile="general",
        authorized_runtime=False,
    )
    rep.add_finding(
        Finding(
            check_id="TCP-SEC-001",
            title="Hardcoded DB String",
            category="Secrets",
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            affected_asset="app.config",
            summary="DB creds.",
        )
    )
    rep.add_finding(
        Finding(
            check_id="TCP-BIN-001",
            title="Missing CFG",
            category="Binary Hardening",
            status=FindingStatus.FAIL,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            affected_asset="Client.exe",
            summary="No CFG.",
        )
    )
    roadmap = rep.compute_remediation_roadmap()
    assert len(roadmap) == 2
    assert roadmap[0]["check_id"] == "TCP-SEC-001"
    assert roadmap[0]["estimated_effort"] == "Config / Vault Migration"


def test_host_trust_ca_and_firewall_hardening(tmp_path: Path) -> None:
    from analyzer.modules.host_offline.trust_firewall_audit import audit_trust_and_firewall

    evidence = {
        "security_posture": {
            "custom_root_cas": [
                {"Subject": "CN=Rogue-Intercept-Root-CA", "Thumbprint": "AABBCC112233"}
            ],
            "firewall_rules": [
                {"Direction": "Inbound", "Action": "Allow", "Program": "C:\\App\\DemoClient.exe", "RemoteAddress": "Any"}
            ],
            "credential_targets": ["DemoClient_SSO_Token"],
        }
    }
    findings = audit_trust_and_firewall(evidence, tmp_path / "DemoClient.exe", _mapper())
    titles = [f.title for f in findings]
    assert any("Non-Standard Trusted Root CA" in t for t in titles)
    assert any("Broad Inbound Windows Firewall" in t for t in titles)
    assert any("Credential Manager" in t for t in titles)


def test_crypto_sbox_and_triage_worklist(tmp_path: Path) -> None:
    import scripts.create_demo_target as demo
    from analyzer.modules.static_audit.crypto_antitamper_audit import audit_crypto_and_antitamper
    from scripts.triage_worklist import apply_triage_decisions

    exe = tmp_path / "CustomCrypto.exe"
    sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    exe.write_bytes(demo.minimal_pe() + b"\x00" + sbox + b"\x00srand\x00")
    ctx = ScanContext(tmp_path)

    findings = audit_crypto_and_antitamper(tmp_path, _mapper(), ctx=ctx)
    titles = [f.title for f in findings]
    assert any("Embedded AES S-Box" in t for t in titles)
    assert any("PRNG" in t for t in titles)

    rep_file = tmp_path / "rep.json"
    rep_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "check_id": "TCP-MGD-001",
                        "title": "Manual Review Needed",
                        "affected_asset": "CustomCrypto.exe",
                        "status": "Manual Required",
                        "severity": "Medium",
                        "evidence": {},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    dec_file = tmp_path / "decisions.json"
    dec_file.write_text(
        json.dumps(
            [
                {
                    "check_id": "TCP-MGD-001",
                    "title": "Manual Review Needed",
                    "affected_asset": "CustomCrypto.exe",
                    "status": "Fail",
                    "severity": "High",
                    "reviewer": "Lead Assessor",
                    "verdict": "Confirmed Exploitable",
                    "notes": "Verified via dnSpy.",
                }
            ]
        ),
        encoding="utf-8",
    )
    res = apply_triage_decisions(rep_file, dec_file)
    assert res["updated_findings"] == 1
    updated = json.loads(rep_file.read_text(encoding="utf-8"))
    assert updated["findings"][0]["status"] == "Fail"
    assert updated["findings"][0]["severity"] == "High"


def test_spki_pin_detection_and_triage_rerender(tmp_path: Path) -> None:
    import scripts.create_demo_target as demo
    from analyzer.modules.static_audit.crypto_antitamper_audit import audit_crypto_and_antitamper
    from scripts.triage_worklist import apply_triage_decisions

    exe = tmp_path / "PinnedApp.exe"
    pin = b"sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    exe.write_bytes(demo.minimal_pe() + b"\x00" + pin + b"\x00")
    ctx = ScanContext(tmp_path)

    findings = audit_crypto_and_antitamper(tmp_path, _mapper(), ctx=ctx)
    assert any("SPKI Public-Key Pinning" in f.title for f in findings)

    rep_file = tmp_path / "tirtcp_PinnedApp.json"
    rep_file.write_text(
        json.dumps(
            {
                "target_name": "PinnedApp.exe",
                "engagement_id": "ENG-TRIAGE",
                "compliance_profile": "general",
                "authorized_runtime": False,
                "findings": [
                    {
                        "check_id": "TCP-MGD-001",
                        "title": "Manual Review Item",
                        "category": "Managed Code",
                        "affected_asset": "PinnedApp.exe",
                        "status": "Manual Required",
                        "severity": "Medium",
                        "confidence": "Medium",
                        "summary": "Review item.",
                        "evidence": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    dec_file = tmp_path / "decisions.json"
    dec_file.write_text(
        json.dumps(
            [
                {
                    "check_id": "TCP-MGD-001",
                    "title": "Manual Review Item",
                    "affected_asset": "PinnedApp.exe",
                    "status": "Fail",
                    "severity": "Critical",
                    "reviewer": "Assessor",
                    "verdict": "Confirmed",
                    "notes": "Confirmed vulnerable.",
                }
            ]
        ),
        encoding="utf-8",
    )
    res = apply_triage_decisions(rep_file, dec_file, rerender=True)
    assert res["updated_findings"] == 1
    assert (tmp_path / "tirtcp_PinnedApp.html").exists()
    assert (tmp_path / "tirtcp_PinnedApp.sarif").exists()
