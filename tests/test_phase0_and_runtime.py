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