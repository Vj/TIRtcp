"""
TIRtcp P1 Static Audit Module: Headless Decompilation (.NET ilspycmd / Java jadx) + Semgrep/Code Rules
Turns low/medium-confidence binary leads into high-confidence source-level findings when
ilspycmd, jadx, or semgrep are available on PATH.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

# Built-in fallback code patterns applied to decompiled C#/Java when semgrep is not installed
DECOMPILED_CODE_RULES: List[Tuple[str, str, re.Pattern[str], Severity, str]] = [
    (
        "TCP-MGD-001",
        "Decompiled .NET TLS Validation Callback Unconditionally Returns True",
        re.compile(
            r"ServerCertificate(?:Custom)?ValidationCallback\s*(?:\+=|=)\s*(?:\([^)]*\)\s*=>\s*true\b|delegate\s*\([^)]*\)\s*\{\s*return\s+true\s*;)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Decompiled C# source explicitly bypasses TLS certificate validation by returning true.",
    ),
    (
        "TCP-MGD-001",
        "Decompiled .NET SQL Command Built via String Concatenation / Interpolation",
        re.compile(
            r"new\s+(?:Sql|Npgsql|MySql|Oracle|Sqlite)Command\s*\(\s*(?:\$\"|\"[^\"]+\"\s*\+)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Decompiled C# source constructs database queries using string interpolation or concatenation.",
    ),
    (
        "TCP-MGD-002",
        "Decompiled Java X509TrustManager With Empty checkServerTrusted()",
        re.compile(
            r"void\s+checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\{\s*(?://[^\n]*\n\s*)?\}",
            re.MULTILINE,
        ),
        Severity.HIGH,
        "Decompiled Java TrustManager implements an empty checkServerTrusted() method, accepting any TLS certificate.",
    ),
    (
        "TCP-MGD-002",
        "Decompiled Java ProcessBuilder / Runtime.exec Command Execution",
        re.compile(
            r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Decompiled Java code invokes OS command execution APIs; verify input sanitization.",
    ),
]


def _decompile_dotnet(pe_path: Path, out_dir: Path, ilspy_bin: str) -> bool:
    proc = subprocess.run(
        [ilspy_bin, "-p", "-o", str(out_dir), str(pe_path)],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    return proc.returncode == 0 and any(out_dir.rglob("*.cs"))


def _decompile_java(jar_path: Path, out_dir: Path, jadx_bin: str) -> bool:
    proc = subprocess.run(
        [jadx_bin, "--no-res", "--no-imports", "-d", str(out_dir), str(jar_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return proc.returncode == 0 and any(out_dir.rglob("*.java"))


def _run_semgrep(src_dir: Path, rules_path: Optional[Path], semgrep_bin: str) -> List[Dict[str, Any]]:
    cmd = [semgrep_bin, "--json", "--quiet", str(src_dir)]
    if rules_path and rules_path.exists():
        cmd.extend(["--config", str(rules_path)])
    else:
        cmd.extend(["--config", "p/csharp", "--config", "p/java"])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
        return data.get("results", [])
    except Exception:
        return []


def _scan_decompiled_tree(
    src_dir: Path,
    origin_asset: str,
    mapper: ComplianceMapper,
    semgrep_bin: Optional[str],
    semgrep_rules: Optional[Path],
) -> List[Finding]:
    findings: List[Finding] = []

    if semgrep_bin:
        sg_results = _run_semgrep(src_dir, semgrep_rules, semgrep_bin)
        for item in sg_results[:50]:
            extra = item.get("extra", {})
            sev_raw = (extra.get("severity") or "WARNING").upper()
            sev = Severity.HIGH if sev_raw == "ERROR" else Severity.MEDIUM
            rel_file = Path(item.get("path", "")).name
            line_no = item.get("start", {}).get("line", 0)
            findings.append(
                Finding(
                    check_id="TCP-MGD-001",
                    title=f"Semgrep Decompiled Code Match: {item.get('check_id', 'rule')}",
                    category="Decompiled Source Analysis",
                    status=FindingStatus.FAIL,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    affected_asset=f"{origin_asset} :: {rel_file}:{line_no}",
                    summary=extra.get("message", "Static rule matched decompiled source code."),
                    evidence={
                        "engine": "semgrep",
                        "rule_id": item.get("check_id"),
                        "file": rel_file,
                        "line": line_no,
                    },
                    remediation="Remediate the flagged pattern in source code and recompile.",
                    compliance_support=mapper.resolve("TCP-MGD-001"),
                )
            )
        return findings

    # Fallback built-in regex/AST-like scan over decompiled .cs / .java files
    for src_file in src_dir.rglob("*"):
        if src_file.suffix.lower() not in (".cs", ".java"):
            continue
        try:
            code = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for check_id, title, rx, sev, summary in DECOMPILED_CODE_RULES:
            m = rx.search(code)
            if m:
                line_no = code[: m.start()].count("\n") + 1
                findings.append(
                    Finding(
                        check_id=check_id,
                        title=title,
                        category="Decompiled Source Analysis",
                        status=FindingStatus.FAIL,
                        severity=sev,
                        confidence=Confidence.HIGH,
                        affected_asset=f"{origin_asset} :: {src_file.name}:{line_no}",
                        summary=summary,
                        evidence={
                            "engine": "decompile_builtin_rules",
                            "decompiled_file": src_file.name,
                            "line": line_no,
                            "snippet": m.group(0)[:180],
                        },
                        remediation="Fix the insecure construct in application source code and rebuild.",
                        compliance_support=mapper.resolve(check_id),
                    )
                )
    return findings


def scan_decompiled_code(
    target_path: Path,
    mapper: ComplianceMapper,
    semgrep_rules: Optional[Path] = None,
) -> List[Finding]:
    """
    Decompile .NET assemblies (via ilspycmd) and Java archives (via jadx) into a temporary
    directory and analyze the recovered source code. Gracefully reports a Tooling Gap if
    neither decompiler is installed.
    """
    ilspy_bin = shutil.which("ilspycmd")
    jadx_bin = shutil.which("jadx")
    semgrep_bin = shutil.which("semgrep")

    if not ilspy_bin and not jadx_bin:
        return [
            Finding(
                check_id="TCP-MGD-001",
                title="Headless Decompilers Unavailable (ilspycmd / jadx)",
                category="Decompiled Source Analysis",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(target_path),
                summary="Neither 'ilspycmd' (.NET) nor 'jadx' (Java) was found on PATH; skipped source-level decompilation.",
                evidence={"ilspycmd": False, "jadx": False, "semgrep": bool(semgrep_bin)},
                remediation="Install ilspycmd (`dotnet tool install -g ilspycmd`) and/or jadx for automated decompilation.",
                compliance_support=mapper.resolve("TCP-MGD-001"),
            )
        ]

    candidates: List[Path] = []
    if target_path.is_file():
        candidates.append(target_path)
    elif target_path.is_dir():
        for root, _, fnames in os.walk(target_path):
            for fname in sorted(fnames):
                fp = Path(root) / fname
                if fp.suffix.lower() in (".exe", ".dll", ".jar", ".war"):
                    candidates.append(fp)

    findings: List[Finding] = []
    with tempfile.TemporaryDirectory(prefix="tirtcp_decomp_") as tmp_root:
        tmp_path = Path(tmp_root)
        for idx, item in enumerate(candidates[:25]):
            ext = item.suffix.lower()
            sub_out = tmp_path / f"unit_{idx}_{item.stem}"
            sub_out.mkdir(parents=True, exist_ok=True)
            try:
                if ext in (".exe", ".dll") and ilspy_bin:
                    if _decompile_dotnet(item, sub_out, ilspy_bin):
                        findings.extend(
                            _scan_decompiled_tree(sub_out, item.name, mapper, semgrep_bin, semgrep_rules)
                        )
                elif ext in (".jar", ".war") and jadx_bin:
                    if _decompile_java(item, sub_out, jadx_bin):
                        findings.extend(
                            _scan_decompiled_tree(sub_out, item.name, mapper, semgrep_bin, semgrep_rules)
                        )
            except subprocess.TimeoutExpired:
                continue

    return findings