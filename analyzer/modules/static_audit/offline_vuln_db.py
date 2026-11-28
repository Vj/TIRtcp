"""
TIRtcp P2 Supply-Chain Intelligence: Offline OSV / CISA KEV / EPSS Advisory Matcher
Parses .NET (*.deps.json), npm (package.json), and Java (pom.properties) dependency manifests
and matches versions against a local air-gapped snapshot (config/offline_vulns.json).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.context import ScanContext
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

DEFAULT_VULN_DB_PATH = Path(__file__).resolve().parents[3] / "config" / "offline_vulns.json"


def _parse_ver(v: str) -> Tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", v)]
    return tuple(nums) if nums else (0,)


def _version_in_range(version: str, fixed_version: str) -> bool:
    if not version or not fixed_version:
        return False
    v_t = _parse_ver(version)
    f_t = _parse_ver(fixed_version)
    max_len = max(len(v_t), len(f_t))
    v_pad = v_t + (0,) * (max_len - len(v_t))
    f_pad = f_t + (0,) * (max_len - len(f_t))
    return v_pad < f_pad


def _extract_package_coordinates(ctx: ScanContext) -> List[Dict[str, str]]:
    """Extract (ecosystem, name, version, source_file) from *.deps.json, package.json, and pom.properties."""
    coords: List[Dict[str, str]] = []

    for rec in ctx.files:
        fname = rec.path.name.lower()

        # 1. .NET *.deps.json
        if fname.endswith(".deps.json"):
            text = rec.read_text()
            if not text:
                continue
            try:
                data = json.loads(text)
                for target_libs in (data.get("targets") or {}).values():
                    if not isinstance(target_libs, dict):
                        continue
                    for pkg_key in target_libs.keys():
                        if "/" in pkg_key:
                            pkg_name, pkg_ver = pkg_key.split("/", 1)
                            coords.append(
                                {
                                    "ecosystem": "NuGet",
                                    "name": pkg_name,
                                    "version": pkg_ver,
                                    "source": rec.rel_path,
                                }
                            )
            except Exception:
                continue

        # 2. npm / Electron package.json
        elif fname == "package.json":
            text = rec.read_text()
            if not text:
                continue
            try:
                data = json.loads(text)
                for section in ("dependencies", "devDependencies"):
                    deps = data.get(section)
                    if isinstance(deps, dict):
                        for pkg_name, raw_ver in deps.items():
                            clean_ver = str(raw_ver).lstrip("^~>=< ")
                            if re.match(r"^\d+\.\d+", clean_ver):
                                coords.append(
                                    {
                                        "ecosystem": "npm",
                                        "name": pkg_name,
                                        "version": clean_ver,
                                        "source": rec.rel_path,
                                    }
                                )
            except Exception:
                continue

        # 3. Java Maven pom.properties
        elif fname == "pom.properties":
            text = rec.read_text()
            if not text:
                continue
            gid = aid = ver = ""
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("groupId="):
                    gid = line.split("=", 1)[1].strip()
                elif line.startswith("artifactId="):
                    aid = line.split("=", 1)[1].strip()
                elif line.startswith("version="):
                    ver = line.split("=", 1)[1].strip()
            if aid and ver:
                coords.append(
                    {
                        "ecosystem": "Maven",
                        "name": f"{gid}:{aid}" if gid else aid,
                        "version": ver,
                        "source": rec.rel_path,
                    }
                )

    return coords


def scan_offline_vulnerabilities(
    ctx: ScanContext,
    mapper: ComplianceMapper,
    vuln_db_path: Optional[Path] = None,
) -> List[Finding]:
    """Match extracted package coordinates against offline OSV + CISA KEV + EPSS snapshot."""
    db_path = vuln_db_path or DEFAULT_VULN_DB_PATH
    compliance_refs = mapper.resolve("TCP-SCA-001")
    coords = _extract_package_coordinates(ctx)

    if not coords:
        return []

    if not db_path.exists():
        return [
            Finding(
                check_id="TCP-SCA-001",
                title="Offline Vulnerability Snapshot Missing (config/offline_vulns.json)",
                category="Supply Chain & Dependencies",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(ctx.target_path),
                summary=f"Extracted {len(coords)} package coordinate(s), but {db_path.name} is not present.",
                evidence={"packages_extracted": len(coords)},
                remediation="Run `python scripts/update_vuln_db.py` on an internet-connected host to build config/offline_vulns.json.",
                compliance_support=compliance_refs,
            )
        ]

    db = json.loads(db_path.read_text(encoding="utf-8"))
    advisories: List[Dict[str, Any]] = db.get("advisories", [])
    findings: List[Finding] = []

    for pkg in coords:
        for adv in advisories:
            if (
                adv.get("ecosystem", "").lower() == pkg["ecosystem"].lower()
                and adv.get("package", "").lower() == pkg["name"].lower()
                and _version_in_range(pkg["version"], adv.get("fixed_version", ""))
            ):
                in_kev = bool(adv.get("cisa_kev", False))
                epss = float(adv.get("epss", 0.0))
                base_sev = adv.get("severity", "Medium").lower()

                if in_kev or epss >= 0.50 or base_sev == "critical":
                    sev = Severity.CRITICAL
                elif base_sev == "high" or epss >= 0.20:
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM

                cve_id = adv.get("cve", adv.get("id", "ADVISORY"))
                kev_tag = " [CISA KEV]" if in_kev else ""
                findings.append(
                    Finding(
                        check_id="TCP-SCA-001",
                        title=f"Vulnerable {pkg['ecosystem']} Dependency: {pkg['name']} {pkg['version']} ({cve_id}){kev_tag}",
                        category="Supply Chain & Dependencies",
                        status=FindingStatus.FAIL,
                        severity=sev,
                        confidence=Confidence.HIGH,
                        affected_asset=f"{pkg['source']} :: {pkg['name']}@{pkg['version']}",
                        summary=(
                            f"{adv.get('summary', 'Known vulnerability in bundled dependency.')} "
                            f"(Fixed in {adv.get('fixed_version')}; EPSS={epss:.2f}, CISA_KEV={in_kev})."
                        ),
                        evidence={
                            "ecosystem": pkg["ecosystem"],
                            "package": pkg["name"],
                            "installed_version": pkg["version"],
                            "fixed_version": adv.get("fixed_version"),
                            "cve": cve_id,
                            "cisa_kev": in_kev,
                            "epss": epss,
                        },
                        remediation=f"Upgrade {pkg['name']} to version {adv.get('fixed_version')} or later.",
                        compliance_support=compliance_refs,
                    )
                )

    return findings