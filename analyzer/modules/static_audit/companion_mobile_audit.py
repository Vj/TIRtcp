"""
TIRtcp Companion Mobile APK Analyzer (TCP-PAIR-001 / TCP-NET-001)
Inspects companion Android .apk files (e.g., QR-pairing mobile clients) for:
  1. Cleartext HTTP traffic allowance (usesCleartextTraffic / http:// server URLs)
  2. Custom deep-link URI schemes handling QR pairing callbacks
  3. Hardcoded API keys, bearer tokens, or pairing secrets inside DEX/assets
  4. Certificate pinning / Network Security Config presence
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.context import ScanContext
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

HTTP_URL_RE = re.compile(rb"http://[a-zA-Z0-9._-]+(?::\d+)?(?:/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]*)?")
SECRET_ASSIGN_RE = re.compile(
    rb"(?:api[_-]?key|client[_-]?secret|pairing[_-]?secret|bearer\s+)[=:\s\"']{1,4}([A-Za-z0-9_\-]{16,64})",
    re.IGNORECASE,
)


def _inspect_single_apk(apk_path: Path, refs: list) -> List[Finding]:
    findings: List[Finding] = []
    if not apk_path.exists() or not zipfile.is_zipfile(apk_path):
        return findings

    cleartext_urls: set[str] = set()
    has_net_sec_cfg = False
    has_pin_strings = False
    has_pairing_keywords = False
    manifest_cleartext_flag = False
    secret_hits = 0

    with zipfile.ZipFile(apk_path, "r") as zf:
        names = zf.namelist()
        has_net_sec_cfg = any("network_security_config" in n.lower() for n in names)

        for name in names:
            low = name.lower()
            if not (low.endswith(".dex") or low.endswith(".xml") or low.endswith(".json") or low.endswith(".properties")):
                continue
            try:
                blob = zf.read(name)
            except Exception:
                continue

            if low == "androidmanifest.xml" and b"usesCleartextTraffic" in blob:
                manifest_cleartext_flag = True

            if b"sha256/" in blob or b"CertificatePinner" in blob or b"trust-anchors" in blob:
                has_pin_strings = True

            if re.search(rb"qr|pair|scanner|deep[-_]?link", blob, re.IGNORECASE):
                has_pairing_keywords = True

            for m in HTTP_URL_RE.finditer(blob):
                u = m.group(0).decode("ascii", errors="ignore")
                if not any(ns in u for ns in ("schemas.android.com", "www.w3.org", "apache.org", "ns.adobe.com")):
                    cleartext_urls.add(u)

            secret_hits += len(SECRET_ASSIGN_RE.findall(blob))

    if manifest_cleartext_flag or cleartext_urls:
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title=f"Companion APK Permits Cleartext HTTP Communication ({apk_path.name})",
                category="Companion Mobile APK Security",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=str(apk_path),
                summary=(
                    "Companion APK declares usesCleartextTraffic or embeds non-HTTPS server endpoints, "
                    "exposing QR pairing tokens and session credentials to network interception."
                ),
                evidence={
                    "manifest_usesCleartextTraffic": manifest_cleartext_flag,
                    "cleartext_urls_sample": sorted(cleartext_urls)[:10],
                },
                remediation="Set android:usesCleartextTraffic='false' in AndroidManifest.xml and enforce HTTPS with TLS 1.2+.",
                compliance_support=refs,
            )
        )

    if not has_net_sec_cfg and not has_pin_strings:
        findings.append(
            Finding(
                check_id="TCP-PAIR-001",
                title=f"Companion APK Lacks Network Security Config or Certificate Pinning ({apk_path.name})",
                category="Companion Mobile APK Security",
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                affected_asset=str(apk_path),
                summary=(
                    "Companion APK does not include an Android network_security_config.xml or CertificatePinner/SPKI pin, "
                    "allowing a rogue CA on the mobile device to MITM server pairing requests."
                ),
                evidence={"has_network_security_config": has_net_sec_cfg, "pairing_logic_detected": has_pairing_keywords},
                remediation="Configure res/xml/network_security_config.xml with SPKI pins or validate the server's ephemeral QR public key fingerprint during pairing.",
                compliance_support=refs,
            )
        )

    if secret_hits > 0:
        findings.append(
            Finding(
                check_id="TCP-SEC-001",
                title=f"Potential Hardcoded API/Pairing Secrets Inside Companion APK ({secret_hits} Match(es))",
                category="Companion Mobile APK Security",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                affected_asset=str(apk_path),
                summary="DEX/resource files inside the companion APK contain hardcoded API key or pairing secret assignments.",
                evidence={"redacted_secret_assignment_count": secret_hits},
                remediation="Remove static API/pairing secrets from the APK and provision per-device asymmetric keys during QR pairing.",
                compliance_support=refs,
            )
        )

    if not findings:
        findings.append(
            Finding(
                check_id="TCP-PAIR-001",
                title=f"Companion APK Transport & Pinning Baseline Clean ({apk_path.name})",
                category="Companion Mobile APK Security",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(apk_path),
                summary="Companion APK enforces HTTPS and includes network security/pinning controls.",
                compliance_support=refs,
            )
        )

    return findings


def audit_companion_mobile(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Optional[ScanContext] = None,
    explicit_apk: Optional[Path] = None,
) -> List[Finding]:
    """Audit explicit --companion-apk or any .apk discovered inside the target workspace."""
    refs = mapper.resolve("TCP-PAIR-001") or mapper.resolve("TCP-NET-001")
    findings: List[Finding] = []
    seen: set[Path] = set()

    if explicit_apk and explicit_apk.exists():
        seen.add(explicit_apk.resolve())
        findings.extend(_inspect_single_apk(explicit_apk, refs))

    scan_ctx = ctx if ctx is not None else (ScanContext(target_path) if target_path.exists() else None)
    if scan_ctx:
        for rec in scan_ctx.files:
            if rec.ext == ".apk" and rec.path.resolve() not in seen:
                seen.add(rec.path.resolve())
                findings.extend(_inspect_single_apk(rec.path, refs))

    return findings
