"""
TIRtcp Network Protocol Module: Non-HTTP TLS & Certificate Inspector
Maps to check_id: TCP-NET-001
"""

from __future__ import annotations
import warnings

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.scope import NetworkScope
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

CONFIG_EXTS = {".config", ".xml", ".json", ".yaml", ".yml", ".ini", ".properties", ".conf", ".cfg"}
ENDPOINT_REGEX = re.compile(
    r"\b(?:https?|tls|ssl|tcp)://([a-zA-Z0-9.-]+):([1-9][0-9]{1,4})\b",
    re.IGNORECASE,
)
WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ADH", "AECDH")
_LOCAL_REFUSAL_MARKERS = (
    "UNSUPPORTED_PROTOCOL",
    "NO_PROTOCOLS_AVAILABLE",
    "NO_CIPHERS_AVAILABLE",
    "UNKNOWN_PROTOCOL",
)


def discover_endpoints_from_configs(target_path: Path) -> Set[Tuple[str, int]]:
    """Extract host:port endpoints from client configuration files."""
    endpoints: Set[Tuple[str, int]] = set()
    files: List[Path] = []

    if target_path.is_file():
        files.append(target_path)
    elif target_path.is_dir():
        for root, _, fnames in os.walk(target_path):
            for fname in fnames:
                fp = Path(root) / fname
                if fp.suffix.lower() in CONFIG_EXTS:
                    files.append(fp)

    for fp in files:
        try:
            if fp.stat().st_size > 10 * 1024 * 1024:
                continue
            text = fp.read_text(encoding="utf-8", errors="ignore")
            for host, port_str in ENDPOINT_REGEX.findall(text):
                low_host = host.lower()
                if low_host in {"localhost", "127.0.0.1", "0.0.0.0", "example.com"}:
                    continue
                port = int(port_str)
                if 1 <= port <= 65535:
                    endpoints.add((host, port))
        except OSError:
            continue

    return endpoints


def _probe_tls_version(
    host: str,
    port: int,
    tls_ver: ssl.TLSVersion,
    timeout: float = 5.0,
) -> Optional[bool]:
    """
    Tri-state legacy-protocol probe:
      True  = server completed a handshake at that version
      False = server explicitly refused it (TLS alert / protocol error)
      None  = INCONCLUSIVE (local OpenSSL cannot offer it, network error, or timeout)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver
    except (ValueError, AttributeError, ssl.SSLError):
        return None

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        msg = str(exc).upper()
        if any(m in msg for m in _LOCAL_REFUSAL_MARKERS):
            return None
        if (
            "ALERT" in msg
            or "WRONG_VERSION" in msg
            or "UNEXPECTED_EOF" in msg
            or "HANDSHAKE_FAILURE" in msg
        ):
            return False
        return None
    except (OSError, socket.timeout):
        return None


def _inspect_endpoint_native(host: str, port: int, timeout: float = 6.0) -> Dict[str, Any]:
    """Perform a native Python TLS handshake, certificate chain check, and legacy protocol probe."""
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "tls_supported": False,
        "negotiated_version": None,
        "negotiated_cipher": None,
        "cert_valid": False,
        "cert_error": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_not_after": None,
        "cert_days_remaining": None,
        "deprecated_protocols_accepted": [],
        "deprecated_protocols_untested": [],
    }

    # 1. Strict Certificate & Modern TLS Verification
    strict_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with strict_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["tls_supported"] = True
                result["cert_valid"] = True
                result["negotiated_version"] = ssock.version()
                result["negotiated_cipher"] = ssock.cipher()
                cert = ssock.getpeercert() or {}
                result["cert_subject"] = str(cert.get("subject", ""))
                result["cert_issuer"] = str(cert.get("issuer", ""))
                not_after_str = cert.get("notAfter")
                result["cert_not_after"] = not_after_str
                if not_after_str:
                    try:
                        exp_ts = ssl.cert_time_to_seconds(not_after_str)
                        result["cert_days_remaining"] = int((exp_ts - time.time()) / 86400)
                    except Exception:
                        pass
    except ssl.SSLCertVerificationError as cert_err:
        result["tls_supported"] = True
        result["cert_valid"] = False
        result["cert_error"] = str(cert_err)
    except Exception as exc:
        result["cert_error"] = str(exc)

    # 2. Permissive Handshake (if strict cert verification failed) to capture cipher/version
    if not result["negotiated_version"]:
        lax_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        lax_ctx.check_hostname = False
        lax_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with lax_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result["tls_supported"] = True
                    result["negotiated_version"] = ssock.version()
                    result["negotiated_cipher"] = ssock.cipher()
        except Exception:
            return result

    # 3. Probe Deprecated TLS 1.0 and TLS 1.1 Support
    if hasattr(ssl, "TLSVersion"):
        for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            outcome = _probe_tls_version(host, port, ver, timeout=timeout)
            if outcome is True:
                result["deprecated_protocols_accepted"].append(label)
            elif outcome is None:
                result["deprecated_protocols_untested"].append(label)

    return result


def _run_testssl_if_available(host: str, port: int) -> Optional[Dict[str, Any]]:
    """Optionally enrich findings using testssl.sh when available on Linux/macOS."""
    testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")
    if not testssl_bin:
        return None
    try:
        proc = subprocess.run(
            [testssl_bin, "--quiet", "--jsonfile-pretty", "-", f"{host}:{port}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
    return None


def inspect_tls_endpoints(
    target_path: Optional[Path],
    mapper: ComplianceMapper,
    explicit_endpoints: Optional[List[str]] = None,
    extra_discovered_endpoints: Optional[Set[Tuple[str, int]]] = None,
    scope: Optional[NetworkScope] = None,
) -> List[Finding]:
    check_id = "TCP-NET-001"
    compliance_refs = mapper.resolve(check_id)
    findings: List[Finding] = []

    discovered: Set[Tuple[str, int]] = set()
    if target_path and target_path.exists():
        discovered.update(discover_endpoints_from_configs(target_path))
    if extra_discovered_endpoints:
        discovered.update(extra_discovered_endpoints)

    explicit_set: Set[Tuple[str, int]] = set()
    for ep in explicit_endpoints or []:
        if ":" in ep:
            h, p_str = ep.rsplit(":", 1)
            if p_str.isdigit():
                explicit_set.add((h.strip(), int(p_str)))

    all_endpoints = sorted(discovered | explicit_set)
    if not all_endpoints:
        return findings

    for host, port in all_endpoints:
        asset = f"{host}:{port}"
        is_explicit = (host, port) in explicit_set

        # Default-deny discovered endpoints unless explicitly allow-listed in --scope-file
        if not is_explicit and (scope is None or not scope.is_allowed(host)):
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Discovered Endpoint Skipped (Outside Active Probe Scope): {asset}",
                    category="Network & Transport",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=asset,
                    summary=(
                        f"Endpoint {asset} was discovered in configuration/capture files but was not "
                        "actively probed because it is not listed in '--scope-file'."
                    ),
                    evidence={
                        "endpoint": asset,
                        "scope_file_configured": bool(scope and scope.configured),
                    },
                    remediation="Add approved target hosts/CIDRs to --scope-file or pass via --endpoints to probe.",
                    compliance_support=compliance_refs,
                )
            )
            continue

        probe = _inspect_endpoint_native(host, port)
        issues_found = False

        # 1. Deprecated TLS (< 1.2)
        deprecated = probe["deprecated_protocols_accepted"]
        if deprecated:
            issues_found = True
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Deprecated TLS Protocol(s) Enabled ({', '.join(deprecated)}) on {asset}",
                    category="Network & Transport",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=asset,
                    summary=(
                        f"Backend endpoint {asset} accepts legacy TLS protocol(s) ({', '.join(deprecated)}), "
                        "violating modern cryptographic transport baselines (TLS 1.2 / 1.3)."
                    ),
                    evidence=probe,
                    remediation="Disable TLS 1.0 and TLS 1.1 on the backend listener; enforce TLS 1.2 and TLS 1.3 only.",
                    compliance_support=compliance_refs,
                )
            )

        # 2. Weak Cipher Suite
        cipher_tuple = probe.get("negotiated_cipher") or ()
        cipher_name = cipher_tuple[0] if cipher_tuple else ""
        if any(tok in cipher_name.upper() for tok in WEAK_CIPHER_TOKENS):
            issues_found = True
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Weak Cipher Suite Negotiated ({cipher_name}) on {asset}",
                    category="Network & Transport",
                    status=FindingStatus.FAIL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=asset,
                    summary=f"Endpoint {asset} negotiated weak cipher suite {cipher_name}.",
                    evidence=probe,
                    remediation="Configure server cipher suites to prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with ECDHE.",
                    compliance_support=compliance_refs,
                )
            )

        # 3. Invalid / Untrusted / Expired Server Certificate
        if not probe["cert_valid"]:
            issues_found = True
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Untrusted, Self-Signed, or Expired TLS Certificate on {asset}",
                    category="Network & Transport",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=asset,
                    summary=(
                        f"TLS certificate validation failed for {asset}: {probe['cert_error']}. "
                        "If the client accepts this connection, it disables standard PKI validation."
                    ),
                    evidence=probe,
                    remediation="Deploy a valid certificate issued by a trusted CA matching the endpoint hostname.",
                    compliance_support=compliance_refs,
                )
            )
        else:
            days_left = probe.get("cert_days_remaining")
            if isinstance(days_left, int) and 0 <= days_left <= 30:
                issues_found = True
                findings.append(
                    Finding(
                        check_id=check_id,
                        title=f"TLS Server Certificate Expiring Soon ({days_left} Day(s)) on {asset}",
                        category="Network & Transport",
                        status=FindingStatus.FAIL,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        affected_asset=asset,
                        summary=f"Certificate for {asset} expires in {days_left} day(s) ({probe.get('cert_not_after')}).",
                        evidence=probe,
                        remediation="Renew and deploy the server TLS certificate prior to expiration.",
                        compliance_support=compliance_refs,
                    )
                )

        untested = probe.get("deprecated_protocols_untested") or []
        if untested and not deprecated:
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Legacy TLS Probe Inconclusive ({', '.join(untested)}) on {asset}",
                    category="Network & Transport",
                    status=FindingStatus.TOOLING_GAP,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    affected_asset=asset,
                    summary="Could not determine whether legacy TLS is accepted (local stack refused or network error). Re-run with testssl.sh/sslyze.",
                    evidence=probe,
                    compliance_support=compliance_refs,
                )
            )

        if not issues_found and not untested:
            findings.append(
                Finding(
                    check_id=check_id,
                    title=f"Modern TLS Transport & Valid Certificate Verified on {asset}",
                    category="Network & Transport",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=asset,
                    summary=(
                        f"Endpoint {asset} negotiated {probe['negotiated_version']} with a valid "
                        "CA-signed certificate and rejected TLS 1.0/1.1."
                    ),
                    evidence=probe,
                    compliance_support=compliance_refs,
                )
            )

        # Always attach a Manual Verification card for Certificate Pinning on thick-client TLS endpoints
        findings.append(
            Finding(
                check_id=check_id,
                title=f"Verify Client-Side Certificate Pinning on {asset}",
                category="Network & Transport",
                status=FindingStatus.MANUAL_REQUIRED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=asset,
                summary=(
                    "Server-side TLS configuration does not confirm whether the thick client "
                    "validates certificate pinning or rejects rogue local root CAs."
                ),
                evidence={"endpoint": asset},
                manual_playbook=PlaybookRef(
                    tool="Burp Suite Invisible Proxy / Frida",
                    objective="Confirm whether the thick client rejects an intercepting proxy certificate.",
                    steps=[
                        f"Install the test proxy CA certificate into the Windows Trusted Root store and route traffic for {host}:{port} through an invisible proxy listener.",
                        "Launch the thick client and attempt authentication or data sync.",
                        "If traffic decrypts cleanly without custom pinning errors, flag missing certificate pinning (especially for BFSI / RBI DPSC targets).",
                    ],
                ),
                compliance_support=compliance_refs,
            )
        )

    return findings
