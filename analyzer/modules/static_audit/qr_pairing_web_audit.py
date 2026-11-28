"""
TIRtcp QR/Device-Pairing Flow, Local Web Server & Stack Audit (TCP-PAIR-001)
Addresses thick-client / local-server + mobile companion pairing workflows:
  1. Tech-stack fingerprinting (Go runtime build IDs, Node.js pkg/nexe, PyInstaller, .NET, Electron)
  2. Local HTTP/WebSocket server bind address detection (0.0.0.0 LAN exposure vs 127.0.0.1)
  3. Permissive CORS headers (Access-Control-Allow-Origin: *) on local APIs
  4. QR / Device-Pairing endpoints (/pair, /qr, /link, /device/auth) & session/token hygiene indicators
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.context import ScanContext
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

GO_MARKERS = (b"Go build ID:", b"go.buildid", b"runtime.main", b"net/http.(*Server)")
NODE_BUNDLER_MARKERS = (b"pkg/prelude/bootstrap.js", b"nexe~~sentinel", b"NODE_SEA_BLOB")
PYINSTALLER_MARKERS = (b"MEI\x0c\x0b\x0a\x0b\x0e", b"pyi-windows-manifest-filename", b"_MEIPASS")

LAN_BIND_RE = re.compile(
    rb"(?:0\.0\.0\.0|\[::\]|http://\+|https://\+):(\d{2,5})"
)
PAIRING_ROUTE_RE = re.compile(
    rb"(?:/api(?:/v\d+)?)?/(?:qr(?:code)?|pair(?:ing)?|device[-_]?link|session[-_]?link|connect[-_]?mobile)\b",
    re.IGNORECASE,
)
CORS_WILDCARD_RE = re.compile(
    rb"Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*['\"]?",
    re.IGNORECASE,
)


def audit_qr_pairing_and_web_surface(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Optional[ScanContext] = None,
) -> List[Finding]:
    """Fingerprint Go/Node/PyInstaller server stacks and audit local web & QR pairing surfaces."""
    refs = mapper.resolve("TCP-PAIR-001") or mapper.resolve("TCP-NET-001")
    findings: List[Finding] = []

    if not target_path.exists():
        return findings

    scan_ctx = ctx if ctx is not None else ScanContext(target_path)

    for rec in scan_ctx.files:
        if rec.ext not in (".exe", ".dll", ".js", ".ts", ".py", ".go", ".cs", ".json", ".html"):
            continue
        raw = rec.read_bytes()
        if not raw:
            continue

        # 1. Tech-stack fingerprinting for compiled server executables
        if rec.is_pe and rec.ext == ".exe":
            detected_stacks: List[str] = []
            if any(m in raw for m in GO_MARKERS):
                detected_stacks.append("Go (Golang net/http / compiled binary)")
            if any(m in raw for m in NODE_BUNDLER_MARKERS):
                detected_stacks.append("Node.js Single-Executable Bundle (pkg / nexe / SEA)")
            if any(m in raw for m in PYINSTALLER_MARKERS):
                detected_stacks.append("Python PyInstaller Bundle")

            if detected_stacks:
                findings.append(
                    Finding(
                        check_id="TCP-PAIR-001",
                        title=f"Server / Client Runtime Stack Identified: {', '.join(detected_stacks)}",
                        category="Tech Stack & Local Web Surface",
                        status=FindingStatus.OBSERVATION,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        affected_asset=str(rec.path),
                        summary=(
                            f"Detected runtime stack ({', '.join(detected_stacks)}). Tailor dynamic/code review to "
                            "stack-specific risks (e.g., Go net/http routing & pprof, Node prototype/CORS, or PyInstaller archive extraction)."
                        ),
                        evidence={"detected_stacks": detected_stacks},
                        compliance_support=refs,
                    )
                )

        # 2. Local Web Server Binding to 0.0.0.0 (LAN Exposure)
        lan_ports = sorted({m.group(1).decode("ascii") for m in LAN_BIND_RE.finditer(raw)})
        if lan_ports:
            findings.append(
                Finding(
                    check_id="TCP-PAIR-001",
                    title=f"Local Web/API Listener Configured to Bind on All Interfaces 0.0.0.0 (Port(s): {', '.join(lan_ports[:8])})",
                    category="Tech Stack & Local Web Surface",
                    status=FindingStatus.FAIL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_asset=str(rec.path),
                    summary=(
                        f"Embedded web/API listener references wildcard bind address 0.0.0.0 on port(s) {', '.join(lan_ports[:8])}. "
                        "Any device on the local network can reach the local API or QR pairing interface."
                    ),
                    evidence={"wildcard_bind_ports": lan_ports[:15]},
                    remediation="Bind local desktop/bridge HTTP listeners strictly to 127.0.0.1 unless LAN pairing is explicitly required and authenticated.",
                    compliance_support=refs,
                )
            )

        # 3. Wildcard CORS Policy (Access-Control-Allow-Origin: *)
        if CORS_WILDCARD_RE.search(raw):
            findings.append(
                Finding(
                    check_id="TCP-PAIR-001",
                    title="Wildcard CORS Policy (Access-Control-Allow-Origin: *) Detected",
                    category="Tech Stack & Local Web Surface",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        "Embedded web server sets Access-Control-Allow-Origin: *, allowing arbitrary malicious websites "
                        "visited in the user's browser to invoke local API or QR pairing endpoints cross-origin."
                    ),
                    remediation="Restrict Access-Control-Allow-Origin to explicit trusted origins and validate anti-CSRF tokens on state-changing routes.",
                    compliance_support=refs,
                )
            )

        # 4. QR Code / Device-Pairing Endpoints Requiring Replay, TTL & Rate-Limit Verification
        pairing_routes = sorted({m.group(0).decode("ascii", errors="ignore") for m in PAIRING_ROUTE_RE.finditer(raw)})
        if pairing_routes:
            has_rate_limit_hint = bool(re.search(rb"rate[-_]?limit|throttle|too\s+many\s+requests|429", raw, re.IGNORECASE))
            has_ttl_hint = bool(re.search(rb"expir(?:e|y|es_at)|ttl|max[-_]?age", raw, re.IGNORECASE))
            findings.append(
                Finding(
                    check_id="TCP-PAIR-001",
                    title=f"QR / Device-Pairing Endpoint(s) Detected ({', '.join(pairing_routes[:5])})",
                    category="QR & Device-Pairing Security",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        f"Identified QR/mobile device pairing endpoint(s): {', '.join(pairing_routes[:8])}. "
                        "Verify token entropy (>=128-bit CSPRNG), single-use invalidation, short TTL (<=60s), and brute-force rate limiting."
                    ),
                    evidence={
                        "pairing_routes": pairing_routes[:15],
                        "rate_limit_indicators_found": has_rate_limit_hint,
                        "expiry_ttl_indicators_found": has_ttl_hint,
                    },
                    remediation=(
                        "Generate pairing tokens with a CSPRNG (>=128 bits), enforce single-use consumption within <=60 seconds, "
                        "rate-limit pairing attempts, and require explicit user confirmation on the desktop/server UI."
                    ),
                    manual_playbook=PlaybookRef(
                        tool="QR / Device-Pairing Flow Replay & Entropy Verification",
                        objective="Verify QR/device-pairing tokens are high-entropy, single-use, short-lived, and rate-limited against replay.",
                    ),
                    compliance_support=refs,
                )
            )


        # 5. Cleartext WebSocket (ws://) & Token-in-Query-String Hygiene
        insecure_ws = sorted({m.group(0).decode("ascii", errors="ignore") for m in WS_INSECURE_RE.finditer(raw)})
        token_in_ws_url = bool(WS_QUERY_TOKEN_RE.search(raw))
        if insecure_ws or token_in_ws_url:
            findings.append(
                Finding(
                    check_id="TCP-PAIR-001",
                    title="Insecure WebSocket Transport (ws://) or Auth Token in WebSocket URL Query",
                    category="QR & Device-Pairing Security",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH if token_in_ws_url else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        "Detected cleartext ws:// WebSocket endpoint(s) or authentication tokens passed in the WebSocket URL query string "
                        "(which leak in proxy/server access logs and browser history)."
                    ),
                    evidence={
                        "cleartext_ws_urls": insecure_ws[:10],
                        "token_in_query_string": token_in_ws_url,
                    },
                    remediation="Enforce wss:// (TLS) for WebSocket channels and authenticate via Sec-WebSocket-Protocol or post-handshake frames rather than URL query parameters.",
                    compliance_support=refs,
                )
            )

    return findings


WS_INSECURE_RE = re.compile(rb'''ws://[a-zA-Z0-9._-]+(?::\d+)?(?:/[^\s\"'<>]*)?''', re.IGNORECASE)
WS_QUERY_TOKEN_RE = re.compile(rb'''wss?://[^\s\"'<>]+\?(?:[^\"'<>]*&)?(?:token|session|auth|key|code)=[^\s\"'<>]+''', re.IGNORECASE)


def analyze_qr_token_samples(
    tokens: List[str],
    mapper: ComplianceMapper,
    source_label: str = "QR Token Samples",
) -> List[Finding]:
    """Evaluate Shannon entropy and predictability across captured QR/device-pairing tokens."""
    import math

    refs = mapper.resolve("TCP-PAIR-001") or mapper.resolve("TCP-NET-001")
    findings: List[Finding] = []
    cleaned = [t.strip() for t in tokens if t and t.strip()]
    if not cleaned:
        return findings

    def _shannon_bits(s: str) -> float:
        if not s:
            return 0.0
        freq = {ch: s.count(ch) / len(s) for ch in set(s)}
        ent_per_char = -sum(p * math.log2(p) for p in freq.values())
        return round(ent_per_char * len(s), 2)

    entropies = [_shannon_bits(t) for t in cleaned]
    avg_bits = round(sum(entropies) / len(entropies), 2)
    is_numeric_seq = all(t.isdigit() for t in cleaned)
    duplicates = len(cleaned) - len(set(cleaned))

    if is_numeric_seq or avg_bits < 80.0 or duplicates > 0:
        findings.append(
            Finding(
                check_id="TCP-PAIR-001",
                title="Low-Entropy or Predictable QR / Device-Pairing Tokens Detected",
                category="QR & Device-Pairing Security",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=source_label,
                summary=(
                    f"Analyzed {len(cleaned)} QR/pairing token(s): average Shannon entropy is {avg_bits} bits "
                    f"(numeric_only={is_numeric_seq}, duplicates={duplicates}). Predictable tokens allow session hijacking."
                ),
                evidence={
                    "sample_count": len(cleaned),
                    "average_shannon_bits": avg_bits,
                    "numeric_only": is_numeric_seq,
                    "duplicate_tokens": duplicates,
                },
                remediation="Generate pairing tokens using >=128 bits from a CSPRNG (e.g., secrets.token_urlsafe(24)) with single-use invalidation.",
                compliance_support=refs,
            )
        )
    else:
        findings.append(
            Finding(
                check_id="TCP-PAIR-001",
                title="QR / Device-Pairing Token Entropy Baseline Passed",
                category="QR & Device-Pairing Security",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=source_label,
                summary=f"Analyzed {len(cleaned)} pairing token(s) with {avg_bits} bits average Shannon entropy and no duplicates.",
                evidence={"sample_count": len(cleaned), "average_shannon_bits": avg_bits},
                compliance_support=refs,
            )
        )

    return findings
