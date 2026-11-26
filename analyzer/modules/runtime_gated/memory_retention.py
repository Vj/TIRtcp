"""
TIRtcp Gated Runtime Hygiene Module: Post-Logout Memory Retention Analyzer
Maps to check_id: TCP-MEM-001

Design & Safety Guardrails:
1. Strictly gated behind evaluate_authorization_gate(--authorized + --engagement-id).
2. Operates offline on a user-provided post-logout diagnostic dump file (.dmp / raw snapshot)
   rather than performing live process injection or credential harvesting.
3. Emits FindingStatus.EVIDENCE_OF_RETENTION with calibrated confidence scores (Low/Medium/High)
   instead of a hard Fail, and never writes raw secret values into reports.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from analyzer.core.auth_gate import evaluate_authorization_gate
from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

# Chunked reading size (16 MB) with 1 KB overlap so strings spanning chunk boundaries are not missed
CHUNK_SIZE = 16 * 1024 * 1024
OVERLAP_BYTES = 4096

# Generic token/header patterns (used only when canary markers are not provided or in addition to them)
BEARER_HEADER_RE = re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}", re.IGNORECASE)
JWT_TOKEN_RE = re.compile(rb"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")


def _fingerprint_marker(marker: str) -> str:
    """Return a non-reversible SHA-256 prefix + length descriptor so raw secrets are never logged."""
    digest = hashlib.sha256(marker.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest} (len={len(marker)})"


def _scan_dump_for_canaries(
    dump_path: Path,
    canary_markers: Sequence[str],
) -> Dict[str, Any]:
    """
    Stream through a binary dump file in chunks, counting ASCII and UTF-16LE
    occurrences of provided QA canary strings as well as structured Bearer/JWT tokens.
    """
    valid_canaries = [c for c in canary_markers if len(c.strip()) >= 6]
    encoded_targets: Dict[str, Dict[str, bytes]] = {}
    for c in valid_canaries:
        fp = _fingerprint_marker(c)
        encoded_targets[fp] = {
            "ascii": c.encode("utf-8"),
            "utf16le": c.encode("utf-16le"),
        }

    canary_counts: Dict[str, Dict[str, int]] = {
        fp: {"ascii_hits": 0, "utf16le_hits": 0} for fp in encoded_targets
    }
    bearer_hits = 0
    jwt_hits = 0
    bytes_scanned = 0

    with dump_path.open("rb") as fh:
        tail = b""
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            bytes_scanned += len(chunk)
            window = tail + chunk
            tl = len(tail)
            # Count only matches that END inside the new chunk; anything fully inside the carried tail was
            # already counted on the previous pass (the old half-overlap logic double-counted these and
            # could inflate the retention confidence rating).
            for fp, encodings in encoded_targets.items():
                for key, needle in (("ascii_hits", encodings["ascii"]), ("utf16le_hits", encodings["utf16le"])):
                    canary_counts[fp][key] += window.count(needle, max(tl - (len(needle) - 1), 0))

            bearer_hits += sum(1 for m in BEARER_HEADER_RE.finditer(window) if m.end() > tl)
            jwt_hits += sum(1 for m in JWT_TOKEN_RE.finditer(window) if m.end() > tl)

            tail = window[-OVERLAP_BYTES:]

    matched_canaries = {
        fp: counts
        for fp, counts in canary_counts.items()
        if (counts["ascii_hits"] + counts["utf16le_hits"]) > 0
    }

    return {
        "bytes_scanned": bytes_scanned,
        "canaries_evaluated": len(valid_canaries),
        "matched_canaries": matched_canaries,
        "structured_bearer_header_hits": bearer_hits,
        "structured_jwt_token_hits": jwt_hits,
    }


def _calibrate_confidence(scan_stats: Dict[str, Any]) -> Confidence:
    """
    Assign Low / Medium / High confidence to memory retention artifacts,
    accounting for normal garbage-collection / freed-page lag.
    """
    matched_canaries = scan_stats["matched_canaries"]
    total_canary_hits = sum(
        c["ascii_hits"] + c["utf16le_hits"] for c in matched_canaries.values()
    )
    multi_encoding = any(
        c["ascii_hits"] > 0 and c["utf16le_hits"] > 0 for c in matched_canaries.values()
    )
    token_hits = scan_stats["structured_bearer_header_hits"] + scan_stats["structured_jwt_token_hits"]

    if total_canary_hits >= 3 or (total_canary_hits >= 2 and multi_encoding):
        return Confidence.HIGH
    if total_canary_hits >= 1 or token_hits >= 1:
        return Confidence.MEDIUM
    return Confidence.LOW


def analyze_post_logout_memory(
    dump_path: Optional[Path],
    mapper: ComplianceMapper,
    authorized_flag: bool,
    engagement_id: Optional[str],
    canary_markers: Optional[Sequence[str]] = None,
    operator: Optional[str] = None,
) -> List[Finding]:
    """
    Evaluate a post-logout process memory snapshot for lingering sensitive strings.
    Requires explicit authorization gate approval (--authorized + valid --engagement-id).
    """
    check_id = "TCP-MEM-001"
    compliance_refs = mapper.resolve(check_id)

    gate = evaluate_authorization_gate(
        authorized_flag=authorized_flag,
        engagement_id=engagement_id,
        operator=operator,
    )

    if not gate.allowed:
        return [
            Finding(
                check_id=check_id,
                title="Post-Logout Memory Hygiene Check Skipped (Authorization Gate Closed)",
                category="Runtime Memory Hygiene",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(dump_path) if dump_path else "Runtime Memory Module",
                summary=gate.reason,
                evidence={
                    "authorized_flag": gate.context.authorized_flag,
                    "engagement_id": gate.context.engagement_id,
                    "operator": gate.context.operator,
                },
                remediation="Re-run with '--authorized --engagement-id <ENGAGEMENT_ID>' on an authorized test target.",
                compliance_support=compliance_refs,
                auth_context=gate.context,
            )
        ]

    if dump_path is None:
        return []

    if not dump_path.exists() or not dump_path.is_file():
        return [
            Finding(
                check_id=check_id,
                title="Post-Logout Memory Dump File Not Found",
                category="Runtime Memory Hygiene",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(dump_path),
                summary=f"Authorized memory check could not locate dump file: {dump_path}",
                evidence={"dump_path": str(dump_path)},
                compliance_support=compliance_refs,
                auth_context=gate.context,
            )
        ]

    stats = _scan_dump_for_canaries(dump_path, canary_markers or [])
    total_canary_hits = sum(
        c["ascii_hits"] + c["utf16le_hits"] for c in stats["matched_canaries"].values()
    )
    total_token_hits = (
        stats["structured_bearer_header_hits"] + stats["structured_jwt_token_hits"]
    )

    if total_canary_hits == 0 and total_token_hits == 0:
        return [
            Finding(
                check_id=check_id,
                title="No Post-Logout Canary Credentials or Session Tokens Retained in Dump",
                category="Runtime Memory Hygiene",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(dump_path),
                summary=(
                    f"Scanned {stats['bytes_scanned']} bytes across post-logout snapshot; "
                    "zero QA canary strings or active Bearer/JWT tokens were detected."
                ),
                evidence=stats,
                compliance_support=compliance_refs,
                auth_context=gate.context,
            )
        ]

    confidence = _calibrate_confidence(stats)
    severity = Severity.MEDIUM if confidence in (Confidence.HIGH, Confidence.MEDIUM) else Severity.LOW

    return [
        Finding(
            check_id=check_id,
            title="Evidence of Post-Logout Sensitive Credential or Token Retention in Memory",
            category="Runtime Memory Hygiene",
            status=FindingStatus.EVIDENCE_OF_RETENTION,
            severity=severity,
            confidence=confidence,
            affected_asset=str(dump_path),
            summary=(
                "Post-logout process memory snapshot retained test canary credentials and/or "
                "structured session tokens. Because freed heap pages in managed runtimes (.NET/JVM/Chromium) "
                "may persist until garbage collection, review buffer zeroization lifecycle."
            ),
            evidence=stats,
            remediation=(
                "Store credentials and session tokens in mutable byte/char buffers rather than immutable "
                "strings, overwrite buffers explicitly on logout (SecureZeroMemory / CryptProtectMemory / "
                "Array.Clear), and force session invalidation server-side."
            ),
            compliance_support=compliance_refs,
            manual_playbook=PlaybookRef(
                tool="WinDbg / API Monitor",
                objective="Confirm whether retained strings reside in active heap allocations vs. unallocated freed pages.",
                steps=[
                    "Inspect the application's logout handler in source or decompiled IL to verify whether credential/token fields are explicitly cleared before dereferencing.",
                    "Confirm that the backend server invalidates the session token immediately upon logout so any lingering client memory artifact cannot be replayed.",
                ],
            ),
            auth_context=gate.context,
        )
    ]