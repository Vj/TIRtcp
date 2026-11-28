"""
TIRtcp Static & Local Artifact Audit Module:
- Embedded Database Connection Strings & Hardcoded Credentials (TCP-SEC-001)
- Debug Artifacts (PDB files, embedded PDB paths) & Local Log PII/Token Leaks (TCP-SEC-002)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Pattern, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.validators import aadhaar_valid, luhn_valid, pan_valid
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

# Maximum file size to read in full (25 MB) to keep scans fast and memory-safe
MAX_SCAN_BYTES = 25 * 1024 * 1024

TEXT_EXTS = {
    ".config", ".xml", ".json", ".yaml", ".yml", ".ini", ".properties",
    ".env", ".conf", ".cfg", ".toml", ".bat", ".ps1", ".sh", ".py", ".js",
}
LOG_EXTS = {".log", ".trace", ".out"}
BINARY_EXTS = {".exe", ".dll", ".sys", ".so", ".dylib", ".jar"}

PLACEHOLDER_TOKENS = {
    "changeme", "password", "your_password", "example", "placeholder",
    "********", "xxxx", "null", "none", "test", "sample", "dummy",
}

# ---------------------------------------------------------------------------
# 1. Regex Signatures: Direct DB Connections & Hardcoded Secrets (TCP-SEC-001)
# ---------------------------------------------------------------------------
DB_CONN_PATTERNS: List[Tuple[str, Pattern[str], Severity]] = [
    (
        "ADO.NET / MSSQL Connection String with Credentials",
        re.compile(
            r"(?:Server|Data Source)\s*=[^;\r\n\"']+;[^\"\r\n']*?(?:User\s*ID|UID)\s*=[^;\r\n\"']+;[^\"\r\n']*?(?:Password|PWD)\s*=\s*([^;\r\n\"']+)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
    ),
    (
        "JDBC Database Connection String with Credentials",
        re.compile(
            r"jdbc:(?:sqlserver|mysql|postgresql|oracle:thin|mariadb|db2)://[^\s\"'<>]+?(?:password|pwd)=([^\s&;\"'<>]+)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
    ),
    (
        "URI-Style Database Connection String (Postgres/MySQL/Mongo/Redis)",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^:\s\"'<>]+:([^@\s\"'<>]+)@[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
    ),
    (
        "Oracle TNS / Easy Connect String with Password",
        re.compile(
            r"\(DESCRIPTION\s*=\s*\(ADDRESS.*?USER\s*=\s*[^)]+\).*?PASSWORD\s*=\s*([^)]+)\)",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.CRITICAL,
    ),
]

HARDCODED_SECRET_PATTERNS: List[Tuple[str, Pattern[str], Severity]] = [
    (
        "PEM Private Key Material",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.HIGH,
    ),
    (
        "Hardcoded Password / Secret Assignment",
        re.compile(
            r"""(?i)\b(?:db_pass(?:word)?|sql_pass(?:word)?|client_secret|api_secret|signing_key|master_key|auth_password)\b\s*[:=]\s*["']?([^\s"'`;]{6,64})["']?"""
        ),
        Severity.HIGH,
    ),
    (
        "Hardcoded Bearer / JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
    ),
]

# ---------------------------------------------------------------------------
# 2. Regex Signatures: Debug Info & Log PII / Token Leaks (TCP-SEC-002)
# ---------------------------------------------------------------------------
EMBEDDED_PDB_PATTERN = re.compile(r"[A-Za-z]:\\[^\x00-\x1f\"*?<>|]{3,240}\.pdb\b", re.IGNORECASE)

LOG_LEAK_PATTERNS: List[Tuple[str, Pattern[str], Severity]] = [
    (
        "Authorization Header / Bearer Token in Log",
        re.compile(r"(?i)Authorization\s*:\s*Bearer\s+([A-Za-z0-9._-]{12,})"),
        Severity.HIGH,
    ),
    (
        "Plaintext Password Logged",
        re.compile(r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["']?([^\s"',;}{]{4,64})"""),
        Severity.HIGH,
    ),
    (
        "Indian PAN Identifier in Local Log (DPDP PII)",
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        Severity.MEDIUM,
    ),
    (
        "Potential Aadhaar Number (12-Digit) in Local Log (DPDP PII)",
        re.compile(r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b"),
        Severity.MEDIUM,
    ),
    (
        "Payment Card Number (PCI PAN, Luhn-valid) in Local Log",
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        Severity.HIGH,
    ),
    (
        "Session / Refresh Token in Log",
        re.compile(r"""(?i)\b(?:session_id|sessiontoken|refresh_token|access_token)\b\s*[:=]\s*["']?([A-Za-z0-9._-]{12,})"""),
        Severity.HIGH,
    ),
]


def _redact(secret: str) -> str:
    """Mask sensitive matches while preserving enough structure for verification."""
    s = secret.strip()
    if len(s) <= 4:
        return "****"
    if len(s) <= 8:
        return f"{s[:2]}****"
    return f"{s[:3]}****{s[-2:]}"


_PLACEHOLDER_SHAPES = re.compile(r"(x+|\*+|\.+|<[^>]*>|\$\{[^}]*\}|%[^%]*%|\{\{[^}]*\}\})")


def _is_placeholder(val: str) -> bool:
    """Exact-match placeholder test. (Substring matching used to discard real secrets such as
    'MyPassword#2026!' or 'Contest#9981x'.)"""
    low = val.strip().lower().strip("\"'")
    if len(low) < 4:
        return True
    return low in PLACEHOLDER_TOKENS or bool(_PLACEHOLDER_SHAPES.fullmatch(low))


def _validate_log_match(label: str, value: str) -> bool:
    """Checksum validation so PAN / Aadhaar / card regexes stop firing on arbitrary IDs and timestamps."""
    if label.startswith("Indian PAN"):
        return pan_valid(value)
    if label.startswith("Potential Aadhaar"):
        return aadhaar_valid(value)
    if label.startswith("Payment Card"):
        return luhn_valid(value)
    return True


def _extract_printable_strings(data: bytes, min_len: int = 6) -> str:
    """Extract ASCII and UTF-16LE printable strings from a binary blob."""
    ascii_matches = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    utf16_matches = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)

    parts = [m.decode("ascii", errors="ignore") for m in ascii_matches]
    parts.extend(m.decode("utf-16le", errors="ignore") for m in utf16_matches)
    return "\n".join(parts)


def scan_secrets_db_and_debug(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Any = None,
) -> List[Finding]:
    """
    Audit client files for:
    1. Direct database connection strings & hardcoded credentials (TCP-SEC-001)
    2. Shipped PDB debug files, embedded PDB paths, and PII/token-leaking logs (TCP-SEC-002)
    """
    sec_refs = mapper.resolve("TCP-SEC-001")
    dbg_refs = mapper.resolve("TCP-SEC-002")
    findings: List[Finding] = []

    if not target_path.exists():
        return findings

    if ctx is not None:
        records = list(ctx.files)
    else:
        from analyzer.core.context import ScanContext
        records = list(ScanContext(target_path).files)

    db_hits_found = False
    sec_hits_found = False
    dbg_hits_found = False
    files_scanned = 0

    for rec in records:
        fpath = rec.path
        ext = rec.ext

        # 1. Shipped PDB Symbol Files (TCP-SEC-002)
        if ext == ".pdb":
            dbg_hits_found = True
            findings.append(
                Finding(
                    check_id="TCP-SEC-002",
                    title="Program Database (PDB) Debug Symbols Shipped with Client",
                    category="Data Exposure & Logging",
                    status=FindingStatus.FAIL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=str(fpath),
                    summary=(
                        "Debug symbol file (.pdb) is bundled in the installation directory, "
                        "exposing internal function names, source file paths, and easing reverse engineering."
                    ),
                    evidence={"artifact_type": "PDB Symbol File", "size_bytes": rec.size},
                    remediation="Exclude .pdb symbol files from release installers and store them in an internal symbol server.",
                    compliance_support=dbg_refs,
                )
            )
            continue

        if rec.size > MAX_SCAN_BYTES or rec.size == 0:
            continue

        is_binary = rec.is_binary or ext in BINARY_EXTS
        content = rec.printable_strings() if is_binary else rec.read_text()
        if not content:
            continue

        files_scanned += 1

        # 2. Embedded PDB Paths Inside Binaries (TCP-SEC-002)
        if is_binary:
            pdb_paths = sorted(set(EMBEDDED_PDB_PATTERN.findall(content)))
            if pdb_paths:
                dbg_hits_found = True
                findings.append(
                    Finding(
                        check_id="TCP-SEC-002",
                        title="Embedded Debug Symbol (PDB) Build Path in Compiled Binary",
                        category="Data Exposure & Logging",
                        status=FindingStatus.FAIL,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        affected_asset=str(fpath),
                        summary="Binary contains hardcoded build-machine PDB paths revealing internal directory structure.",
                        evidence={"embedded_pdb_paths": pdb_paths[:10]},
                        remediation="Strip private PDB paths in release builds using MSVC /PDBALTPATH:%_PDB%.",
                        compliance_support=dbg_refs,
                    )
                )

        # 3. Direct Database Connection Strings (TCP-SEC-001)
        if ext in TEXT_EXTS or is_binary:
            for label, pattern, sev in DB_CONN_PATTERNS:
                matches = pattern.findall(content)
                valid_matches = [m for m in matches if not _is_placeholder(m)]
                if valid_matches:
                    db_hits_found = True
                    sec_hits_found = True
                    findings.append(
                        Finding(
                            check_id="TCP-SEC-001",
                            title=f"Direct Database Connection String Detected ({label})",
                            category="Secrets & Configuration",
                            status=FindingStatus.FAIL,
                            severity=sev,
                            confidence=Confidence.HIGH,
                            affected_asset=str(fpath),
                            summary=(
                                "Client artifact contains a direct backend database connection string "
                                "with embedded credentials, enabling attackers to bypass application logic."
                            ),
                            evidence={
                                "pattern": label,
                                "match_count": len(valid_matches),
                                "redacted_secrets": [_redact(m) for m in valid_matches[:5]],
                                "source_type": "binary_strings" if is_binary else "config_text",
                            },
                            remediation=(
                                "Remove direct database connections from the thick client. Route all data "
                                "operations through an authenticated backend API tier."
                            ),
                            compliance_support=sec_refs,
                            manual_playbook=PlaybookRef(
                                tool="dnSpy / Wireshark",
                                objective="Verify whether the database port is reachable from client workstations and test privilege scope.",
                                steps=[
                                    "Inspect the surrounding configuration or decompiled assembly in dnSpy/ILSpy to extract the DB host, port, and database name.",
                                    "Capture connection initialization in Wireshark to confirm whether TLS encryption is enforced on the DB wire protocol.",
                                    "Verify if the embedded database account has DBA/sa privileges or write access to sensitive tables.",
                                ],
                            ),
                        )
                    )

            # 4. General Hardcoded Secrets & Keys (TCP-SEC-001)
            for label, pattern, sev in HARDCODED_SECRET_PATTERNS:
                matches = pattern.findall(content)
                valid_matches = [m for m in matches if not _is_placeholder(m)]
                if valid_matches:
                    sec_hits_found = True
                    findings.append(
                        Finding(
                            check_id="TCP-SEC-001",
                            title=f"Hardcoded Secret or Cryptographic Material ({label})",
                            category="Secrets & Configuration",
                            status=FindingStatus.FAIL,
                            severity=sev,
                            confidence=Confidence.MEDIUM if is_binary else Confidence.HIGH,
                            affected_asset=str(fpath),
                            summary=f"Detected {len(valid_matches)} instance(s) of {label} inside client artifact.",
                            evidence={
                                "pattern": label,
                                "match_count": len(valid_matches),
                                "redacted_samples": [_redact(m) for m in valid_matches[:5]],
                            },
                            remediation=(
                                "Revoke and rotate exposed credentials. Issue short-lived user-bound tokens "
                                "after authentication rather than embedding static secrets."
                            ),
                            compliance_support=sec_refs,
                        )
                    )

        # 5. Local Log Files Leaking PII or Tokens (TCP-SEC-002)
        if ext in LOG_EXTS or (not is_binary and re.search(r"(^|[._-])logs?([._-]|$)", fpath.name.lower())):
            for label, pattern, sev in LOG_LEAK_PATTERNS:
                matches = pattern.findall(content)
                valid_matches = [m for m in matches if not _is_placeholder(m) and _validate_log_match(label, m)]
                if valid_matches:
                    dbg_hits_found = True
                    findings.append(
                        Finding(
                            check_id="TCP-SEC-002",
                            title=f"Sensitive Data or PII Logged Locally ({label})",
                            category="Data Exposure & Logging",
                            status=FindingStatus.FAIL,
                            severity=sev,
                            confidence=Confidence.HIGH,
                            affected_asset=str(fpath),
                            summary=(
                                f"Local application log records sensitive data ({label}), creating local "
                                "credential exposure and DPDP personal data protection risks."
                            ),
                            evidence={
                                "leak_type": label,
                                "occurrences": len(valid_matches),
                                "redacted_samples": [_redact(m) for m in valid_matches[:5]],
                            },
                            remediation=(
                                "Sanitize logging sinks to mask passwords, bearer tokens, and national identifiers "
                                "(PAN/Aadhaar) before writing to disk, and enforce restrictive file ACLs."
                            ),
                            compliance_support=dbg_refs,
                        )
                    )

    if records and not sec_hits_found:
        findings.append(
            Finding(
                check_id="TCP-SEC-001",
                title="No Embedded Database Strings or Hardcoded Secrets Detected",
                category="Secrets & Configuration",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(target_path),
                summary=f"Scanned {files_scanned} file(s); no plaintext DB connection strings or hardcoded secrets matched.",
                evidence={"files_scanned": files_scanned},
                compliance_support=sec_refs,
            )
        )

    if records and not dbg_hits_found and not db_hits_found:
        findings.append(
            Finding(
                check_id="TCP-SEC-002",
                title="No Shipped PDB Symbols or PII/Token Log Leaks Detected",
                category="Data Exposure & Logging",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(target_path),
                summary=f"Scanned {files_scanned} file(s); no PDB debug artifacts or PII/token log leaks matched.",
                evidence={"files_scanned": files_scanned},
                compliance_support=dbg_refs,
            )
        )

    return findings