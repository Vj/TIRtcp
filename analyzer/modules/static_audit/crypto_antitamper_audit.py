"""
TIRtcp Native Crypto & Anti-Tamper Binary Audit (TCP-BIN-003 / TCP-NET-002)
Inspects compiled binaries via ScanContext for:
  1. Embedded AES Rijndael S-box / inverse S-box tables (indicates custom/hardcoded symmetric crypto)
  2. Weak non-cryptographic PRNG imports (rand, srand, RtlRandom, RtlRandomEx)
  3. Presence or absence of WinVerifyTrust / CertGetCertificateChain (runtime binary & TLS trust validation)
"""

from __future__ import annotations

import re
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

# First 16 bytes of standard AES forward & inverse S-boxes
AES_FWD_SBOX_PREFIX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
AES_INV_SBOX_PREFIX = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")

WEAK_PRNG_APIS = [b"srand\x00", b"rand\x00", b"RtlRandom\x00", b"RtlRandomEx\x00"]
TRUST_APIS = [b"WinVerifyTrust", b"CertGetCertificateChain", b"WinHttpSetOption"]
SPKI_PIN_RE = re.compile(rb"sha256/[A-Za-z0-9+/]{42,44}=?")
PEM_PUB_RE = re.compile(rb"-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----")


def audit_crypto_and_antitamper(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Optional[ScanContext] = None,
) -> List[Finding]:
    """Scan PE binaries for custom AES S-boxes, weak PRNGs, and trust-validation imports."""
    bin_refs = mapper.resolve("TCP-BIN-001")
    net_refs = mapper.resolve("TCP-NET-001")
    findings: List[Finding] = []

    if not target_path.exists():
        return findings

    scan_ctx = ctx if ctx is not None else ScanContext(target_path)
    audited = 0

    for rec in scan_ctx.iter_binaries():
        if not rec.is_pe or rec.ext not in (".exe", ".dll"):
            continue
        raw = rec.read_bytes()
        if not raw:
            continue

        audited += 1

        # 1. Embedded AES S-box detection
        has_fwd_sbox = AES_FWD_SBOX_PREFIX in raw
        has_inv_sbox = AES_INV_SBOX_PREFIX in raw
        if has_fwd_sbox or has_inv_sbox:
            findings.append(
                Finding(
                    check_id="TCP-BIN-001",
                    title="Embedded AES S-Box Table Detected in Native Binary",
                    category="Cryptography & Anti-Tamper",
                    status=FindingStatus.OBSERVATION,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        "Binary embeds static Rijndael/AES S-box lookup tables, indicating custom or statically linked "
                        "symmetric cryptography rather than OS CNG/BCrypt primitives. Inspect key derivation and key storage."
                    ),
                    evidence={
                        "forward_sbox": has_fwd_sbox,
                        "inverse_sbox": has_inv_sbox,
                    },
                    remediation="Prefer Windows CNG (BCryptGenRandom / BCryptEncrypt) and OS-backed key storage over custom AES tables.",
                    compliance_support=bin_refs,
                )
            )

        # 2. Weak PRNG symbols
        found_prngs = [api.rstrip(b"\x00").decode("ascii") for api in WEAK_PRNG_APIS if api in raw]
        if found_prngs:
            findings.append(
                Finding(
                    check_id="TCP-BIN-001",
                    title=f"Non-Cryptographic PRNG Symbol(s) Present ({', '.join(found_prngs)})",
                    category="Cryptography & Anti-Tamper",
                    status=FindingStatus.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    affected_asset=str(rec.path),
                    summary=(
                        f"Binary references non-cryptographic PRNG function(s) ({', '.join(found_prngs)}). "
                        "Verify these are not used to generate session tokens, nonces, or encryption IVs."
                    ),
                    evidence={"weak_prng_symbols": found_prngs},
                    remediation="Use BCryptGenRandom or CryptGenRandom for all security-sensitive random values.",
                    compliance_support=bin_refs,
                )
            )

        # 3. Runtime Authenticode / TLS Certificate Chain Verification APIs
        found_trust = [api.decode("ascii") for api in TRUST_APIS if api in raw]
        if rec.ext == ".exe" and not found_trust:
            findings.append(
                Finding(
                    check_id="TCP-NET-001",
                    title="Primary Executable Lacks Explicit WinVerifyTrust / CertGetCertificateChain APIs",
                    category="Cryptography & Anti-Tamper",
                    status=FindingStatus.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    affected_asset=str(rec.path),
                    summary=(
                        "Primary executable does not import WinVerifyTrust or CertGetCertificateChain directly; "
                        "verify whether plugin DLL integrity and TLS certificate pinning are enforced via a managed runtime."
                    ),
                    evidence={"trust_apis_detected": found_trust},
                    compliance_support=net_refs,
                )
            )


        # 4. Hardcoded SPKI Certificate Pins / PEM Trust Anchors
        spki_pins = sorted({m.group(0).decode("ascii") for m in SPKI_PIN_RE.finditer(raw)})
        has_pem_pin = bool(PEM_PUB_RE.search(raw))
        if spki_pins or has_pem_pin:
            findings.append(
                Finding(
                    check_id="TCP-NET-001",
                    title="TLS Certificate / SPKI Public-Key Pinning Material Detected",
                    category="Cryptography & Anti-Tamper",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=str(rec.path),
                    summary=(
                        f"Detected {len(spki_pins)} SHA-256 SPKI pin(s) and/or embedded PEM certificate anchors. "
                        "Dynamic MITM proxy testing will require Frida SSL-unpinning hooks."
                    ),
                    evidence={
                        "spki_pins": spki_pins[:10],
                        "embedded_pem_anchor": has_pem_pin,
                    },
                    compliance_support=net_refs,
                )
            )

    if audited > 0 and not findings:
        findings.append(
            Finding(
                check_id="TCP-BIN-001",
                title="Native Crypto & Trust-API Hygiene Clean",
                category="Cryptography & Anti-Tamper",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(target_path),
                summary=f"Audited {audited} PE binary/binaries with no embedded custom AES S-boxes or weak PRNG flags.",
                compliance_support=bin_refs,
            )
        )

    return findings
