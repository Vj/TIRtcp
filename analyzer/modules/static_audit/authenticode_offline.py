"""Pure-Python Authenticode inspection (no signtool/osslsigncode needed).

Answers, offline and on any OS: is the PE signed, by whom, with what digest, is there a trusted
timestamp, is the leaf certificate expired/self-signed/weak, and - the important pen-test one -
does the signed digest still match the file (i.e. was the binary patched after signing).
NOTE: certificate-chain trust and revocation are NOT evaluated here (they need the OS trust store);
that part stays with signature_audit.py / signtool."""
from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from asn1crypto import cms, x509  # type: ignore
    HAS_ASN1 = True
except ImportError:  # pragma: no cover
    HAS_ASN1 = False

OID_TIMESTAMP_RFC3161 = "1.3.6.1.4.1.311.3.3.1"
OID_COUNTERSIGNATURE = "1.2.840.113549.1.9.6"


def _der_children(data: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i + 2 <= len(data):
        tag = data[i]; ln = data[i + 1]; i += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(data[i:i + n], "big"); i += n
        out.append((tag, data[i:i + ln])); i += ln
    return out


def _signed_digest(content: bytes) -> Optional[bytes]:
    """SpcIndirectDataContent -> DigestInfo.digest."""
    try:
        top = _der_children(content)            # [SpcAttributeTypeAndValue, DigestInfo]
        digest_info = _der_children(top[1][1])   # [AlgorithmIdentifier, OCTET STRING]
        return digest_info[1][1]
    except (IndexError, ValueError):
        return None


def authenticode_hash(data: bytes, pe_offset: int, algo: str, cert_off: int, cert_size: int, size_of_headers: int,
                      sections: List[Tuple[int, int]], is_pe32_plus: bool) -> str:
    h = hashlib.new(algo)
    opt = pe_offset + 24
    checksum_off = opt + 64
    dd_start = opt + (112 if is_pe32_plus else 96)
    certdir_off = dd_start + 4 * 8
    h.update(data[:checksum_off]); h.update(data[checksum_off + 4:certdir_off])
    h.update(data[certdir_off + 8:size_of_headers])
    hashed = size_of_headers
    for ptr, size in sorted(sections):
        h.update(data[ptr:ptr + size]); hashed += size
    end = len(data) - cert_size if cert_size and cert_off + cert_size >= len(data) else len(data)
    if hashed < end:
        h.update(data[hashed:end])
    return h.hexdigest()


def inspect_authenticode(path: str) -> Dict[str, Any]:
    import pefile  # local import keeps module importable without pefile
    result: Dict[str, Any] = {"signed": False}
    with open(path, "rb") as fh:
        data = fh.read()
    pe = pefile.PE(data=data, fast_load=True)
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if not sec.VirtualAddress or not sec.Size:
            return result
        result["signed"] = True
        if not HAS_ASN1:
            result["error"] = "asn1crypto not installed"
            return result
        blob = data[sec.VirtualAddress: sec.VirtualAddress + sec.Size]
        length, _rev, ctype = struct.unpack_from("<IHH", blob, 0)
        if ctype != 2:
            result["error"] = f"unsupported WIN_CERTIFICATE type {ctype}"
            return result
        sd = cms.ContentInfo.load(blob[8:length])["content"]
        si = sd["signer_infos"][0]
        digest_alg = si["digest_algorithm"]["algorithm"].native
        result["digest_algorithm"] = digest_alg

        # leaf certificate = the one matching the signer's issuer+serial
        leaf = None
        sid = si["sid"].chosen
        for c in sd["certificates"]:
            cert = c.chosen
            if cert.serial_number == sid["serial_number"].native and cert.issuer == sid["issuer"]:
                leaf = cert; break
        if leaf is None and len(sd["certificates"]):
            leaf = sd["certificates"][0].chosen
        if leaf is not None:
            nb, na = leaf["tbs_certificate"]["validity"]["not_before"].native, leaf["tbs_certificate"]["validity"]["not_after"].native
            pub = leaf.public_key
            result.update({
                "subject": leaf.subject.human_friendly, "issuer": leaf.issuer.human_friendly,
                "not_before": nb.isoformat(), "not_after": na.isoformat(),
                "expired": na < datetime.now(timezone.utc),
                "self_signed": leaf.subject == leaf.issuer,
                "cert_signature_algorithm": leaf["signature_algorithm"]["algorithm"].native,
                "public_key_algorithm": pub.algorithm, "public_key_bits": pub.bit_size,
                "chain_certs_embedded": len(sd["certificates"]),
            })
        unsigned = [a["type"].native for a in (si["unsigned_attrs"] or [])]
        result["has_timestamp"] = any(t in (OID_TIMESTAMP_RFC3161, OID_COUNTERSIGNATURE, "counter_signature") for t in unsigned) or any(
            "311.3.3.1" in str(t) for t in unsigned)

        # integrity: recompute the Authenticode digest and compare
        expected = _signed_digest(sd["encap_content_info"]["content"].contents)
        if expected and digest_alg in hashlib.algorithms_available:
            actual = authenticode_hash(
                data, pe.DOS_HEADER.e_lfanew, digest_alg, sec.VirtualAddress, sec.Size,
                pe.OPTIONAL_HEADER.SizeOfHeaders, [(s.PointerToRawData, s.SizeOfRawData) for s in pe.sections],
                pe.OPTIONAL_HEADER.Magic == 0x20B)
            result["digest_matches_file"] = actual == expected.hex()
        return result
    except Exception as exc:  # parsing malformed signatures must never kill the scan
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        pe.close()
