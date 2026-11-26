"""Minimal, dependency-free TLS Client/ServerHello parser.

Why: a ClientHello from a fully modern TLS 1.2/1.3 client routinely carries record-layer
version 0x0301 for compatibility, so matching on the record header alone flags healthy traffic
as "TLS 1.0". The *negotiated* version lives in ServerHello (and supported_versions)."""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

VERSION_NAMES = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}


def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _ext_supported_versions(ext_blob: bytes, is_server: bool) -> List[int]:
    i, out = 0, []
    while i + 4 <= len(ext_blob):
        etype, elen = struct.unpack_from("!HH", ext_blob, i)
        body = ext_blob[i + 4: i + 4 + elen]
        i += 4 + elen
        if etype != 43:
            continue
        if is_server and len(body) >= 2:
            out.append(struct.unpack_from("!H", body, 0)[0])
        elif not is_server and body:
            n = body[0]
            out.extend(struct.unpack_from("!H", body, 1 + k)[0] for k in range(0, min(n, len(body) - 1) - 1, 2))
    return [v for v in out if not _is_grease(v)]


def parse_tls_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Return {'kind','effective_version','effective_name','legacy'} for the first hello in payload, else None."""
    try:
        if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        hs_type = payload[5]
        if hs_type not in (1, 2):
            return None
        body = payload[9:]
        legacy_ver = struct.unpack_from("!H", body, 0)[0]
        pos = 2 + 32
        sid_len = body[pos]; pos += 1 + sid_len
        if hs_type == 1:
            cs_len = struct.unpack_from("!H", body, pos)[0]; pos += 2 + cs_len
            comp_len = body[pos]; pos += 1 + comp_len
        else:
            pos += 2 + 1  # chosen cipher + compression
        versions: List[int] = []
        if pos + 2 <= len(body):
            ext_len = struct.unpack_from("!H", body, pos)[0]
            versions = _ext_supported_versions(body[pos + 2: pos + 2 + ext_len], is_server=(hs_type == 2))
        effective = max(versions) if versions else legacy_ver
        return {
            "kind": "client_hello" if hs_type == 1 else "server_hello",
            "effective_version": effective,
            "effective_name": VERSION_NAMES.get(effective, hex(effective)),
            "legacy": effective < 0x0303,
        }
    except (IndexError, struct.error):
        return None


def _ext_sni(ext_blob: bytes) -> Optional[str]:
    """Extract Server Name Indication (extension type 0) from ClientHello extensions."""
    i = 0
    while i + 4 <= len(ext_blob):
        etype, elen = struct.unpack_from("!HH", ext_blob, i)
        body = ext_blob[i + 4 : i + 4 + elen]
        i += 4 + elen
        if etype != 0 or len(body) < 5:
            continue
        list_len = struct.unpack_from("!H", body, 0)[0]
        pos = 2
        end = min(2 + list_len, len(body))
        while pos + 3 <= end:
            name_type = body[pos]
            name_len = struct.unpack_from("!H", body, pos + 1)[0]
            pos += 3
            if name_type == 0 and pos + name_len <= end:
                return body[pos : pos + name_len].decode("ascii", errors="ignore").lower()
            pos += name_len
    return None


def parse_tls_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Return {'kind','effective_version','effective_name','legacy','sni'} for the first hello in payload, else None."""
    try:
        if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        hs_type = payload[5]
        if hs_type not in (1, 2):
            return None
        body = payload[9:]
        legacy_ver = struct.unpack_from("!H", body, 0)[0]
        pos = 2 + 32
        sid_len = body[pos]; pos += 1 + sid_len
        if hs_type == 1:
            cs_len = struct.unpack_from("!H", body, pos)[0]; pos += 2 + cs_len
            comp_len = body[pos]; pos += 1 + comp_len
        else:
            pos += 2 + 1
        versions: List[int] = []
        sni: Optional[str] = None
        if pos + 2 <= len(body):
            ext_len = struct.unpack_from("!H", body, pos)[0]
            ext_blob = body[pos + 2 : pos + 2 + ext_len]
            versions = _ext_supported_versions(ext_blob, is_server=(hs_type == 2))
            if hs_type == 1:
                sni = _ext_sni(ext_blob)
        effective = max(versions) if versions else legacy_ver
        return {
            "kind": "client_hello" if hs_type == 1 else "server_hello",
            "effective_version": effective,
            "effective_name": VERSION_NAMES.get(effective, hex(effective)),
            "legacy": effective < 0x0303,
            "sni": sni,
        }
    except (IndexError, struct.error):
        return None