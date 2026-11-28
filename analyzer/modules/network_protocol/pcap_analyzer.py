"""
TIRtcp Network Protocol Module: Offline PCAP & PCAPNG Wire-Protocol Analyzer
Supports:
- Classic PCAP (0xa1b2c3d4 / 0xd4c3b2a1) and PCAPNG (0x0a0d0d0a) without external dependencies
- TLS ClientHello SNI & destination IP:port extraction for scope-gated TLS probing
- Cleartext credentials (with mandatory secret redaction)
- Port-gated database wire protocols (MSSQL TDS, MySQL, PostgreSQL, Oracle TNS)
- Actual ClientHello/ServerHello version inspection (via tls_records.parse_tls_hello)
- Cleartext HTTP auto-update / binary download detection
"""

from __future__ import annotations

import re
import struct
from collections import defaultdict
from typing import Any, Dict, List, Tuple
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.modules.network_protocol.wire_dissectors import inspect_wire_protocols
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)
from analyzer.modules.network_protocol.tls_records import parse_tls_hello

try:
    from scapy.utils import PcapReader  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# Additional cleartext enterprise protocol signatures
LDAP_SIMPLE_BIND_RE = re.compile(rb"\x30[\x0c-\x84].{1,4}\x02\x01[\x01-\x04]\x60[\x07-\x84].{1,4}\x02\x01\x03\x04([^\x00-\x1f]{3,128})\x80([^\x00-\x1f]{1,128})")
FTP_CREDS_RE = re.compile(rb"(?im)^(?:USER|PASS)\s+([^\r\n]{1,128})\r?\n")
SNMP_COMMUNITY_RE = re.compile(rb"\x30[\x10-\x84].{1,4}\x02\x01[\x00\x01]\x04([A-Za-z0-9_@.-]{3,64})")
SMB1_NEGOTIATE_SIG = b"\xffSMB\x72"


def _reassemble_tcp_streams(
    packets: List[Tuple[str, int, str, int, str, int, bytes]]
) -> Dict[str, bytes]:
    """
    Group TCP segments by 4-tuple (src_ip, src_port, dst_ip, dst_port), order by
    TCP sequence number, deduplicate retransmissions, and concatenate stream payloads.
    """
    streams: Dict[str, List[Tuple[int, bytes]]] = defaultdict(list)
    for src_ip, src_port, dst_ip, dst_port, proto, seq, payload in packets:
        if proto != "TCP" or not payload:
            continue
        key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        streams[key].append((seq, payload))

    assembled: Dict[str, bytes] = {}
    for key, segments in streams.items():
        segments.sort(key=lambda item: item[0])
        buf = bytearray()
        last_end: int | None = None
        for seq, data in segments:
            if last_end is None:
                buf.extend(data)
                last_end = seq + len(data)
            elif seq >= last_end:
                buf.extend(data)
                last_end = seq + len(data)
            elif seq + len(data) > last_end:
                overlap = last_end - seq
                buf.extend(data[overlap:])
                last_end = seq + len(data)
        assembled[key] = bytes(buf)
    return assembled

DB_WIRE_SIGNATURES: List[Tuple[str, int, bytes]] = [
    ("MSSQL Tabular Data Stream (TDS)", 1433, b"\x12\x01\x00"),
    ("Oracle TNS Connect Packet", 1521, b"(CONNECT_DATA="),
    ("PostgreSQL Wire Protocol", 5432, b"\x00user\x00"),
]

MYSQL_GREETING_RE = re.compile(rb"^.\x00\x00\x00\x0a([3-8]\.[0-9]+\.[0-9]+)")

CLEARTEXT_AUTH_RE = re.compile(
    rb"(?i)(?:Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}|"
    rb"(?:^|[\r\n&{,\"\s])(?:password|passwd|pwd|passcode)\s*[:=]\s*[\"']?([^\s\"'&},;]{3,64}))"
)

HTTP_UPDATER_RE = re.compile(
    rb"GET\s+(/[^\s]*?(?:update|patch|upgrade|release|version|manifest|\.exe|\.msi|\.dll|\.zip)[^\s]*)\s+HTTP/1\.[01]\r\n(?:[^\r\n]+\r\n)*?Host:\s*([^\r\n]+)",
    re.IGNORECASE,
)

_PW_VALUE_RE = re.compile(rb"(?i)((?:password|passwd|pwd|passcode)\s*[:=]\s*[\"']?)[^\s\"'&},;]+")
_BASIC_RE = re.compile(rb"(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+")


def _redact_payload(raw: bytes) -> str:
    raw = _BASIC_RE.sub(rb"\1****", raw)
    raw = _PW_VALUE_RE.sub(rb"\1****", raw)
    return raw.decode("utf-8", errors="replace")


def _decode_l2_frame(frame: bytes, linktype: int = 1) -> Iterator[Tuple[str, int, str, int, str, bytes]]:
    """Decode Ethernet (linktype 1, including 802.1Q VLAN) or Raw IP (linktype 101) into L4 tuples."""
    if linktype == 1:
        if len(frame) < 14:
            return
        eth_type = struct.unpack("!H", frame[12:14])[0]
        ip_start = 14
        if eth_type == 0x8100 and len(frame) >= 18:  # 802.1Q VLAN tag
            eth_type = struct.unpack("!H", frame[16:18])[0]
            ip_start = 18
        if eth_type != 0x0800:
            return
    elif linktype == 101:
        ip_start = 0
    else:
        return

    if len(frame) < ip_start + 20:
        return
    version = (frame[ip_start] >> 4) & 0x0F
    if version != 4:
        return

    ihl = (frame[ip_start] & 0x0F) * 4
    if len(frame) < ip_start + ihl:
        return

    proto_num = frame[ip_start + 9]
    src_ip = ".".join(str(b) for b in frame[ip_start + 12 : ip_start + 16])
    dst_ip = ".".join(str(b) for b in frame[ip_start + 16 : ip_start + 20])
    l4_start = ip_start + ihl

    if proto_num == 6 and len(frame) >= l4_start + 20:
        src_port, dst_port = struct.unpack("!HH", frame[l4_start : l4_start + 4])
        data_offset = ((frame[l4_start + 12] >> 4) & 0x0F) * 4
        payload = frame[l4_start + data_offset :]
        if payload:
            yield src_ip, src_port, dst_ip, dst_port, "TCP", payload
    elif proto_num == 17 and len(frame) >= l4_start + 8:
        src_port, dst_port = struct.unpack("!HH", frame[l4_start : l4_start + 4])
        payload = frame[l4_start + 8 :]
        if payload:
            yield src_ip, src_port, dst_ip, dst_port, "UDP", payload


def _iter_packets_pcapng(data: bytes) -> Iterator[Tuple[str, int, str, int, str, bytes]]:
    """Pure-Python PCAPNG block stream reader (SHB, IDB, EPB, SPB)."""
    offset = 0
    total = len(data)
    endian = "<"
    interfaces: List[int] = []

    while offset + 12 <= total:
        block_type, block_len = struct.unpack(f"{endian}II", data[offset : offset + 8])
        if block_type == 0x0A0D0D0A and offset + 12 <= total:
            bom = struct.unpack("<I", data[offset + 8 : offset + 12])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            block_type, block_len = struct.unpack(f"{endian}II", data[offset : offset + 8])
            interfaces = []

        if block_len < 12 or offset + block_len > total:
            break

        body = data[offset + 8 : offset + block_len - 4]
        offset += block_len

        if block_type == 0x00000001 and len(body) >= 2:  # Interface Description Block (IDB)
            linktype = struct.unpack(f"{endian}H", body[:2])[0]
            interfaces.append(linktype)
        elif block_type == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block (EPB)
            iface_id, _, _, cap_len, _ = struct.unpack(f"{endian}IIIII", body[:20])
            linktype = interfaces[iface_id] if iface_id < len(interfaces) else 1
            frame = body[20 : 20 + cap_len]
            yield from _decode_l2_frame(frame, linktype=linktype)
        elif block_type == 0x00000003 and len(body) >= 4:  # Simple Packet Block (SPB)
            linktype = interfaces[0] if interfaces else 1
            yield from _decode_l2_frame(body[4:], linktype=linktype)


def _iter_packets_fallback(pcap_path: Path) -> Iterator[Tuple[str, int, str, int, str, bytes]]:
    """Pure-Python PCAP and PCAPNG reader used when Scapy is unavailable."""
    data = pcap_path.read_bytes()
    if len(data) < 24:
        return

    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0x0A0D0D0A:
        yield from _iter_packets_pcapng(data)
        return

    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        return

    linktype = struct.unpack(f"{endian}I", data[20:24])[0]
    offset = 24
    total = len(data)
    while offset + 16 <= total:
        _, _, incl_len, _ = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        yield from _decode_l2_frame(frame, linktype=linktype)


def _iter_packets(pcap_path: Path) -> Iterator[Tuple[str, int, str, int, str, bytes]]:
    """Stream L4 payloads using Scapy PcapReader (supports PCAP & PCAPNG) or pure-Python fallback."""
    if HAS_SCAPY:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                if not pkt.haslayer(Raw):
                    continue
                payload = bytes(pkt[Raw].load)
                if not payload:
                    continue
                if pkt.haslayer(IP):
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
                else:
                    continue
                if pkt.haslayer(TCP):
                    yield src_ip, int(pkt[TCP].sport), dst_ip, int(pkt[TCP].dport), "TCP", payload
                elif pkt.haslayer(UDP):
                    yield src_ip, int(pkt[UDP].sport), dst_ip, int(pkt[UDP].dport), "UDP", payload
    else:
        yield from _iter_packets_fallback(pcap_path)


def analyze_pcap_capture(
    pcap_path: Path,
    mapper: ComplianceMapper,
    discovered_endpoints_out: Optional[Set[Tuple[str, int]]] = None,
) -> List[Finding]:
    """
    Analyze PCAP/PCAPNG capture for wire-level risks and populate discovered_endpoints_out
    with (sni_or_dst_ip, dst_port) tuples from TLS handshakes for downstream TLS probing.
    """
    net_refs = mapper.resolve("TCP-NET-001")
    db_refs = mapper.resolve("TCP-SEC-001")
    host_refs = mapper.resolve("TCP-HOST-001")
    findings: List[Finding] = []

    if not pcap_path.exists():
        return [
            Finding(
                check_id="TCP-NET-001",
                title="PCAP File Not Found",
                category="Network & Transport",
                status=FindingStatus.TOOLING_GAP,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(pcap_path),
                summary=f"Specified capture file does not exist: {pcap_path}",
                compliance_support=net_refs,
            )
        ]

    cleartext_flows: Dict[str, Dict[str, Any]] = {}
    db_flows: Dict[str, Dict[str, Any]] = {}
    legacy_tls_flows: Dict[str, Dict[str, Any]] = {}
    http_update_urls: Dict[str, Dict[str, Any]] = {}
    total_payload_packets = 0
    encrypted_tls_packets = 0

    for src_ip, src_port, dst_ip, dst_port, proto, payload in _iter_packets(pcap_path):
        total_payload_packets += 1
        flow_key = f"{src_ip} -> {dst_ip}:{dst_port} ({proto})"

        if proto == "TCP":
            if len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
                encrypted_tls_packets += 1

            hello = parse_tls_hello(payload)
            if hello:
                if hello["kind"] == "client_hello" and discovered_endpoints_out is not None:
                    target_host = hello.get("sni") or dst_ip
                    discovered_endpoints_out.add((target_host, dst_port))
                if hello["legacy"]:
                    legacy_tls_flows[flow_key] = {
                        "flow": flow_key,
                        "protocol_version": hello["effective_name"],
                        "observed_in": hello["kind"],
                        "sni": hello.get("sni"),
                    }

        for db_name, default_port, sig in DB_WIRE_SIGNATURES:
            if sig in payload and default_port in (src_port, dst_port):
                db_flows[flow_key] = {
                    "flow": flow_key,
                    "database_protocol": db_name,
                    "destination_port": default_port,
                }

        if dst_port == 3306 or src_port == 3306:
            m_mysql = MYSQL_GREETING_RE.search(payload)
            if m_mysql:
                db_flows[flow_key] = {
                    "flow": flow_key,
                    "database_protocol": f"MySQL Wire Protocol (Server {m_mysql.group(1).decode('ascii', 'ignore')})",
                    "destination_port": 3306,
                }

        if proto == "TCP":
            for path_bytes, host_bytes in HTTP_UPDATER_RE.findall(payload):
                host_str = host_bytes.decode("utf-8", errors="ignore").strip()
                path_str = path_bytes.decode("utf-8", errors="ignore").strip()
                url = f"http://{host_str}{path_str}"
                http_update_urls[url] = {
                    "url": url,
                    "source_ip": src_ip,
                    "destination": f"{dst_ip}:{dst_port}",
                }

        if CLEARTEXT_AUTH_RE.search(payload):
            cleartext_flows[flow_key] = {
                "flow": flow_key,
                "protocol": proto,
                "sample_preview_redacted": _redact_payload(payload[:120]),
            }

    for info in cleartext_flows.values():
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title=f"Cleartext Credentials or Authentication Transmitted ({info['flow']})",
                category="Network & Transport",
                status=FindingStatus.FAIL,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                affected_asset=f"{pcap_path.name} :: {info['flow']}",
                summary="Captured traffic contains unencrypted credentials or Basic authentication headers.",
                evidence=info,
                remediation="Enforce TLS 1.2/1.3 encryption for all client-server communication channels.",
                compliance_support=net_refs,
            )
        )

    for info in db_flows.values():
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title=f"Direct Database Wire Protocol Traffic Observed ({info['database_protocol']})",
                category="Network & Transport",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=f"{pcap_path.name} :: {info['flow']}",
                summary=f"Thick client communicates directly with a backend database over {info['database_protocol']}.",
                evidence=info,
                remediation="Refactor client-database interactions behind an authenticated application API tier.",
                compliance_support=net_refs + db_refs,
            )
        )

    for info in legacy_tls_flows.values():
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title=f"Deprecated TLS Handshake Observed in PCAP ({info['protocol_version']})",
                category="Network & Transport",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=f"{pcap_path.name} :: {info['flow']}",
                summary=f"Captured handshake negotiated deprecated {info['protocol_version']} (< TLS 1.2).",
                evidence=info,
                remediation="Upgrade client TLS libraries and server configurations to enforce TLS 1.2 or TLS 1.3.",
                compliance_support=net_refs,
            )
        )

    for url, info in http_update_urls.items():
        findings.append(
            Finding(
                check_id="TCP-HOST-001",
                title="Insecure Cleartext HTTP Auto-Update or Binary Download Channel",
                category="Host & Filesystem ACLs",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=url,
                summary="Client fetches update manifests or executable payloads over unencrypted HTTP.",
                evidence=info,
                remediation="Serve all update manifests and installers exclusively over HTTPS with signature verification.",
                compliance_support=host_refs + net_refs,
            )
        )

    if total_payload_packets > 0 and not (cleartext_flows or db_flows or legacy_tls_flows or http_update_urls):
        pct_tls = round((encrypted_tls_packets / total_payload_packets) * 100, 1)
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title="No Cleartext Credentials, Direct DB Traffic, or Legacy TLS Handshakes in Capture",
                category="Network & Transport",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(pcap_path),
                summary=(
                    f"Analyzed {total_payload_packets} payload packet(s) ({pct_tls}% TLS records) "
                    "with zero cleartext credential, direct DB, or HTTP updater signatures matched."
                ),
                evidence={
                    "packets_analyzed": total_payload_packets,
                    "tls_record_packets": encrypted_tls_packets,
                    "tls_coverage_percent": pct_tls,
                    "parser_backend": "scapy" if HAS_SCAPY else "builtin_pcap_pcapng",
                },
                compliance_support=net_refs,
            )
        )

    if "tcp_payloads" in locals() and tcp_payloads:
        findings.extend(inspect_wire_protocols(tcp_payloads, str(pcap_path), mapper))
    return findings