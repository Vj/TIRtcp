"""
TIRtcp Network Protocol Module: Offline PCAP & Custom Wire-Protocol Analyzer
Detects:
- Cleartext TCP/UDP credentials & unencrypted application traffic (TCP-NET-001)
- Direct database wire protocols: MSSQL TDS, MySQL, PostgreSQL, Oracle TNS (TCP-NET-001 / TCP-SEC-001)
- Deprecated TLS (< 1.2) handshake records in captured traffic (TCP-NET-001)
- Insecure HTTP (cleartext) auto-update & binary download requests (TCP-HOST-001)
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)

try:
    from scapy.all import IP, IPv6, Raw, TCP, UDP, rdpcap  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# Direct Database Wire-Protocol Signatures
DB_WIRE_SIGNATURES: List[Tuple[str, int, bytes]] = [
    ("MSSQL Tabular Data Stream (TDS)", 1433, b"\x12\x01\x00"),
    ("Oracle TNS Connect Packet", 1521, b"(CONNECT_DATA="),
    ("PostgreSQL Wire Protocol", 5432, b"\x00user\x00"),
]

MYSQL_GREETING_RE = re.compile(rb"^.\x00\x00\x00\x0a([3-8]\.[0-9]+\.[0-9]+)")

# Cleartext Credential / Auth Patterns in TCP/UDP Streams
CLEARTEXT_AUTH_RE = re.compile(
    rb"(?i)(?:Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}|"
    rb"(?:^|[\r\n&{,\"\s])(?:password|passwd|pwd|passcode)\s*[:=]\s*[\"']?([^\s\"'&},;]{3,64}))"
)

# Plaintext HTTP Auto-Update / Installer Fetch Pattern
HTTP_UPDATER_RE = re.compile(
    rb"GET\s+(/[^\s]*?(?:update|patch|upgrade|release|version|manifest|\.exe|\.msi|\.dll|\.zip)[^\s]*)\s+HTTP/1\.[01]\r\nHost:\s*([^\r\n]+)",
    re.IGNORECASE,
)


def _iter_packets_fallback(pcap_path: Path) -> Iterator[Tuple[str, int, str, int, str, bytes]]:
    """
    Pure-Python classic PCAP (magic 0xa1b2c3d4 / 0xd4c3b2a1) Ethernet/IPv4/TCP+UDP parser
    used automatically when Scapy is not installed.
    Yields: (src_ip, src_port, dst_ip, dst_port, proto, payload_bytes)
    """
    data = pcap_path.read_bytes()
    if len(data) < 24:
        return

    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        return

    offset = 24
    total = len(data)
    while offset + 16 <= total:
        _, _, incl_len, _ = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len

        if len(frame) < 34:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0800:  # IPv4
            continue

        ip_start = 14
        ihl = (frame[ip_start] & 0x0F) * 4
        if len(frame) < ip_start + ihl:
            continue

        proto_num = frame[ip_start + 9]
        src_ip = ".".join(str(b) for b in frame[ip_start + 12 : ip_start + 16])
        dst_ip = ".".join(str(b) for b in frame[ip_start + 16 : ip_start + 20])
        l4_start = ip_start + ihl

        if proto_num == 6 and len(frame) >= l4_start + 20:  # TCP
            src_port, dst_port = struct.unpack("!HH", frame[l4_start : l4_start + 4])
            data_offset = ((frame[l4_start + 12] >> 4) & 0x0F) * 4
            payload = frame[l4_start + data_offset :]
            if payload:
                yield src_ip, src_port, dst_ip, dst_port, "TCP", payload
        elif proto_num == 17 and len(frame) >= l4_start + 8:  # UDP
            src_port, dst_port = struct.unpack("!HH", frame[l4_start : l4_start + 4])
            payload = frame[l4_start + 8 :]
            if payload:
                yield src_ip, src_port, dst_ip, dst_port, "UDP", payload


def _iter_packets(pcap_path: Path) -> Iterator[Tuple[str, int, str, int, str, bytes]]:
    """Iterate L4 payloads using Scapy if available, else pure-Python PCAP parser."""
    if HAS_SCAPY:
        packets = rdpcap(str(pcap_path))
        for pkt in packets:
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
) -> List[Finding]:
    """
    Analyze a thick-client PCAP/PCAPNG capture for cleartext credentials, direct database
    wire protocols, deprecated TLS handshakes, and plaintext HTTP auto-update requests.
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
                summary=f"Specified PCAP file does not exist: {pcap_path}",
                compliance_support=net_refs,
            )
        ]

    cleartext_flows: Dict[str, Dict[str, Any]] = {}
    db_flows: Dict[str, Dict[str, Any]] = {}
    legacy_tls_flows: Dict[str, Dict[str, Any]] = {}
    http_update_urls: Dict[str, Dict[str, Any]] = {}
    total_payload_packets = 0

    for src_ip, src_port, dst_ip, dst_port, proto, payload in _iter_packets(pcap_path):
        total_payload_packets += 1
        flow_key = f"{src_ip} -> {dst_ip}:{dst_port} ({proto})"

        # 1. Detect Deprecated TLS Record Versions in Handshake Frames
        # TLS Handshake ContentType = 0x16; Version 0x0300 (SSLv3), 0x0301 (TLS 1.0), 0x0302 (TLS 1.1)
        if proto == "TCP" and len(payload) >= 6 and payload[0] == 0x16:
            rec_ver = payload[1:3]
            ver_map = {
                b"\x03\x00": "SSLv3",
                b"\x03\x01": "TLSv1.0",
                b"\x03\x02": "TLSv1.1",
            }
            if rec_ver in ver_map:
                legacy_tls_flows[flow_key] = {
                    "flow": flow_key,
                    "protocol_version": ver_map[rec_ver],
                }

        # 2. Detect Direct Database Wire Protocols
        for db_name, default_port, sig in DB_WIRE_SIGNATURES:
            if sig in payload or (dst_port == default_port and len(payload) > 8 and payload[0] != 0x16):
                if sig in payload:
                    db_flows[flow_key] = {
                        "flow": flow_key,
                        "database_protocol": db_name,
                        "destination_port": dst_port,
                    }

        if dst_port == 3306 or src_port == 3306:
            m_mysql = MYSQL_GREETING_RE.search(payload)
            if m_mysql:
                db_flows[flow_key] = {
                    "flow": flow_key,
                    "database_protocol": f"MySQL Wire Protocol (Server {m_mysql.group(1).decode('ascii', 'ignore')})",
                    "destination_port": 3306 if dst_port == 3306 else src_port,
                }

        # 3. Detect Insecure HTTP Auto-Update / Binary Download Requests
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

        # 4. Detect Cleartext Credentials / Auth Headers in TCP or UDP Payloads
        if CLEARTEXT_AUTH_RE.search(payload):
            cleartext_flows[flow_key] = {
                "flow": flow_key,
                "protocol": proto,
                "sample_preview": payload[:120].decode("utf-8", errors="replace"),
            }

    # Emit Findings
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
                summary=(
                    "Captured network traffic contains unencrypted credentials or Basic/plaintext "
                    "authentication parameters, exposing sessions to passive interception."
                ),
                evidence=info,
                remediation="Enforce TLS 1.2/1.3 encryption for all client-server communication channels.",
                compliance_support=net_refs,
                manual_playbook=PlaybookRef(
                    tool="Wireshark",
                    objective="Follow the TCP/UDP stream to determine the full scope of exposed session data.",
                    steps=[
                        f"Open {pcap_path.name} in Wireshark and filter by `{info['flow'].split(' ')[0]}`.",
                        "Right-click the stream and select 'Follow -> TCP/UDP Stream' to inspect authentication and business payload framing.",
                    ],
                ),
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
                summary=(
                    f"Thick client communicates directly with a backend database over {info['database_protocol']}, "
                    "indicating a 2-tier architecture vulnerable to direct query manipulation."
                ),
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
                summary=(
                    "Client fetches update manifests or executable payloads over unencrypted HTTP, "
                    "exposing endpoints to MitM binary injection."
                ),
                evidence=info,
                remediation="Serve all update manifests and installers exclusively over HTTPS with signature verification.",
                compliance_support=host_refs + net_refs,
            )
        )

    if total_payload_packets > 0 and not (cleartext_flows or db_flows or legacy_tls_flows or http_update_urls):
        findings.append(
            Finding(
                check_id="TCP-NET-001",
                title="No Cleartext Credentials, Direct DB Traffic, or Legacy TLS Handshakes in PCAP",
                category="Network & Transport",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                affected_asset=str(pcap_path),
                summary=(
                    f"Analyzed {total_payload_packets} TCP/UDP payload packet(s) in {pcap_path.name} "
                    "with zero cleartext credential, direct DB, or HTTP updater signatures matched."
                ),
                evidence={
                    "packets_analyzed": total_payload_packets,
                    "parser_backend": "scapy" if HAS_SCAPY else "builtin_pcap",
                },
                compliance_support=net_refs,
            )
        )

    return findings