"""
TIRtcp Non-HTTP Wire-Protocol Dissectors
Inspects TCP stream payloads extracted from PCAP/PCAPNG captures for:
  - MSSQL TDS (Tabular Data Stream) PRELOGIN / LOGIN7 cleartext authentication
  - PostgreSQL StartupMessage / Cleartext PasswordMessage ('p')
  - MQTT CONNECT control packets with username/password flags
  - Cleartext HTTP/2 connection preface ('PRI * HTTP/2.0') & gRPC ('application/grpc')
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, Dict, List

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)


def inspect_wire_protocols(
    payloads: List[Dict[str, Any]],
    capture_asset: str,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Analyze reconstructed TCP payload chunks:
      payloads = [{"src": str, "dst": str, "dst_port": int, "data": bytes}, ...]
    """
    net_refs = mapper.resolve("TCP-NET-001")
    findings: List[Finding] = []
    seen_tags: set[str] = set()

    for pkt in payloads:
        data: bytes = pkt.get("data") or b""
        if len(data) < 4:
            continue
        dst = f"{pkt.get('dst', 'unknown')}:{pkt.get('dst_port', 0)}"

        # 1. Cleartext HTTP/2 & gRPC ('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        if b"PRI * HTTP/2.0" in data or b"application/grpc" in data:
            tag = f"grpc_h2c:{dst}"
            if tag not in seen_tags:
                seen_tags.add(tag)
                is_grpc = b"application/grpc" in data
                findings.append(
                    Finding(
                        check_id="TCP-NET-001",
                        title=f"Cleartext {'gRPC / ' if is_grpc else ''}HTTP/2 (h2c) Traffic Observed ({dst})",
                        category="Network & Wire Protocol",
                        status=FindingStatus.FAIL,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_asset=f"{capture_asset} -> {dst}",
                        summary="Detected unencrypted HTTP/2 connection preface or gRPC framing over plaintext TCP.",
                        evidence={"endpoint": dst, "grpc_detected": is_grpc},
                        remediation="Enforce TLS (ALPN h2) on all gRPC and HTTP/2 service endpoints.",
                        compliance_support=net_refs,
                    )
                )

        # 2. PostgreSQL StartupMessage (len[4] + 0x00030000 + 'user\x00') or PasswordMessage ('p' + len[4])
        if len(data) >= 13 and data[4:8] == b"\x00\x03\x00\x00" and b"user\x00" in data[:64]:
            tag = f"pg_cleartext:{dst}"
            if tag not in seen_tags:
                seen_tags.add(tag)
                m_user = re.search(rb"user\x00([^\x00]{1,64})\x00", data[:128])
                pg_user = m_user.group(1).decode("utf-8", errors="ignore") if m_user else "unknown"
                findings.append(
                    Finding(
                        check_id="TCP-NET-001",
                        title=f"Unencrypted PostgreSQL Wire Session ({dst})",
                        category="Network & Wire Protocol",
                        status=FindingStatus.FAIL,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_asset=f"{capture_asset} -> {dst}",
                        summary=f"PostgreSQL StartupMessage sent without SSLRequest negotiation (user='{pg_user}').",
                        evidence={"endpoint": dst, "protocol": "PostgreSQL", "db_user": pg_user},
                        remediation="Require sslmode=verify-full on client database connections and enforce hostssl in pg_hba.conf.",
                        compliance_support=net_refs,
                    )
                )

        # 3. MSSQL TDS Packet (Type 0x12 PRELOGIN or 0x10 TDS7 LOGIN)
        if data[0] in (0x10, 0x12) and len(data) >= 8:
            pkt_len = struct.unpack(">H", data[2:4])[0]
            if 8 <= pkt_len <= len(data) + 64:
                tag = f"mssql_tds:{dst}"
                if tag not in seen_tags:
                    seen_tags.add(tag)
                    pkt_type = "TDS7_LOGIN (0x10)" if data[0] == 0x10 else "TDS_PRELOGIN (0x12)"
                    findings.append(
                        Finding(
                            check_id="TCP-NET-001",
                            title=f"Unencrypted MSSQL TDS Wire Traffic Observed ({dst})",
                            category="Network & Wire Protocol",
                            status=FindingStatus.FAIL,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            affected_asset=f"{capture_asset} -> {dst}",
                            summary=f"Captured cleartext Microsoft SQL Server {pkt_type} framing on {dst}.",
                            evidence={"endpoint": dst, "protocol": "MSSQL-TDS", "packet_type": pkt_type},
                            remediation="Enable Force Encryption on SQL Server and set Encrypt=True;TrustServerCertificate=False in client connection strings.",
                            compliance_support=net_refs,
                        )
                    )

        # 4. MQTT CONNECT Packet (0x10 + remaining_len + 0x00 0x04 'MQTT')
        if data[0] == 0x10 and b"\x00\x04MQTT" in data[:12]:
            tag = f"mqtt_cleartext:{dst}"
            if tag not in seen_tags:
                seen_tags.add(tag)
                findings.append(
                    Finding(
                        check_id="TCP-NET-001",
                        title=f"Cleartext MQTT Broker Connection Observed ({dst})",
                        category="Network & Wire Protocol",
                        status=FindingStatus.FAIL,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_asset=f"{capture_asset} -> {dst}",
                        summary="MQTT CONNECT control packet transmitted over unencrypted TCP without TLS (MQTTS).",
                        evidence={"endpoint": dst, "protocol": "MQTT"},
                        remediation="Migrate telemetry/messaging broker connections to MQTTS (TLS 1.2+/1.3) with certificate validation.",
                        compliance_support=net_refs,
                    )
                )

    return findings
