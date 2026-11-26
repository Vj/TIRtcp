#!/usr/bin/env python3
"""Build a SAFE, synthetic, deliberately-weak thick-client fixture for end-to-end testing of TIRtcp.

Nothing here is real: credentials are fake canaries, binaries are minimal hand-assembled PE stubs
(non-executable data), the PCAP is hand-written. Output layout:

  <out>/DemoClient/            DemoClient.exe (PE, no ASLR/DEP), config w/ DB string, log w/ PAN,
                               debug.pdb, resources/app.asar (insecure webPreferences, minified)
  <out>/host_evidence.json     weak ACL + unquoted URI handler + SYSTEM task
  <out>/capture.pcap           cleartext password, TDS prelogin, HTTP update, + a *benign* modern ClientHello
  <out>/procmon.csv            phantom DLL probe in a user-writable path
  <out>/post_logout.dmp        canary retained in 'memory'
  <out>/EXPECTED.json          what a correct analyzer should report (used by tests)
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

CANARY = "CanaryPass#2026"


def minimal_pe(machine: int = 0x8664, dll_chars: int = 0x0000) -> bytes:
    """Smallest PE the parsers accept: DOS hdr + PE sig + COFF + PE32+ optional hdr + 1 section."""
    dos = bytearray(64); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                      # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)                    # entry rva
    struct.pack_into("<Q", opt, 24, 0x140000000)               # image base
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)            # section/file align
    struct.pack_into("<HH", opt, 40, 6, 0)                     # os ver
    struct.pack_into("<HH", opt, 48, 6, 0)                     # subsystem ver
    struct.pack_into("<II", opt, 56, 0x2000, 0x200)            # image/hdr size
    struct.pack_into("<H", opt, 68, 3)                         # subsystem console
    struct.pack_into("<H", opt, 70, dll_chars)                 # DllCharacteristics
    struct.pack_into("<QQQQ", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", opt, 108, 16)                       # NumberOfRvaAndSizes
    sect = struct.pack("<8sIIIIIIHHI", b".text", 0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sect
    return hdr.ljust(0x200, b"\0") + b"\xC3".ljust(0x200, b"\0")


def asar_bytes(files: dict[str, str]) -> bytes:
    header, blob, off = {"files": {}}, b"", 0
    for name, text in files.items():
        data = text.encode()
        header["files"][name] = {"size": len(data), "offset": str(off)}
        blob += data; off += len(data)
    j = json.dumps(header, separators=(",", ":")).encode()
    padded = j + b"\0" * ((4 - len(j) % 4) % 4)
    inner = struct.pack("<II", len(padded) + 4, len(j)) + padded
    return struct.pack("<II", 4, len(inner)) + inner + blob


def ipv4_tcp_frame(src, dst, sport, dport, payload: bytes) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


def write_pcap(path: Path, frames: list[bytes]) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", i, 0, len(fr), len(fr)) + fr
    path.write_bytes(out)


def client_hello(record_ver=0x0301, client_ver=0x0303, supported=(0x0304, 0x0303)) -> bytes:
    exts = struct.pack("!HHB", 43, 1 + 2 * len(supported), 2 * len(supported)) + b"".join(struct.pack("!H", v) for v in supported)
    body = struct.pack("!H", client_ver) + b"\x11" * 32 + b"\x00" + struct.pack("!HH", 2, 0x1301) + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!HH", record_ver, len(hs)) + hs


def server_hello(version=0x0301) -> bytes:
    body = struct.pack("!H", version) + b"\x22" * 32 + b"\x00" + struct.pack("!HB", 0x002F, 0) + struct.pack("!H", 0)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!HH", version, len(hs)) + hs


def build(out: Path) -> dict:
    app = out / "DemoClient"; (app / "resources").mkdir(parents=True, exist_ok=True)
    (app / "DemoClient.exe").write_bytes(minimal_pe(dll_chars=0x0000))
    (app / "app.config").write_text(
        '<configuration><connectionStrings><add name="db" connectionString="Server=10.0.0.5;Database=core;'
        'User ID=sa;Password=Pr0d#MyPassword99;" /></connectionStrings></configuration>')
    (app / "client.log").write_text(
        "2026-11-24 10:00:01 INFO login ok\n2026-11-24 10:00:02 DEBUG pan=4111 1111 1111 1111\n"
        "2026-11-24 10:00:03 DEBUG aadhaar=234123412346 ts=202611241530\nrequest id=ABCDE1234F\n"
        "Authorization: Bearer abcdefghijklmnop1234567890\n")
    (app / "debug.pdb").write_bytes(b"Microsoft C/C++ MSF 7.00")
    (app / "resources" / "app.asar").write_bytes(asar_bytes({
        "main.js": 'new BrowserWindow({webPreferences:{nodeIntegration:!0,contextIsolation:!1}});'}))

    (out / "host_evidence.json").write_text(json.dumps({
        "hostname": "DEMO-HOST",
        "weak_acls": [{"path": r"C:\Program Files\DemoClient\updater", "principal": "BUILTIN\\Users", "rights": "(M)"}],
        "custom_uri_handlers": [{"scheme": "democlient", "command": r'"C:\Program Files\DemoClient\DemoClient.exe" %1', "unquoted_url_argument": True}],
        "scheduled_tasks": [{"task_name": "DemoUpdate", "run_as_user": "NT AUTHORITY\\SYSTEM", "task_to_run": r"C:\Program Files\DemoClient\updater\up.exe"}],
        "named_pipes": [], "com_dcom_appids": [], "insecure_services": [],
    }, indent=2))

    write_pcap(out / "capture.pcap", [
        ipv4_tcp_frame("10.0.0.2", "10.0.0.9", 50000, 8080, b"POST /login HTTP/1.1\r\nHost: a\r\n\r\nuser=a&password=Sup3rSecret!"),
        ipv4_tcp_frame("10.0.0.2", "10.0.0.5", 50001, 1433, b"\x12\x01\x00\x2f" + b"\0" * 40),
        ipv4_tcp_frame("10.0.0.2", "10.0.0.9", 50002, 80, b"GET /updates/setup.exe HTTP/1.1\r\nHost: dl.demo.local\r\n\r\n"),
        ipv4_tcp_frame("10.0.0.2", "10.0.0.7", 50003, 443, client_hello()),          # BENIGN: must NOT be flagged
        ipv4_tcp_frame("10.0.0.8", "10.0.0.2", 443, 50004, server_hello(0x0301)),    # TRUE legacy: must be flagged
    ])
    (out / "procmon.csv").write_text(
        '"Process Name","Operation","Path","Result"\n'
        r'"DemoClient.exe","CreateFile","C:\Users\bob\AppData\Local\DemoClient\evil.dll","NAME NOT FOUND"' "\n")
    (out / "post_logout.dmp").write_bytes(b"\0" * 5000 + CANARY.encode() + b"\0" * 5000)

    expected = {
        "must_detect": ["TCP-BIN-001", "TCP-SEC-001", "TCP-SEC-002", "TCP-ELEC-001", "TCP-HOST-001", "TCP-HOST-002", "TCP-IPC-001", "TCP-NET-001", "TCP-MEM-001"],
        "pcap_legacy_tls_flows": 1, "procmon_candidates": 1, "memory_canary_hits": 1,
        "pan_findings_in_log": 1, "aadhaar_findings_in_log": 1,
    }
    (out / "EXPECTED.json").write_text(json.dumps(expected, indent=2))
    return expected


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("./demo_fixture"))
    a = ap.parse_args(); build(a.out); print(f"fixture written to {a.out.resolve()}")
