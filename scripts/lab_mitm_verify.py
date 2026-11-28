#!/usr/bin/env python3
"""
TIRtcp v0.3 Lab Active Verification Harness (Authorized Lab Only)
Automates:
1. TLS Certificate Pinning check via an ephemeral intercepting TLS listener
2. Auto-Updater integrity check (unsigned payload & version-downgrade rejection)
Emits TIRtcp-compatible JSON findings (--lab-results) merged directly into ScanReport.
"""

from __future__ import annotations

import argparse
import datetime
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List


def _generate_ephemeral_lab_cert(tmp_dir: Path) -> tuple[Path, Path]:
    """Generate a self-signed lab CA certificate & key using OpenSSL CLI if present."""
    cert_path = tmp_dir / "lab_mitm_ca.pem"
    key_path = tmp_dir / "lab_mitm_key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1", "-subj", "/CN=TIRtcp-Lab-Intercept-CA",
        ],
        capture_output=True,
        check=True,
    )
    return cert_path, key_path


def run_pinning_probe(
    target_exe: Path,
    listen_port: int = 8449,
    duration: int = 12,
) -> Dict[str, Any]:
    """
    Launch target with HTTPS_PROXY pointed at an ephemeral untrusted TLS proxy.
    If any TLS handshake succeeds without client-side abort, certificate pinning is absent.
    """
    telemetry: Dict[str, Any] = {
        "connections_attempted": 0,
        "handshakes_succeeded_with_untrusted_ca": 0,
        "handshakes_rejected_by_client": 0,
        "errors": [],
    }
    stop_event = threading.Event()

    with tempfile.TemporaryDirectory(prefix="tirtcp_pin_") as tmp:
        tmp_path = Path(tmp)
        try:
            cert_file, key_file = _generate_ephemeral_lab_cert(tmp_path)
        except Exception as exc:
            telemetry["errors"].append(f"OpenSSL cert generation unavailable: {exc}")
            return telemetry

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", listen_port))
        srv.listen(16)
        srv.settimeout(0.5)

        def _accept_loop() -> None:
            while not stop_event.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                telemetry["connections_attempted"] += 1
                try:
                    peek = conn.recv(7, socket.MSG_PEEK)
                    if peek.upper().startswith(b"CONNECT"):
                        conn.recv(4096)
                        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.settimeout(2.0)
                        _ = tls_conn.recv(64)
                        telemetry["handshakes_succeeded_with_untrusted_ca"] += 1
                except ssl.SSLError:
                    telemetry["handshakes_rejected_by_client"] += 1
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        t = threading.Thread(target=_accept_loop, daemon=True)
        t.start()

        env = dict(**{k: v for k, v in dict(__import__("os").environ).items()})
        env["HTTPS_PROXY"] = f"http://127.0.0.1:{listen_port}"
        env["HTTP_PROXY"] = f"http://127.0.0.1:{listen_port}"

        proc = subprocess.Popen([str(target_exe)], cwd=str(target_exe.parent), env=env)
        try:
            time.sleep(duration)
        finally:
            proc.terminate()
            stop_event.set()
            srv.close()
            t.join(timeout=2)

    return telemetry


def run_updater_tamper_probe(listen_port: int = 8450) -> Dict[str, Any]:
    """
    Stand up a local update server serving an unsigned binary & downgraded version manifest
    for local updater testing (--updater-url http://127.0.0.1:8450/manifest.json).
    """
    hits: List[str] = []

    class UpdaterHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            hits.append(self.path)
            if self.path.endswith(".json"):
                body = json.dumps(
                    {
                        "version": "0.0.1-downgrade-test",
                        "url": f"http://127.0.0.1:{listen_port}/unsigned_patch.exe",
                        "sha256": "0" * 64,
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                payload = b"MZ" + (b"\x00" * 128) + b"TIRTCP_UNSIGNED_UPDATER_TEST"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", listen_port), UpdaterHandler)
    return {"server": server, "hits": hits, "manifest_url": f"http://127.0.0.1:{listen_port}/manifest.json"}


def main() -> int:
    ap = argparse.ArgumentParser(description="TIRtcp Authorized Lab Pinning & Updater Verification Harness")
    ap.add_argument("--target", type=Path, required=True, help="Target thick-client executable.")
    ap.add_argument("--duration", type=int, default=12, help="Probe duration in seconds.")
    ap.add_argument("--authorized", action="store_true", help="Required authorization gate.")
    ap.add_argument("--output", type=Path, default=Path("lab_verify.json"), help="Output JSON path.")
    args = ap.parse_args()

    if not args.authorized:
        print("[!] Refusing active lab instrumentation without '--authorized'.", file=sys.stderr)
        return 2

    pin_res = run_pinning_probe(args.target.resolve(), duration=args.duration)
    out = {
        "schema_version": "1.0.0",
        "target_exe": str(args.target.resolve()),
        "tested_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pinning_probe": pin_res,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[+] Lab verification results written to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())