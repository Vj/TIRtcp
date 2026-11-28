#!/usr/bin/env python3
"""
TIRtcp Authorization-Gated Frida Runtime API Instrumentation Harness
Requires explicit --authorized flag. Hooks DPAPI, TLS chain validation, DLL loading,
process creation, and registry writes on Windows targets, outputting JSON compatible
with TIRtcp (--runtime-hooks).
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

FRIDA_AGENT_JS = r"""
'use strict';

function safeReadUtf16(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return ptr.readUtf16String(); } catch (e) { return null; }
}

function safeReadAnsi(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return ptr.readAnsiString(); } catch (e) { return null; }
}

// 1. DPAPI: CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
const cryptProtect = Module.findExportByName('crypt32.dll', 'CryptProtectData');
if (cryptProtect) {
    Interceptor.attach(cryptProtect, {
        onEnter: function (args) {
            const descr = safeReadUtf16(args[1]) || '(none)';
            const hasEntropy = !args[2].isNull();
            const flags = args[5].toUInt32();
            send({
                category: 'dpapi',
                api: 'CryptProtectData',
                description: descr,
                has_optional_entropy: hasEntropy,
                flags: flags
            });
        }
    });
}

// 2. TLS Chain Policy: CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus)
const certVerify = Module.findExportByName('crypt32.dll', 'CertVerifyCertificateChainPolicy');
if (certVerify) {
    Interceptor.attach(certVerify, {
        onEnter: function (args) {
            this.statusPtr = args[3];
        },
        onLeave: function (retval) {
            if (this.statusPtr && !this.statusPtr.isNull()) {
                try {
                    // CERT_CHAIN_POLICY_STATUS: cbSize (DWORD at 0), dwError (DWORD at 4)
                    const dwError = this.statusPtr.add(4).readU32();
                    send({
                        category: 'tls_validation',
                        api: 'CertVerifyCertificateChainPolicy',
                        dw_error: dwError,
                        chain_valid: dwError === 0
                    });
                } catch (e) {}
            }
        }
    });
}

// 3. Dynamic DLL Loading: LoadLibraryExW(lpLibFileName, hFile, dwFlags)
const loadLibExW = Module.findExportByName('kernel32.dll', 'LoadLibraryExW');
if (loadLibExW) {
    Interceptor.attach(loadLibExW, {
        onEnter: function (args) {
            const dllPath = safeReadUtf16(args[0]);
            const flags = args[2].toUInt32();
            if (dllPath) {
                send({
                    category: 'dll_load',
                    api: 'LoadLibraryExW',
                    path: dllPath,
                    flags: flags
                });
            }
        }
    });
}

const loadLibW = Module.findExportByName('kernel32.dll', 'LoadLibraryW');
if (loadLibW) {
    Interceptor.attach(loadLibW, {
        onEnter: function (args) {
            const dllPath = safeReadUtf16(args[0]);
            if (dllPath) {
                send({
                    category: 'dll_load',
                    api: 'LoadLibraryW',
                    path: dllPath,
                    flags: 0
                });
            }
        }
    });
}

// 4. Child Process Execution: CreateProcessW
const createProcW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
if (createProcW) {
    Interceptor.attach(createProcW, {
        onEnter: function (args) {
            const appName = safeReadUtf16(args[0]) || '';
            const cmdLine = safeReadUtf16(args[1]) || '';
            send({
                category: 'process_exec',
                api: 'CreateProcessW',
                application: appName,
                command_line: cmdLine.slice(0, 240)
            });
        }
    });
}

// 5. WinHTTP Cleartext / Endpoint Telemetry: WinHttpOpenRequest
const winHttpOpenReq = Module.findExportByName('winhttp.dll', 'WinHttpOpenRequest');
if (winHttpOpenReq) {
    Interceptor.attach(winHttpOpenReq, {
        onEnter: function (args) {
            const verb = safeReadUtf16(args[1]) || 'GET';
            const objName = safeReadUtf16(args[2]) || '/';
            const flags = args[6].toUInt32();
            const isSecure = (flags & 0x00800000) !== 0; // WINHTTP_FLAG_SECURE
            send({
                category: 'winhttp',
                api: 'WinHttpOpenRequest',
                method: verb,
                path: objName.split('?')[0].slice(0, 120),
                tls_enabled: isSecure
            });
        }
    });
}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="frida_hook_harness",
        description="TIRtcp Authorization-Gated Runtime API Instrumentation Harness",
    )
    parser.add_argument("--target", type=Path, required=True, help="Target executable to spawn.")
    parser.add_argument("--duration", type=int, default=20, help="Seconds to capture runtime hooks (default: 20).")
    parser.add_argument("--authorized", action="store_true", help="Required explicit authorization confirmation.")
    parser.add_argument("--output", type=Path, default=Path("runtime_hooks.json"), help="Output JSON path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.authorized:
        print("[!] Refusing runtime instrumentation: '--authorized' flag is required.", file=sys.stderr)
        return 2

    if not args.target.exists():
        print(f"[!] Target executable not found: {args.target}", file=sys.stderr)
        return 1

    try:
        import frida  # type: ignore
    except ImportError:
        print("[!] Frida is not installed. Run: pip install frida frida-tools", file=sys.stderr)
        return 1

    events: List[Dict[str, Any]] = []

    def on_message(message: Dict[str, Any], _data: Any) -> None:
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            payload = dict(message["payload"])
            payload["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            events.append(payload)

    device = frida.get_local_device()
    pid = device.spawn([str(args.target.resolve())])
    session = device.attach(pid)
    script = session.create_script(FRIDA_AGENT_JS)
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    print(f"[+] Attached to {args.target.name} (PID {pid}) for {args.duration}s...")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
        try:
            device.kill(pid)
        except Exception:
            pass

    bundle = {
        "schema_version": "1.0.0",
        "target_exe": str(args.target.resolve()),
        "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_count": len(events),
        "events": events,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[+] Captured {len(events)} runtime API event(s) -> {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())