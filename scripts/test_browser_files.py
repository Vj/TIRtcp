#!/usr/bin/env python3
"""AI-browser / Chromium-family file test script for TIRtcp.

  python scripts/test_browser_files.py --self-test            # build a synthetic AI-browser install+profile, scan it, verify detections
  python scripts/test_browser_files.py --self-test --keep DIR # also keep the fixture
  python scripts/test_browser_files.py --target "C:\\Users\\me\\AppData\\Local\\SomeAIBrowser"   # scan a REAL install/profile dir (read-only)

Self-test fixture contains deliberately weak, fake artifacts: plaintext + DPAPI-style saved passwords, plaintext session cookie,
Local State without app-bound key, launch flags (--no-sandbox, remote debugging, ignore-cert-errors), over-privileged extension,
wildcard native-messaging host, plaintext AI conversation store, MCP config with plaintext token, LLM API key in Preferences,
Chromium version dir. Exit code 0 = every expected detection fired (and the benign controls stayed quiet)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

FAKE_KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # synthetic, not a real credential


def build_fixture(out: Path) -> Path:
    import create_demo_target as demo
    app = out / "AIBrowser" / "Application"; prof = out / "AIBrowser" / "User Data" / "Default"
    (app / "127.0.6533.100").mkdir(parents=True, exist_ok=True); prof.mkdir(parents=True, exist_ok=True)
    (app / "aibrowser.exe").write_bytes(demo.minimal_pe()); (app / "chrome_elf.dll").write_bytes(demo.minimal_pe())
    (app / "launch_args.txt").write_text("aibrowser.exe --no-sandbox --remote-debugging-port=9222 --remote-allow-origins=* --ignore-certificate-errors")

    con = sqlite3.connect(prof / "Login Data")
    con.execute("create table logins(origin_url text, username_value text, password_value blob)")
    con.executemany("insert into logins values(?,?,?)", [
        ("https://bank.example.net/login", "alice", b"hunter2-plain"),
        ("https://mail.example.net/", "alice", b"v10" + b"\x01" * 40),
        ("https://wiki.example.net/", "alice", b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf" + b"\x02" * 30)])
    con.commit(); con.close()
    con = sqlite3.connect(prof / "Cookies")
    con.execute("create table cookies(host_key text, name text, value text, encrypted_value blob, is_secure int, is_httponly int)")
    con.executemany("insert into cookies values(?,?,?,?,?,?)", [
        ("app.example.net", "session_token", "abc123plainsession", b"", 0, 0),
        ("app.example.net", "theme", "dark", b"", 0, 0)])           # benign control: non-sensitive name
    con.commit(); con.close()
    (out / "AIBrowser" / "User Data" / "Local State").write_text(json.dumps({"os_crypt": {"encrypted_key": "RFBBUEkx..."}}))
    (prof / "Preferences").write_text(json.dumps({"assistant": {"api_key": FAKE_KEY, "model": "gpt-x"}}))
    ext = prof / "Extensions" / "abcdefghijklmnopabcdefghijklmnop" / "1.0"; ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({"manifest_version": 3, "name": "AI Sidebar", "version": "1.0",
        "permissions": ["debugger", "cookies", "nativeMessaging", "history"], "host_permissions": ["<all_urls>"],
        "content_security_policy": {"extension_pages": "script-src 'self' 'unsafe-eval'"}}))
    good = prof / "Extensions" / "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" / "2.0"; good.mkdir(parents=True)      # benign control
    (good / "manifest.json").write_text(json.dumps({"manifest_version": 3, "name": "Dark Theme", "version": "2.0", "permissions": ["storage"]}))
    nm = out / "AIBrowser" / "User Data" / "NativeMessagingHosts"; nm.mkdir()
    (nm / "com.aibrowser.agent.json").write_text(json.dumps({"name": "com.aibrowser.agent", "path": r"C:\Users\bob\AppData\Local\agent\host.exe", "allowed_origins": ["chrome-extension://*/"]}))
    (prof / "conversations.json").write_text(json.dumps([{"role": "user", "content": "summarise my bank statement ..."}]))
    (out / "AIBrowser" / "User Data" / "mcp.json").write_text(json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["fs-server"], "env": {"API_TOKEN": "tok_live_9f8e7d6c5b4a3921"}}}}))
    return out / "AIBrowser"


EXPECT = [  # (label, substring that must appear in a finding title)
    ("plaintext saved passwords", "Saved Passwords Stored in Plaintext"),
    ("DPAPI/v10 only credential protection", "Protected Only by User-Level Key"),
    ("plaintext session cookie", "Cookies Stored Unencrypted"),
    ("cookie flags missing", "Missing Secure/HttpOnly"),
    ("Local State key material", "Encryption Key Material"),
    ("dangerous launch flags", "Dangerous Chromium Command-Line Flags"),
    ("over-privileged extension", "Over-Privileged Browser Extension: AI Sidebar"),
    ("weak native messaging host", "Native Messaging Host Weakly Constrained"),
    ("plaintext AI conversations", "AI Conversation / Memory / Agent History Stored Unencrypted"),
    ("MCP config plaintext secret", "AI Agent / MCP Server Configuration With Plaintext Secrets"),
    ("LLM API key in prefs", "LLM Provider API Key"),
    ("Chromium runtime inventory", "Embedded Chromium / CEF / Electron Runtime Detected"),
]
MUST_NOT = ["Over-Privileged Browser Extension: Dark Theme"]     # benign control must stay quiet


def run(target: Path):
    from analyzer.core.compliance_loader import ComplianceMapper
    from analyzer.core.context import ScanContext
    from analyzer.modules.static_audit.browser_profile_audit import scan_browser_artifacts
    from analyzer.modules.static_audit.string_intel import scan_string_intel
    m = ComplianceMapper(ROOT / "tests/fixtures/compliance_map.test.yaml", profile="general")
    ctx = ScanContext(target)
    return scan_browser_artifacts(target, m, ctx=ctx) + scan_string_intel(target, m, ctx=ctx)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true"); ap.add_argument("--target", type=Path); ap.add_argument("--keep", type=Path)
    a = ap.parse_args()
    if not (a.self_test or a.target):
        ap.error("use --self-test or --target DIR")
    if a.target:
        fs = run(a.target)
        for f in sorted(fs, key=lambda x: x.severity.value):
            print(f"[{f.severity.value:<8}] {f.status.value:<16} {f.check_id}  {f.title}")
        print(f"\n{len(fs)} finding(s). Read-only scan complete."); return 0
    base = a.keep or Path(tempfile.mkdtemp(prefix="tirtcp_aibrowser_"))
    base.mkdir(parents=True, exist_ok=True)
    target = build_fixture(base)
    titles = [f.title for f in run(target)]
    ok = True
    print(f"fixture: {target}\n")
    for label, needle in EXPECT:
        hit = any(needle in t for t in titles); ok &= hit
        print(f"  [{'PASS' if hit else 'FAIL'}] {label}")
    for needle in MUST_NOT:
        quiet = not any(needle in t for t in titles); ok &= quiet
        print(f"  [{'PASS' if quiet else 'FAIL'}] control stays quiet: {needle.split(': ')[-1]}")
    leaked = any(s in json.dumps(titles) for s in (FAKE_KEY, "hunter2-plain", "abc123plainsession"))
    ok &= not leaked
    print(f"  [{'PASS' if not leaked else 'FAIL'}] no secret values in finding titles")
    print("\nRESULT:", "ALL CHECKS PASSED" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
