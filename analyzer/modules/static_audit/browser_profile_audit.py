"""TCP-BRW-001..005: Chromium / CEF / Electron-style browser and AI-browser artifact audit.

Targets the on-disk footprint of (AI) browsers: credential & cookie stores, Local State key material, launch flags,
extensions and native-messaging hosts, AI conversation/memory/agent/MCP artifacts, embedded Chromium version.
Read-only: SQLite files are opened with mode=ro&immutable=1; secrets are never written to findings."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import Confidence, Finding, FindingStatus, PlaybookRef, Severity

CAT = "Browser & AI-Browser Artifacts"
DPAPI_PREFIX = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"
SENSITIVE_COOKIE = re.compile(r"(?i)(sess|token|auth|jwt|sid|login|csrf|bearer)")
DANGEROUS_FLAGS: Dict[str, Tuple[Severity, str]] = {
    "--no-sandbox": (Severity.HIGH, "Disables the renderer sandbox: any renderer bug becomes full code execution as the user."),
    "--disable-web-security": (Severity.HIGH, "Disables same-origin policy: any page can read any other origin's data."),
    "--remote-debugging-port": (Severity.HIGH, "Opens the DevTools protocol on a TCP port: local processes (and with --remote-allow-origins, web pages) can drive the browser and read cookies/tokens."),
    "--remote-allow-origins=*": (Severity.HIGH, "Allows any web origin to connect to the DevTools websocket."),
    "--ignore-certificate-errors": (Severity.HIGH, "Disables TLS validation for all browsing and for the AI/agent back-end traffic."),
    "--allow-running-insecure-content": (Severity.MEDIUM, "Permits mixed content on HTTPS pages."),
    "--disable-site-isolation-trials": (Severity.MEDIUM, "Weakens cross-site process isolation (Spectre/UXSS mitigations)."),
    "--disable-features=isolateorigins": (Severity.MEDIUM, "Disables origin isolation."),
    "--unsafely-treat-insecure-origin-as-secure": (Severity.MEDIUM, "Treats HTTP origins as secure contexts."),
    "--disable-gpu-sandbox": (Severity.MEDIUM, "Disables the GPU process sandbox."),
    "--allow-file-access-from-files": (Severity.MEDIUM, "file:// pages can read other local files."),
}
DANGEROUS_PERMS = {"debugger": Severity.HIGH, "nativeMessaging": Severity.MEDIUM, "webRequestBlocking": Severity.MEDIUM,
                   "cookies": Severity.MEDIUM, "management": Severity.MEDIUM, "proxy": Severity.MEDIUM, "privacy": Severity.LOW,
                   "history": Severity.LOW, "<all_urls>": Severity.MEDIUM, "*://*/*": Severity.MEDIUM, "scripting": Severity.LOW}
AI_ARTIFACT_NAME = re.compile(r"(?i)(conversation|chat[_-]?history|chats?\.(?:json|db|sqlite)|assistant|agent[_-]?(?:memory|state|history)|memor(?:y|ies)|prompt[_-]?history|copilot|llm|mcp)")
MCP_CONFIG_NAME = re.compile(r"(?i)^(mcp[_-]?(?:servers|config)?\.json|claude_desktop_config\.json|mcp\.json)$")
SECRET_ENV = re.compile(r"(?i)(key|token|secret|passw)")
CHROMIUM_VER_DIR = re.compile(r"^\d{2,3}\.\d+\.\d+\.\d+$")


def _mk(cid: str, title: str, status: FindingStatus, sev: Severity, conf: Confidence, asset: str, summary: str, evidence: Dict[str, Any],
        mapper: ComplianceMapper, remediation: str = "", playbook: Optional[PlaybookRef] = None) -> Finding:
    return Finding(check_id=cid, title=title, category=CAT, status=status, severity=sev, confidence=conf, affected_asset=asset, summary=summary,
                   evidence=evidence, remediation=remediation, compliance_support=mapper.resolve(cid), manual_playbook=playbook)


def _ro_sqlite(path: Path) -> Optional[sqlite3.Connection]:
    try:
        con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True, timeout=2)
        con.execute("select name from sqlite_master limit 1")
        return con
    except sqlite3.Error:
        return None


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(16).startswith(b"SQLite format 3")
    except OSError:
        return False


def _walk(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root; return
    for r, _d, fs in os.walk(root):
        for f in fs:
            yield Path(r) / f


def audit_credential_stores(files: List[Path], mapper: ComplianceMapper) -> List[Finding]:
    out: List[Finding] = []
    for p in files:
        name = p.name.lower()
        if name.startswith("login data") and _is_sqlite(p):
            con = _ro_sqlite(p)
            if not con:
                continue
            try:
                rows = con.execute("select origin_url, password_value from logins").fetchall()
            except sqlite3.Error:
                continue
            plain = [r for r in rows if r[1] and not bytes(r[1]).startswith((b"v10", b"v11", b"v20", DPAPI_PREFIX)) ]
            v10 = [r for r in rows if r[1] and bytes(r[1]).startswith((b"v10", b"v11", DPAPI_PREFIX))]
            v20 = [r for r in rows if r[1] and bytes(r[1]).startswith(b"v20")]
            if plain:
                hosts = sorted({re.sub(r"^https?://([^/]+).*", r"\1", r[0] or "") for r in plain})[:10]
                out.append(_mk("TCP-BRW-001", "Saved Passwords Stored in Plaintext in Browser Credential Store", FindingStatus.FAIL, Severity.HIGH, Confidence.HIGH, str(p),
                               f"{len(plain)} saved credential(s) have no encryption envelope; any process or user with file access reads them directly (values not reproduced).",
                               {"plaintext_entries": len(plain), "sites": hosts}, mapper, "Encrypt with OS-backed keys (DPAPI/Keychain + app-bound encryption) or do not persist passwords."))
            if v10 and not v20:
                out.append(_mk("TCP-BRW-001", "Saved Passwords Protected Only by User-Level Key (Same-User Malware Can Decrypt)", FindingStatus.OBSERVATION, Severity.MEDIUM, Confidence.MEDIUM, str(p),
                               f"{len(v10)} credential(s) use v10/DPAPI-style encryption whose key is recoverable by any process running as the same user (infostealer model). No app-bound (v20) entries seen.",
                               {"v10_entries": len(v10), "v20_entries": 0}, mapper,
                               playbook=PlaybookRef("DPAPI tooling (lab only)", "Demonstrate same-user recoverability", ["Read Local State os_crypt.encrypted_key", "Decrypt via CryptUnprotectData in the same user session", "Decrypt a v10 blob (AES-256-GCM)"])))
            con.close()
        elif name == "cookies" and _is_sqlite(p):
            con = _ro_sqlite(p)
            if not con:
                continue
            try:
                cols = {r[1] for r in con.execute("pragma table_info(cookies)")}
                sel = "name, value, " + ("is_secure" if "is_secure" in cols else "1") + ", " + ("is_httponly" if "is_httponly" in cols else "1") + ", host_key"
                rows = con.execute(f"select {sel} from cookies").fetchall()
            except sqlite3.Error:
                continue
            plain = [r for r in rows if r[1] and SENSITIVE_COOKIE.search(r[0] or "")]
            weak = [r for r in rows if SENSITIVE_COOKIE.search(r[0] or "") and (not r[2] or not r[3])]
            if plain:
                out.append(_mk("TCP-BRW-001", "Session/Auth Cookies Stored Unencrypted", FindingStatus.FAIL, Severity.HIGH, Confidence.HIGH, str(p),
                               f"{len(plain)} session-like cookie(s) have a plaintext value column (values not reproduced): session theft by file read.",
                               {"cookie_names": sorted({r[0] for r in plain})[:15]}, mapper, "Store cookie values only in the encrypted_value column with OS-backed keys."))
            if weak:
                out.append(_mk("TCP-BRW-001", "Session Cookies Missing Secure/HttpOnly Flags", FindingStatus.FAIL, Severity.MEDIUM, Confidence.MEDIUM, str(p),
                               f"{len(weak)} session-like cookie(s) lack Secure and/or HttpOnly.", {"cookie_names": sorted({r[0] for r in weak})[:15], "hosts": sorted({r[4] for r in weak})[:10]}, mapper,
                               "Set Secure, HttpOnly and SameSite on all auth cookies."))
            con.close()
        elif name == "local state":
            try:
                ls = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, ValueError):
                continue
            oc = ls.get("os_crypt", {}) if isinstance(ls, dict) else {}
            out.append(_mk("TCP-BRW-001", "Browser Encryption Key Material (Local State os_crypt)", FindingStatus.OBSERVATION, Severity.INFO, Confidence.HIGH, str(p),
                           "DPAPI-wrapped key present" + ("; app-bound key present (stronger)" if oc.get("app_bound_encrypted_key") else "; no app-bound key (same-user decryptable)"),
                           {"encrypted_key_present": bool(oc.get("encrypted_key")), "app_bound_key_present": bool(oc.get("app_bound_encrypted_key"))}, mapper))
    return out


def audit_launch_flags(target: Path, files: List[Path], mapper: ComplianceMapper) -> List[Finding]:
    hits: Dict[str, List[str]] = {}
    for p in files:
        if p.stat().st_size > 8 * 1024 * 1024:
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        text = raw.decode("utf-8", "ignore") + "\n" + raw.decode("utf-16le", "ignore")
        low = text.lower()
        for flag in DANGEROUS_FLAGS:
            if flag in low and (p.suffix.lower() in (".json", ".txt", ".cfg", ".ini", ".bat", ".cmd", ".ps1", ".lnk", ".xml", ".plist", ".desktop", ".sh", ".config") or "launch" in p.name.lower()):
                hits.setdefault(flag, []).append(p.name)
    if not hits:
        return []
    worst = max((DANGEROUS_FLAGS[f][0] for f in hits), key=lambda s: ["info", "low", "medium", "high", "critical"].index(s.value.lower()))
    return [_mk("TCP-BRW-002", "Dangerous Chromium Command-Line Flags Configured", FindingStatus.FAIL, worst, Confidence.MEDIUM, str(target),
                "Launch configuration enables: " + ", ".join(sorted(hits)),
                {"flags": {f: {"files": sorted(set(v))[:8], "impact": DANGEROUS_FLAGS[f][1]} for f, v in hits.items()}}, mapper,
                "Remove these flags from shipped launchers/configs; use --remote-debugging-pipe only in test builds.",
                PlaybookRef("netstat / curl / Burp", "Confirm the debug port is reachable", ["netstat -ano | findstr 9222", "curl http://127.0.0.1:9222/json (lists tabs and websocket URLs)", "Attempt cross-origin connection from a web page if --remote-allow-origins=*"]))]


def audit_extensions(files: List[Path], mapper: ComplianceMapper) -> List[Finding]:
    out: List[Finding] = []
    for p in files:
        if p.name.lower() != "manifest.json":
            continue
        parts = [x.lower() for x in p.parts]
        in_ext = "extensions" in parts
        try:
            m = json.loads(p.read_text(encoding="utf-8-sig", errors="ignore"))
        except (OSError, ValueError):
            continue
        if not isinstance(m, dict) or "manifest_version" not in m:
            continue
        perms = [x for x in (m.get("permissions") or []) + (m.get("host_permissions") or []) if isinstance(x, str)]
        bad = sorted({x for x in perms if x in DANGEROUS_PERMS})
        csp = json.dumps(m.get("content_security_policy", ""))
        ext_conn = (m.get("externally_connectable") or {}).get("matches", [])
        issues = []
        if bad:
            issues.append("powerful permissions: " + ", ".join(bad))
        if "unsafe-eval" in csp or "unsafe-inline" in csp:
            issues.append("CSP allows unsafe-eval/unsafe-inline")
        if any(isinstance(x, str) and (x in ("*://*/*", "<all_urls>") or x.startswith("*://*.")) for x in ext_conn):
            issues.append("externally_connectable accepts any website")
        if not issues:
            continue
        sev = max([DANGEROUS_PERMS[b] for b in bad] + [Severity.MEDIUM if len(issues) > 1 or "CSP" in " ".join(issues) else Severity.LOW],
                  key=lambda s: ["info", "low", "medium", "high", "critical"].index(s.value.lower()))
        out.append(_mk("TCP-BRW-003", f"Over-Privileged Browser Extension: {m.get('name', p.parent.name)}", FindingStatus.FAIL if sev != Severity.LOW else FindingStatus.OBSERVATION,
                       sev, Confidence.MEDIUM, str(p), "; ".join(issues) + ". A compromised or malicious update of this extension inherits these rights.",
                       {"name": m.get("name"), "version": m.get("version"), "permissions": bad, "in_extensions_dir": in_ext}, mapper,
                       "Apply least privilege (activeTab, narrow host_permissions), strict CSP, pin extension updates."))
    for p in files:
        if "nativemessaginghosts" in [x.lower() for x in p.parts] and p.suffix.lower() == ".json":
            try:
                m = json.loads(p.read_text(encoding="utf-8-sig", errors="ignore"))
            except (OSError, ValueError):
                continue
            origins = m.get("allowed_origins", [])
            if not origins or any("*" in str(o) for o in origins) or re.search(r"(?i)\\users\\|appdata|\\temp\\", str(m.get("path", ""))):
                out.append(_mk("TCP-BRW-003", f"Native Messaging Host Weakly Constrained: {m.get('name', p.stem)}", FindingStatus.MANUAL_REQUIRED, Severity.MEDIUM, Confidence.MEDIUM, str(p),
                               "Host has wildcard/empty allowed_origins or points to a user-writable path: a rogue extension/web content can reach a local executable.",
                               {"path": m.get("path"), "allowed_origins": origins}, mapper, "Restrict allowed_origins to exact extension IDs; install host binary in an admin-only directory.",
                               PlaybookRef("Chrome + test extension", "Verify who may invoke the host", ["Install a throw-away extension with nativeMessaging", "Attempt connectNative() with the host name", "Check ACL of the host binary"])))
    return out


def audit_ai_artifacts(files: List[Path], mapper: ComplianceMapper) -> List[Finding]:
    out: List[Finding] = []
    stores: List[Dict[str, Any]] = []
    for p in files:
        if "extensions" in [x.lower() for x in p.parts] or p.suffix.lower() not in (".json", ".db", ".sqlite", ".sqlite3", ".jsonl", ".txt", ".ldb", ".log"):
            continue
        if MCP_CONFIG_NAME.match(p.name):
            try:
                cfg = json.loads(p.read_text(encoding="utf-8-sig", errors="ignore"))
            except (OSError, ValueError):
                continue
            servers = cfg.get("mcpServers") or cfg.get("mcp_servers") or cfg.get("servers") or {}
            leaky = []
            for sname, spec in (servers.items() if isinstance(servers, dict) else []):
                env = (spec or {}).get("env") or {}
                leaky += [f"{sname}:{k}" for k, v in env.items() if SECRET_ENV.search(k) and isinstance(v, str) and len(v) >= 8 and not v.startswith("${")]
            if leaky or servers:
                out.append(_mk("TCP-BRW-004", "AI Agent / MCP Server Configuration" + (" With Plaintext Secrets" if leaky else ""),
                               FindingStatus.FAIL if leaky else FindingStatus.OBSERVATION, Severity.HIGH if leaky else Severity.LOW, Confidence.HIGH, str(p),
                               f"{len(servers)} MCP/agent server(s) defined" + (f"; {len(leaky)} env secret(s) stored in plaintext (names only shown)" if leaky else "") + ". MCP servers run local commands with the user's rights: a writable config is a code-execution and prompt-injection pivot.",
                               {"servers": sorted(servers)[:20] if isinstance(servers, dict) else [], "plaintext_secret_env": leaky[:20]}, mapper,
                               "Reference secrets from the OS keychain; make the config admin-writable; allow-list MCP commands.",
                               PlaybookRef("Process Monitor / manual", "Check config tamper path", ["Check ACL of the config file", "Modify command to a benign marker binary and restart (authorised lab)", "Confirm whether the browser re-validates or signs the config"])))
        elif AI_ARTIFACT_NAME.search(p.name) or AI_ARTIFACT_NAME.search(p.parent.name):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            plaintext = _is_sqlite(p) or p.suffix.lower() in (".json", ".jsonl", ".txt")
            if plaintext and size > 0:
                stores.append({"file": str(p.name), "bytes": size, "format": "sqlite" if _is_sqlite(p) else "text/json"})
    if stores:
        out.append(_mk("TCP-BRW-004", "AI Conversation / Memory / Agent History Stored Unencrypted on Disk", FindingStatus.FAIL, Severity.MEDIUM, Confidence.MEDIUM,
                       str(files[0].parent if files else ""), f"{len(stores)} AI-related store(s) are plaintext SQLite/JSON. Prompts, page content and agent memory (often personal or corporate data) are readable by any local process and included in backups (DPDP/GDPR exposure).",
                       {"stores": stores[:30]}, mapper, "Encrypt at rest with OS-backed keys, minimise retention, exclude from sync/backups, and provide user-visible deletion.",
                       PlaybookRef("DB Browser for SQLite / manual", "Assess sensitivity of stored AI data", ["Open each store read-only", "Look for page contents, tokens, PII, credentials in prompts", "Check retention and logout wipe behaviour"])))
    return out


def audit_chromium_version(target: Path, files: List[Path], mapper: ComplianceMapper) -> List[Finding]:
    versions = sorted({p.name for p in (Path(r) / d for r, ds, _ in os.walk(target) for d in ds) if CHROMIUM_VER_DIR.match(p.name)}) if target.is_dir() else []
    comps = sorted({p.name for p in files if p.name.lower() in ("chrome.dll", "libcef.dll", "chrome_elf.dll", "msedge.dll", "electron.exe", "libegl.dll", "chrome_100_percent.pak", "resources.pak", "v8_context_snapshot.bin")})
    if not versions and not comps:
        return []
    return [_mk("TCP-BRW-005", "Embedded Chromium / CEF / Electron Runtime Detected (Verify Patch Level)", FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, str(target),
                f"Chromium-family components found{' (version dir: ' + ', '.join(versions) + ')' if versions else ''}. Embedded browsers inherit every Chromium CVE until the vendor ships an update: compare against the current stable release and the vendor's update cadence.",
                {"version_dirs": versions, "components": comps}, mapper, "Ship Chromium security updates within days; auto-update with signature verification.",
                PlaybookRef("chrome://version / vendor notes", "Confirm runtime version and update path", ["Launch with --version or open about:version", "Compare against current stable Chromium", "Check the updater verifies signatures (updater integrity test)"]))]


def scan_browser_artifacts(target: Path, mapper: ComplianceMapper, ctx: Any = None) -> List[Finding]:
    files = [r.path for r in ctx.files] if ctx is not None else list(_walk(target))
    out: List[Finding] = []
    for fn in (lambda: audit_credential_stores(files, mapper), lambda: audit_launch_flags(target, files, mapper), lambda: audit_extensions(files, mapper),
               lambda: audit_ai_artifacts(files, mapper), lambda: audit_chromium_version(target, files, mapper)):
        try:
            out.extend(fn())
        except Exception as exc:  # one bad artifact must not hide the others
            out.append(_mk("TCP-BRW-001", "Browser Artifact Audit Error", FindingStatus.TOOLING_GAP, Severity.INFO, Confidence.LOW, str(target), str(exc), {"error": str(exc)}, mapper))
    return out
