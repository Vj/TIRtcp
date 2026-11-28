"""TCP-INTEL-010..015: string / IOC intelligence for any file (native, managed #US, config, resources).

Turns raw strings into pen-test leads: hard-coded endpoints (cleartext vs TLS), third-party data egress,
cloud/API secrets, hard-coded crypto material, embedded SQL / OS commands / registry+path persistence, and
debug/bypass switches. Everything secret-like is redacted before it reaches a report."""
from __future__ import annotations

import ipaddress
import math
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import Confidence, Finding, FindingStatus, PlaybookRef, Severity
from analyzer.modules.static_audit.secrets_db_audit import _is_placeholder, _redact

CAT = "String & Endpoint Intelligence"
MAX_BYTES = 80 * 1024 * 1024
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".wav",
             ".avi", ".pdb", ".nupkg", ".zip", ".cab", ".msi"}
MAX_SAMPLES = 25
TEXT_SUFFIXES = {".json", ".config", ".xml", ".txt", ".ini", ".yaml", ".yml", ".js", ".html", ".htm", ".cfg", ".conf", ".properties", ".toml", ".md", ".log", ".csv", ".manifest"}

URL_RE = re.compile(r"\b(?:https?|ftp|sftp|wss?|ldaps?|smtps?|redis|rediss|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|amqps?|mqtts?|tcp)://[^\s\"'<>\\\x00-\x1f\x7f]{3,200}", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
NOISE_HOST_SUFFIX = (
    "w3.org", "microsoft.com", "windowsupdate.com", "msftncsi.com", "digicert.com", "verisign.com", "symcdn.com", "symauth.com",
    "sectigo.com", "usertrust.com", "globalsign.com", "entrust.net", "letsencrypt.org", "godaddy.com", "comodoca.com",
    "xmlsoap.org", "purl.org", "openxmlformats.org", "apache.org", "mozilla.org", "gnu.org", "example.com", "example.org",
    "schemas.openxmlformats.org", "aka.ms", "nuget.org", "dotnetfoundation.org", "xmlpull.org", "oasis-open.org",
    "ocsp.msocsp.com", "localhost", "iana.org", "ietf.org", "openssl.org", "sun.com", "oracle.com", "java.com",
    "ecma-international.org", "wikipedia.org", "creativecommons.org", "unicode.org", "sqlite.org", "python.org",
)
TELEMETRY = {
    "sentry.io": "Sentry crash reporting", "appcenter.ms": "Microsoft App Center", "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager", "mixpanel.com": "Mixpanel", "segment.io": "Segment", "segment.com": "Segment",
    "amplitude.com": "Amplitude", "bugsnag.com": "Bugsnag", "rollbar.com": "Rollbar", "newrelic.com": "New Relic",
    "datadoghq.com": "Datadog", "firebaseio.com": "Firebase", "crashlytics.com": "Crashlytics", "hotjar.com": "Hotjar",
    "dc.services.visualstudio.com": "Azure Application Insights", "applicationinsights.azure.com": "Azure Application Insights",
    "raygun.io": "Raygun", "loggly.com": "Loggly", "intercom.io": "Intercom", "posthog.com": "PostHog", "api.openai.com": "OpenAI API",
    "telemetry": "generic telemetry host", "stats.g.doubleclick.net": "DoubleClick",
}
SECRET_PATTERNS: List[Tuple[str, re.Pattern, Severity]] = [
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("LLM Provider API Key (OpenAI/Anthropic-style)", re.compile(r"\bsk-(?:proj-|ant-(?:api\d{2}-)?|svcacct-)?[A-Za-z0-9_\-]{32,}\b"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.MEDIUM),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("Slack Token / Webhook", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}|hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), Severity.HIGH),
    ("Stripe Live Secret Key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"), Severity.CRITICAL),
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), Severity.HIGH),
    ("Azure Storage Account Key", re.compile(r"AccountKey=[A-Za-z0-9+/]{60,}={0,2}"), Severity.CRITICAL),
    ("Azure SAS Token", re.compile(r"[?&]sig=[A-Za-z0-9%]{30,}"), Severity.HIGH),
    ("Credentials Embedded in URL", re.compile(r"\b[a-z][a-z0-9+.\-]{2,10}://[^/\s:@\"']{2,40}:([^/\s@\"']{3,60})@[^/\s\"']{3,80}", re.I), Severity.HIGH),
    ("Private Key Material", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), Severity.MEDIUM),
]
HARDCODED_KEY_RE = re.compile(
    r"(?i)\b(?:aes|des|crypt\w*|enc(?:ryption)?|secret|master|signing|hmac)[_\- ]?(?:key|iv|salt|passphrase)\w*\s*[=:]\s*[\"']?"
    r"([A-Za-z0-9+/=]{16,64}|[0-9a-fA-F]{32,64})[\"']?")
GENERIC_SECRET_RE = re.compile(r"(?i)\b(?:api[_\-]?key|client[_\-]?secret|auth[_\-]?token|access[_\-]?token|passw(?:or)?d|pwd)\s*[=:]\s*[\"']?([^\s\"';,<>]{8,80})")
CMD_RE = re.compile(r"(?i)\b(?:cmd(?:\.exe)?\s+/[ck]\s|powershell(?:\.exe)?\s+-(?:enc\w*|e\s|nop|w\s|command|ep\s)|wmic\s+\w+|reg(?:\.exe)?\s+(?:add|delete|save)\s|schtasks(?:\.exe)?\s+/|"
                    r"sc(?:\.exe)?\s+(?:create|config)\s|net\s+(?:user|localgroup)\s|certutil(?:\.exe)?\s+-|bitsadmin|mshta(?:\.exe)?\s|rundll32(?:\.exe)?\s+\S+,|icacls\s+\S+\s+/grant|netsh\s+\w+)[^\x00\r\n]{0,80}")
REG_RE = re.compile(r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HK(?:LM|CU|CR|U))\\[^\x00\"\r\n]{4,140}")
PATH_RE = re.compile(r"(?i)(?:%(?:temp|tmp|appdata|localappdata|programdata|public|userprofile)%\\[^\x00\"\r\n]{2,100}|\b[A-Z]:\\(?:Users\\(?!Default)[^\\\x00\"\r\n]{1,30}\\[^\x00\"\r\n]{2,100}|ProgramData\\[^\x00\"\r\n]{2,100}|Temp\\[^\x00\"\r\n]{2,100}|Windows\\Temp\\[^\x00\"\r\n]{2,80}))")
SQL_RE = re.compile(r"(?i)\b(?:select\s+[\w*,.\[\]\s]{1,80}\s+from\s+[\[\w.\]]{2,60}|insert\s+into\s+[\[\w.\]]{2,60}|update\s+[\[\w.\]]{2,60}\s+set\s|delete\s+from\s+[\[\w.\]]{2,60}|exec(?:ute)?\s+(?:sp|xp)_\w+)[^\x00\r\n]{0,100}")
SQL_CONCAT_HINT = re.compile(r"(?:=\s*'|\+\s*$|'\s*\+|\{\d\}|%s|\$\{|'\"|\"\s*\+)", re.I)
DEBUG_RE = re.compile(r"(?i)\b(?:backdoor|debug[_ ]?mode|enable[_ ]?debug|test[_ ]?user|admin\s*[:/]\s*admin|master[_ ]?password|god[_ ]?mode|bypass[_ ]?(?:auth|license|login)|"
                      r"--?(?:dev|debug|test)[_-]?mode|disable[_ ]?ssl[_ ]?verif\w*|ignore[_ ]?cert\w*|allow[_ ]?invalid[_ ]?cert\w*|trust[_ ]?all[_ ]?cert\w*|accept[_ ]?all[_ ]?cert\w*)\b")
WEAK_CRYPTO_RE = re.compile(r"(?i)\b(?:AES|DES|DESede|Blowfish)/ECB/\w+|CipherMode\.ECB|\bRC4\b|\bTripleDESCryptoServiceProvider\b|\bDESCryptoServiceProvider\b|\bRC2CryptoServiceProvider\b|\bMD5CryptoServiceProvider\b|\bSHA1CryptoServiceProvider\b")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((s.count(c) / n) * math.log2(s.count(c) / n) for c in set(s))


def _strings(data: bytes, min_len: int = 6) -> str:
    parts = [m.decode("ascii", "ignore") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    parts += [m.decode("utf-16le", "ignore") for m in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)]
    return "\n".join(parts)


def _safe_url_sample(u: Any, raw: str, keep_path: bool = False) -> str:
    """scheme://host[:port]/first-path-segment - enough to locate the endpoint, too little to leak tokens, query secrets,
    credentials, or neighbouring bytes of a binary file that the greedy URL regex may have absorbed."""
    host = u.hostname or ""
    port = f":{u.port}" if u.port else ""
    if not keep_path:       # binary containers (SQLite, PE, DAT) glue neighbouring record bytes onto the URL: keep host only
        return f"{u.scheme}://{host}{port}"
    first = (u.path.lstrip("/").split("/")[0] if u.path else "")[:32]
    more = "/..." if (u.path.count("/") > 1 or u.query or len(u.path.lstrip("/").split("/")[0]) > 32) else ""
    return f"{u.scheme}://{host}{port}/{first}{more}" if first or more else f"{u.scheme}://{host}{port}"


def _is_noise_host(host: str) -> bool:
    h = host.lower().strip(".")
    return any(h == s or h.endswith("." + s) for s in NOISE_HOST_SUFFIX)


def _public_or_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved:
        return False
    first = int(ip.split(".")[0])
    return a.is_private or first >= 24  # dotted-quads with tiny first octet are almost always version numbers


class _Collector:
    def __init__(self) -> None:
        self.hits: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"samples": [], "count": 0, "files": set()})

    def add(self, key: str, file: str, value: str, **meta: Any) -> None:
        h = self.hits[key]; h["count"] += 1; h["files"].add(file); h.update(meta)
        if len(h["samples"]) < MAX_SAMPLES and value not in h["samples"]:
            h["samples"].append(value)


def scan_text_intel(text: str, file_label: str, col: _Collector, endpoints: Set[Tuple[str, int]]) -> None:
    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,);]'\"")
        try:
            u = urlsplit(raw)
        except ValueError:
            continue
        host = (u.hostname or "").lower()
        if not host or _is_noise_host(host) or "{" in host or "%" in host or "." not in host and not _public_or_private_ip(host):
            continue
        scheme = u.scheme.lower()
        safe = _safe_url_sample(u, raw, keep_path=Path(file_label).suffix.lower() in TEXT_SUFFIXES)                      # no userinfo, no query values, bounded path (adjacent binary bytes can glue onto URLs)
        port = u.port or {"https": 443, "wss": 443, "http": 80, "ws": 80, "ldaps": 636, "ldap": 389, "ftp": 21, "smtps": 465, "rediss": 6380}.get(scheme, 0)
        if scheme in ("http", "ws", "ftp", "ldap", "redis", "mqtt", "amqp") and not (host.endswith(".local") and False):
            col.add("cleartext_endpoints", file_label, safe)
        else:
            col.add("tls_endpoints", file_label, safe)
        if scheme in ("https", "wss", "ldaps", "smtps", "rediss", "mqtts", "amqps", "tcp") and port:
            endpoints.add((host, port))
        if scheme in ("postgres", "postgresql", "mysql", "mongodb", "mongodb+srv"):
            col.add("db_endpoints", file_label, safe)
        for dom, label in TELEMETRY.items():
            if host == dom or host.endswith("." + dom) or (dom == "telemetry" and "telemetry" in host):
                col.add("telemetry", file_label, f"{label}: {host}")
    for ip in IPV4_RE.findall(text):
        if _public_or_private_ip(ip):
            col.add("ip_literals", file_label, ip)
    for label, rx, sev in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if rx.groups else m.group(0)
            if _is_placeholder(val):
                continue
            col.add(f"secret::{label}", file_label, _redact(val), severity=sev)
    for m in HARDCODED_KEY_RE.finditer(text):
        val = m.group(1)
        if not _is_placeholder(val) and _entropy(val) >= 3.0:
            col.add("hardcoded_crypto_material", file_label, _redact(val))
    for m in GENERIC_SECRET_RE.finditer(text):
        val = m.group(1)
        if (not _is_placeholder(val) and _entropy(val) >= 3.3 and re.search(r"\d", val) and re.search(r"[A-Za-z]", val)
                and not val.lower().startswith(("system.", "microsoft.", "http"))):
            col.add("generic_secret_assignments", file_label, _redact(val))
    for m in CMD_RE.finditer(text):
        col.add("os_commands", file_label, m.group(0)[:120])
    for m in REG_RE.finditer(text):
        col.add("registry_keys", file_label, m.group(0)[:140])
    for m in PATH_RE.finditer(text):
        col.add("hardcoded_paths", file_label, m.group(0)[:140])
    for m in SQL_RE.finditer(text):
        s = m.group(0)
        col.add("sql_statements", file_label, s[:140])
        if SQL_CONCAT_HINT.search(s):
            col.add("sql_concat_hint", file_label, s[:140])
    for m in DEBUG_RE.finditer(text):
        col.add("debug_switches", file_label, m.group(0)[:100])
    for m in WEAK_CRYPTO_RE.finditer(text):
        col.add("weak_crypto_strings", file_label, m.group(0))


def _mk(title: str, status: FindingStatus, sev: Severity, conf: Confidence, asset: str, summary: str, evidence: Dict[str, Any],
        mapper: ComplianceMapper, cid: str, remediation: str = "", playbook: Optional[PlaybookRef] = None) -> Finding:
    return Finding(check_id=cid, title=title, category=CAT, status=status, severity=sev, confidence=conf, affected_asset=asset,
                   summary=summary, evidence=evidence, remediation=remediation, compliance_support=mapper.resolve(cid), manual_playbook=playbook)


def _ev(h: Dict[str, Any]) -> Dict[str, Any]:
    return {"total_hits": h["count"], "files": sorted(h["files"])[:15], "samples": h["samples"]}


def build_findings(col: _Collector, target: Path, mapper: ComplianceMapper) -> List[Finding]:
    H, asset, out = col.hits, str(target), []
    if "cleartext_endpoints" in H:
        h = H["cleartext_endpoints"]
        out.append(_mk("Hard-Coded Cleartext Endpoints (http/ws/ftp/ldap)", FindingStatus.FAIL, Severity.MEDIUM, Confidence.MEDIUM, asset,
                       f"{h['count']} cleartext URL(s) are embedded in the target. If the client actually uses them, credentials/data cross the network unencrypted and can be modified in transit.",
                       _ev(h), mapper, "TCP-INTEL-010", "Use TLS 1.2+ for every endpoint and remove plaintext fallbacks.",
                       PlaybookRef("Wireshark / mitmproxy", "Confirm the endpoint is really contacted in plaintext",
                                   ["Run the client with capture enabled (pktmon/Wireshark)", "Exercise login, sync and update flows", "Feed the PCAP to TIRtcp --pcap"])))
    if "tls_endpoints" in H or "ip_literals" in H or "db_endpoints" in H:
        ev = {k: _ev(H[k]) for k in ("tls_endpoints", "ip_literals", "db_endpoints") if k in H}
        out.append(_mk("Hard-Coded Network Endpoints Inventory (Back-End Attack Surface)", FindingStatus.OBSERVATION, Severity.INFO, Confidence.HIGH, asset,
                       "Hostnames/IPs embedded in the client define the server-side attack surface and the scope for TLS, authN/Z and API testing. Only test hosts covered by your authorization.",
                       ev, mapper, "TCP-INTEL-010",
                       playbook=PlaybookRef("TIRtcp + Burp/mitmproxy", "Turn endpoints into test targets",
                                            ["Add in-scope hosts to --scope-file", "Run TIRtcp TLS inspection (scope-gated)", "Proxy the client and test the API for IDOR/authZ gaps"])))
    if "db_endpoints" in H:
        out.append(_mk("Direct Database / Message-Broker Endpoint Referenced by Client (Two-Tier Architecture Lead)", FindingStatus.MANUAL_REQUIRED, Severity.HIGH, Confidence.MEDIUM, asset,
                       "A DB/broker URL is embedded: thick clients that talk to the database directly expose it to any user holding the client's credentials.",
                       _ev(H["db_endpoints"]), mapper, "TCP-INTEL-011", "Put an authenticated API tier between client and database; never ship DB credentials.",
                       PlaybookRef("DBeaver / nmap / Wireshark", "Test direct DB reachability and privileges",
                                   ["Check network reachability from a standard user workstation", "Test extracted creds only if authorized", "Check row-level security and excessive privileges"])))
    if "telemetry" in H:
        out.append(_mk("Third-Party Telemetry / SaaS Data Egress Endpoints", FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, asset,
                       "The client references third-party analytics/crash/AI services. Verify what personal data leaves the device (DPDP/GDPR minimisation, consent, cross-border transfer).",
                       _ev(H["telemetry"]), mapper, "TCP-INTEL-010"))
    for key in [k for k in H if k.startswith("secret::")]:
        h = H[key]; label = key.split("::", 1)[1]
        out.append(_mk(f"Hard-Coded Secret: {label}", FindingStatus.FAIL, h.get("severity", Severity.HIGH), Confidence.MEDIUM, asset,
                       f"{h['count']} match(es) of '{label}' (values redacted). Secrets shipped in a client are recoverable by every user.",
                       _ev(h), mapper, "TCP-INTEL-012", "Remove the secret, rotate it, and fetch scoped short-lived tokens from a backend after user authentication."))
    if "hardcoded_crypto_material" in H:
        out.append(_mk("Hard-Coded Cryptographic Key / IV / Salt", FindingStatus.FAIL, Severity.HIGH, Confidence.MEDIUM, asset,
                       "Key-like material is assigned to key/IV/salt identifiers. A key embedded in the client protects nothing from a user of that client.",
                       _ev(H["hardcoded_crypto_material"]), mapper, "TCP-INTEL-012", "Derive keys per user/device (DPAPI, KMS, hardware-backed store) rather than shipping them."))
    if "generic_secret_assignments" in H:
        out.append(_mk("Possible Hard-Coded Credential Assignments (Review)", FindingStatus.MANUAL_REQUIRED, Severity.MEDIUM, Confidence.LOW, asset,
                       "High-entropy values assigned to password/token/api-key style names (redacted). Needs analyst review to rule out defaults and test fixtures.",
                       _ev(H["generic_secret_assignments"]), mapper, "TCP-INTEL-012"))
    if "weak_crypto_strings" in H:
        out.append(_mk("Weak Cryptographic Algorithm / Mode References", FindingStatus.FAIL, Severity.MEDIUM, Confidence.LOW, asset,
                       "Strings reference ECB mode, DES/3DES/RC2/RC4, or MD5/SHA-1 provider classes. Confirm they protect security-relevant data and not just legacy interop.",
                       _ev(H["weak_crypto_strings"]), mapper, "TCP-INTEL-013", "Use AES-GCM/ChaCha20-Poly1305 and SHA-256+; PBKDF2/Argon2 for passwords."))
    if "sql_statements" in H:
        concat = "sql_concat_hint" in H
        out.append(_mk("Embedded SQL Statements" + (" With String-Building Indicators (SQL Injection Lead)" if concat else ""),
                       FindingStatus.MANUAL_REQUIRED if concat else FindingStatus.OBSERVATION, Severity.MEDIUM if concat else Severity.INFO, Confidence.LOW, asset,
                       "Client builds SQL itself. If it connects to the database directly, every query is attacker-controllable by a local user; if via API, parameter handling still needs review.",
                       {"statements": _ev(H["sql_statements"]), "concat_hints": _ev(H["sql_concat_hint"]) if concat else None}, mapper, "TCP-INTEL-014",
                       "Use parameterised queries / stored procedures server-side; do not expose SQL construction to the client.",
                       PlaybookRef("dnSpy / Burp", "Validate injection reachability", ["Locate the string in code", "Trace user-controlled inputs into it", "Replay via proxy with injection payloads"])))
    if "os_commands" in H or "registry_keys" in H or "hardcoded_paths" in H:
        out.append(_mk("Embedded OS Commands, Registry Keys and Writable-Path Usage (Host Interaction Leads)", FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, asset,
                       "Hard-coded commands/registry/profile paths show where the client stores state and what it executes. Check ACLs, command injection and DLL/file planting.",
                       {k: _ev(H[k]) for k in ("os_commands", "registry_keys", "hardcoded_paths") if k in H}, mapper, "TCP-INTEL-014",
                       playbook=PlaybookRef("Procmon / Regshot / accesschk", "Verify storage and execution behaviour",
                                            ["Procmon: filter by process, review writes to listed paths/keys", "accesschk -wus on each path; icacls on keys", "Look for secrets/tokens written in cleartext"])))
    if "debug_switches" in H:
        out.append(_mk("Debug / Test / Security-Bypass Switches in Strings", FindingStatus.MANUAL_REQUIRED, Severity.MEDIUM, Confidence.LOW, asset,
                       "Strings suggest debug modes, test accounts or certificate-validation bypass flags that may be enabled by config, CLI or registry.",
                       _ev(H["debug_switches"]), mapper, "TCP-INTEL-015", "Strip debug/bypass paths from release builds or gate them behind signed server-side flags."))
    return out


def scan_string_intel(target: Path, mapper: ComplianceMapper, ctx: Any = None,
                      endpoints_out: Optional[Set[Tuple[str, int]]] = None) -> List[Finding]:
    col, endpoints = _Collector(), set()
    scanned = skipped = 0
    paths: Iterable[Path] = [r.path for r in ctx.files] if ctx is not None else ([target] if target.is_file() else [Path(r) / f for r, _, fs in os.walk(target) for f in fs])
    for p in paths:
        if p.suffix.lower() in SKIP_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_BYTES or p.stat().st_size == 0:
                skipped += 1; continue
            data = p.read_bytes()
        except OSError:
            skipped += 1; continue
        scanned += 1
        scan_text_intel(_strings(data), p.name, col, endpoints)
    if endpoints_out is not None:
        endpoints_out.update(endpoints)
    findings = build_findings(col, target, mapper)
    if skipped:
        findings.append(_mk("String Intelligence Coverage Incomplete", FindingStatus.NOT_ASSESSED, Severity.INFO, Confidence.HIGH, str(target),
                            f"{skipped} file(s) skipped (empty, unreadable or > {MAX_BYTES // (1024 * 1024)} MB).", {"scanned": scanned, "skipped": skipped}, mapper, "TCP-INTEL-010"))
    return findings
