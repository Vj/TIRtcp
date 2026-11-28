"""TCP-INTEL-020/021: .NET metadata intelligence (dnfile): profile, third-party refs, P/Invoke, resources,
obfuscation, and a categorised sensitive-API inventory that becomes concrete test leads."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import Confidence, Finding, FindingStatus, PlaybookRef, Severity

try:
    import dnfile  # type: ignore
    HAS_DNFILE = True
except ImportError:  # pragma: no cover
    HAS_DNFILE = False

CAT = ".NET Intelligence"
FRAMEWORK_PREFIXES = ("System", "Microsoft", "mscorlib", "netstandard", "WindowsBase", "PresentationCore", "PresentationFramework",
                      "Accessibility", "UIAutomation", "ReachFramework")
OBFUSCATOR_MARKERS = {
    "confuserex": "ConfuserEx", "confusedbyattribute": "ConfuserEx", "dotfuscator": "Dotfuscator", "obfuscatedbyagiledotnet": "Agile.NET",
    "smartassembly": "SmartAssembly", "poweredbyattribute": "SmartAssembly", "eziriz": ".NET Reactor", "reactor": ".NET Reactor",
    "babelobfuscator": "Babel", "crypto obfuscator": "Crypto Obfuscator", "cryptoobfuscator": "Crypto Obfuscator", "xenocode": "Xenocode",
}

# rule: (risk_key, type-name-prefix/exact, member or None)
API_RULES: List[Tuple[str, str, Optional[str]]] = [
    *[("weak_crypto", f"System.Security.Cryptography.{t}", None) for t in
      ("MD5", "MD5CryptoServiceProvider", "SHA1", "SHA1CryptoServiceProvider", "SHA1Managed", "DES", "DESCryptoServiceProvider", "TripleDES",
       "TripleDESCryptoServiceProvider", "RC2", "RC2CryptoServiceProvider", "RijndaelManaged", "HMACMD5", "HMACSHA1", "PasswordDeriveBytes")],
    ("insecure_rng", "System.Random", None),
    ("tls_validation_bypass", "System.Net.Http.HttpClientHandler", "set_ServerCertificateCustomValidationCallback"),
    ("tls_validation_bypass", "System.Net.Http.HttpClientHandler", "get_DangerousAcceptAnyServerCertificateValidator"),
    ("tls_validation_bypass", "System.Net.ServicePointManager", "set_ServerCertificateValidationCallback"),
    ("tls_validation_bypass", "System.Net.Security.SslStream", ".ctor"),
    ("legacy_remoting_wcf", "System.Runtime.Remoting", None),
    ("legacy_remoting_wcf", "System.ServiceModel", None),
    ("direct_db_client", "System.Data.SqlClient", None), ("direct_db_client", "Microsoft.Data.SqlClient", None),
    ("direct_db_client", "Npgsql", None), ("direct_db_client", "MySql.Data", None), ("direct_db_client", "MySqlConnector", None),
    ("direct_db_client", "Oracle.ManagedDataAccess", None), ("direct_db_client", "System.Data.OleDb", None),
    ("direct_db_client", "System.Data.Odbc", None), ("direct_db_client", "System.Data.SQLite", None), ("direct_db_client", "Microsoft.Data.Sqlite", None),
    ("custom_network", "System.Net.Sockets.TcpClient", None), ("custom_network", "System.Net.Sockets.Socket", None),
    ("custom_network", "System.Net.Sockets.UdpClient", None), ("custom_network", "System.Net.WebSockets.ClientWebSocket", None),
    ("custom_network", "System.Net.FtpWebRequest", None), ("custom_network", "System.Net.Mail.SmtpClient", None),
    ("http_client", "System.Net.WebClient", None), ("http_client", "System.Net.HttpWebRequest", None), ("http_client", "System.Net.Http.HttpClient", None),
    ("js_bridge", "CefSharp", None), ("js_bridge", "Microsoft.Web.WebView2", None), ("js_bridge", "System.Windows.Forms.WebBrowser", None),
    ("dynamic_code", "System.Reflection.Assembly", "Load"), ("dynamic_code", "System.Reflection.Assembly", "LoadFrom"),
    ("dynamic_code", "System.Reflection.Assembly", "LoadFile"), ("dynamic_code", "System.Reflection.Emit", None),
    ("dynamic_code", "System.CodeDom.Compiler", None), ("dynamic_code", "Microsoft.CodeAnalysis.CSharp.Scripting", None),
    ("dynamic_code", "System.Activator", "CreateInstance"),
    ("process_exec", "System.Diagnostics.Process", "Start"), ("wmi", "System.Management", None),
    ("registry", "Microsoft.Win32.Registry", None), ("registry", "Microsoft.Win32.RegistryKey", None),
    ("dpapi", "System.Security.Cryptography.ProtectedData", None), ("dpapi", "System.Security.Cryptography.ProtectedMemory", None),
    ("clipboard_screen", "System.Windows.Forms.Clipboard", None), ("clipboard_screen", "System.Windows.Clipboard", None),
    ("clipboard_screen", "System.Drawing.Graphics", "CopyFromScreen"),
    ("anti_debug", "System.Diagnostics.Debugger", None),
    ("xml_legacy", "System.Xml.XmlDocument", None), ("xml_legacy", "System.Xml.XmlTextReader", None),
    ("temp_files", "System.IO.Path", "GetTempFileName"), ("temp_files", "System.IO.Path", "GetTempPath"),
    ("unsafe_deser_misc", "System.Web.Script.Serialization.JavaScriptSerializer", None),
    ("unsafe_deser_misc", "System.Web.Script.Serialization.SimpleTypeResolver", None),
]
JS_BRIDGE_MEMBERS = {"RegisterJsObject", "RegisterAsyncJsObject", "AddHostObjectToScript", "AddWebAllowedObject", "ObjectForScripting", "set_ObjectForScripting"}

RISK_META: Dict[str, Tuple[FindingStatus, Severity, Confidence, str, str, str]] = {
    "weak_crypto": (FindingStatus.FAIL, Severity.MEDIUM, Confidence.MEDIUM, "Weak Cryptographic Primitives Referenced (.NET)",
                    "Assembly references MD5/SHA-1/DES/3DES/RC2/Rijndael(Managed)/PasswordDeriveBytes. Confirm usage protects security-relevant data.",
                    "Use AES-GCM, SHA-256+, Rfc2898DeriveBytes with >=600k iterations (or Argon2)."),
    "insecure_rng": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.LOW, "System.Random Referenced (Check It Is Not Used for Tokens/Keys)",
                     "System.Random is predictable; verify it never generates passwords, tokens, IVs or keys.", "Use RandomNumberGenerator for security values."),
    "tls_validation_bypass": (FindingStatus.MANUAL_REQUIRED, Severity.HIGH, Confidence.MEDIUM, "Custom TLS Certificate Validation Hooks Referenced",
                              "Custom validation callbacks are frequently implemented as 'return true'. Decompile the callback and confirm it validates chain, host and (if intended) pins the key.",
                              "Remove custom callbacks or implement strict chain + SPKI pinning validation."),
    "legacy_remoting_wcf": (FindingStatus.FAIL, Severity.MEDIUM, Confidence.MEDIUM, "Legacy .NET Remoting / WCF Stack in Use",
                            ".NET Remoting (BinaryFormatter-based) and loosely configured WCF endpoints are classic thick-client RCE/authZ attack surfaces.",
                            "Replace with authenticated gRPC/REST over TLS; never expose Remoting channels."),
    "direct_db_client": (FindingStatus.MANUAL_REQUIRED, Severity.HIGH, Confidence.MEDIUM, "Direct Database Client Library in Client (Two-Tier Architecture)",
                         "The client links a database driver, implying it may connect to the DB directly with embedded or user-entered credentials. Any local user can reuse those credentials outside the app.",
                         "Move data access behind an authenticated API; enforce least-privilege and row-level security."),
    "custom_network": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, "Custom Socket / Protocol Code (Non-HTTP Attack Surface)",
                       "Raw sockets / FTP / SMTP / WebSocket clients indicate bespoke protocols that standard web proxies will not see.",
                       ""),
    "http_client": (FindingStatus.OBSERVATION, Severity.INFO, Confidence.HIGH, "HTTP Client Stack Referenced", "Proxy the client to test the API surface.", ""),
    "js_bridge": (FindingStatus.MANUAL_REQUIRED, Severity.MEDIUM, Confidence.MEDIUM, "Embedded Browser Control With Possible JS-to-.NET Bridge",
                  "Embedded browsers (CefSharp/WebView2/WebBrowser) that expose host objects turn any XSS/remote-content injection into local code execution.",
                  "Disable host-object bridges, restrict navigation to an allow-list, enforce CSP."),
    "dynamic_code": (FindingStatus.MANUAL_REQUIRED, Severity.MEDIUM, Confidence.LOW, "Dynamic Code Loading / Reflection Emit / Runtime Compilation",
                     "Runtime assembly loading or compilation is where plug-in/update/script injection flaws live; verify the origin and integrity of what is loaded.",
                     "Load only signed assemblies from admin-writable locations; validate hashes/signatures."),
    "process_exec": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, "Process.Start Usage", "Check argument/path construction for injection and unquoted paths.", ""),
    "wmi": (FindingStatus.OBSERVATION, Severity.INFO, Confidence.MEDIUM, "WMI (System.Management) Usage", "WMI queries built from user input can be abused; review query construction.", ""),
    "registry": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, "Registry Access From Managed Code", "Diff registry before/after use; check ACLs and secrets stored in HKCU/HKLM.", ""),
    "dpapi": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, "DPAPI (ProtectedData) Usage", "DPAPI data is decryptable by the same user: inspect optionalEntropy and scope; recover blobs with mimikatz/DonPAPI in lab.", ""),
    "clipboard_screen": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, "Clipboard / Screen Capture APIs", "Check whether sensitive values transit the clipboard and are cleared.", ""),
    "anti_debug": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, "Debugger Detection (System.Diagnostics.Debugger)", "Expect tamper checks when attaching dnSpy/x64dbg.", ""),
    "xml_legacy": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.LOW, "Legacy XML Parsers (XXE Lead)", "XmlDocument/XmlTextReader on older frameworks resolve DTDs by default; test XXE on any XML the client parses.", "Set XmlResolver=null and DtdProcessing=Prohibit."),
    "temp_files": (FindingStatus.OBSERVATION, Severity.LOW, Confidence.LOW, "Temp File Usage", "Test predictable names, permissions and TOCTOU races in %TEMP%.", ""),
    "unsafe_deser_misc": (FindingStatus.FAIL, Severity.MEDIUM, Confidence.MEDIUM, "JavaScriptSerializer / SimpleTypeResolver Deserialization", "Type-resolver based deserialization permits gadget instantiation.", "Use System.Text.Json without type resolvers."),
}


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def analyze_dotnet(path: Path) -> Optional[Dict[str, Any]]:
    pe = dnfile.dnPE(str(path))
    try:
        if not getattr(pe, "net", None) or pe.net.mdtables is None:
            return None
        md = pe.net.mdtables
        type_refs: Dict[int, str] = {}
        if md.TypeRef is not None:
            for i, r in enumerate(md.TypeRef.rows, 1):
                type_refs[i] = f"{_s(r.TypeNamespace)}.{_s(r.TypeName)}".lstrip(".")
        member_refs: List[Tuple[str, str]] = []
        if md.MemberRef is not None:
            for r in md.MemberRef.rows:
                parent = ""
                if getattr(r, "Class", None) is not None and r.Class.table is not None and r.Class.table.name == "TypeRef":
                    parent = type_refs.get(r.Class.row_index, "")
                member_refs.append((parent, _s(r.Name)))
        type_defs = [f"{_s(r.TypeNamespace)}.{_s(r.TypeName)}".lstrip(".") for r in (md.TypeDef.rows if md.TypeDef is not None else [])]
        asm_refs = [(_s(r.Name), f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}") for r in (md.AssemblyRef.rows if md.AssemblyRef is not None else [])]
        pinvokes = []
        if md.ImplMap is not None:
            for r in md.ImplMap.rows:
                scope = getattr(getattr(r.ImportScope, "row", None), "Name", None)
                pinvokes.append(f"{_s(scope)}!{_s(r.ImportName)}")
        resources = [_s(r.Name) for r in (md.ManifestResource.rows if md.ManifestResource is not None else [])]
        asm_name = _s(md.Assembly.rows[0].Name) if md.Assembly is not None and md.Assembly.rows else path.stem
        lowered = " ".join(type_defs + resources).lower()
        obf = sorted({label for k, label in OBFUSCATOR_MARKERS.items() if k in lowered})
        weird = sum(1 for t in type_defs if t and any(ord(c) > 0x7e or ord(c) < 0x20 for c in t))
        if len(type_defs) > 30 and weird / max(len(type_defs), 1) > 0.3:
            obf.append("unprintable/renamed identifiers")
        families = {a for a, _ in asm_refs}
        runtime = ".NET Framework" if "mscorlib" in families else (".NET (Core/5+)" if families & {"System.Runtime", "System.Private.CoreLib", "netstandard"} else "unknown")
        return {
            "assembly": asm_name, "runtime_family": runtime, "strong_name_signed": bool(getattr(pe.net.Flags, "CLR_STRONGNAMESIGNED", False)),
            "obfuscators": obf, "assembly_refs": asm_refs, "pinvokes": pinvokes, "resources": resources,
            "type_refs": sorted(set(type_refs.values())), "member_refs": member_refs, "type_def_count": len(type_defs),
            "debuggable": any(t.endswith("DebuggableAttribute") for t in type_refs.values()),
            "wpf": "PresentationFramework" in families, "winforms": "System.Windows.Forms" in families,
        }
    finally:
        pe.close()


def classify_apis(info: Dict[str, Any]) -> Dict[str, List[str]]:
    hits: Dict[str, Set[str]] = {}
    members = info["member_refs"]
    for risk, tprefix, member in API_RULES:
        for t in info["type_refs"]:
            if t == tprefix or t.startswith(tprefix + ".") or (member is None and t.startswith(tprefix) and tprefix.count(".") >= 1 and t[len(tprefix):len(tprefix) + 1] in ("", ".")):
                if member is None:
                    hits.setdefault(risk, set()).add(t)
                elif any(pt == t and mn == member for pt, mn in members):
                    hits.setdefault(risk, set()).add(f"{t}::{member}")
    if any(mn in JS_BRIDGE_MEMBERS for _, mn in members):
        hits.setdefault("js_bridge", set()).update(f"::{mn}" for _, mn in members if mn in JS_BRIDGE_MEMBERS)
    return {k: sorted(v) for k, v in hits.items()}


def dotnet_findings(path: Path, mapper: ComplianceMapper, label: Optional[str] = None) -> List[Finding]:
    info = analyze_dotnet(path)
    if not info:
        return []
    asset = label or str(path)
    third = [f"{n} {v}" for n, v in info["assembly_refs"] if not n.startswith(FRAMEWORK_PREFIXES)]
    embedded = [r for r in info["resources"] if r.lower().endswith((".dll", ".exe", ".zip", ".config", ".json", ".xml", ".pfx", ".pem", ".key", ".db", ".sqlite", ".sql"))]
    out: List[Finding] = []
    out.append(Finding(
        check_id="TCP-INTEL-020", title=".NET Assembly Profile", category=CAT, status=FindingStatus.OBSERVATION, severity=Severity.INFO,
        confidence=Confidence.HIGH, affected_asset=asset,
        summary=f"{info['assembly']} | {info['runtime_family']} | {'WPF ' if info['wpf'] else ''}{'WinForms ' if info['winforms'] else ''}| {len(third)} third-party reference(s) | {len(info['pinvokes'])} P/Invoke import(s) | {len(info['resources'])} embedded resource(s)",
        evidence={"assembly": info["assembly"], "runtime": info["runtime_family"], "strong_name_signed": info["strong_name_signed"],
                  "debuggable_attribute": info["debuggable"], "third_party_assemblies": third[:60], "pinvoke_imports": info["pinvokes"][:60],
                  "embedded_resources_of_interest": embedded[:40], "type_definitions": info["type_def_count"]},
        compliance_support=mapper.resolve("TCP-INTEL-020"),
        manual_playbook=PlaybookRef("dnSpyEx / ILSpy", "Decompile and review the highest-risk code first",
                                    ["Open the assembly in dnSpyEx", "Search for the types/methods listed in the sensitive-API findings", "Review third-party assemblies for known CVEs (OSV/NuGet audit)"])))
    if info["obfuscators"]:
        out.append(Finding(check_id="TCP-INTEL-020", title="Obfuscated .NET Assembly (Static Review Is Incomplete)", category=CAT,
                           status=FindingStatus.MANUAL_REQUIRED, severity=Severity.LOW, confidence=Confidence.MEDIUM, affected_asset=asset,
                           summary="Obfuscator markers: " + ", ".join(info["obfuscators"]) + ". Strings and API names may be hidden, so other static checks under-report.",
                           evidence={"obfuscators": info["obfuscators"]}, compliance_support=mapper.resolve("TCP-INTEL-020"),
                           manual_playbook=PlaybookRef("de4dot / dnSpyEx", "Deobfuscate then re-scan", ["de4dot <file>", "Re-run TIRtcp on the cleaned assembly"])))
    if embedded:
        out.append(Finding(check_id="TCP-INTEL-020", title="Embedded Files in Assembly Resources", category=CAT, status=FindingStatus.OBSERVATION,
                           severity=Severity.LOW, confidence=Confidence.MEDIUM, affected_asset=asset,
                           summary=f"{len(embedded)} resource(s) look like files (dll/config/key/db). They are not on disk and are skipped by file-based scanners.",
                           evidence={"resources": embedded[:60]}, compliance_support=mapper.resolve("TCP-INTEL-020"),
                           manual_playbook=PlaybookRef("dnSpyEx", "Export resources and scan them", ["Right-click resource -> Save", "Run TIRtcp on the export directory"])))
    for risk, hits in classify_apis(info).items():
        status, sev, conf, title, text, fix = RISK_META[risk]
        out.append(Finding(check_id="TCP-INTEL-021", title=title, category=CAT, status=status, severity=sev, confidence=conf, affected_asset=asset,
                           summary=text, evidence={"references": hits[:40], "count": len(hits)}, remediation=fix,
                           compliance_support=mapper.resolve("TCP-INTEL-021"),
                           manual_playbook=PlaybookRef("dnSpyEx", f"Review call sites for: {title}", ["Analyze -> Used By on the listed types", "Trace inputs back to user/network data"]) if status == FindingStatus.MANUAL_REQUIRED else None))
    return out


def scan_dotnet_intel(target: Path, mapper: ComplianceMapper, ctx: Any = None, path_prefix: Optional[Tuple[Path, str]] = None) -> List[Finding]:
    if not HAS_DNFILE:
        return [Finding(check_id="TCP-INTEL-020", title=".NET Intelligence Unavailable", category=CAT, status=FindingStatus.TOOLING_GAP, severity=Severity.INFO,
                        confidence=Confidence.HIGH, affected_asset=str(target), summary="dnfile is not installed.", evidence={"missing_packages": ["dnfile"]},
                        remediation="pip install dnfile")]
    paths = [r.path for r in ctx.iter_binaries() if r.is_pe] if ctx is not None else (
        [target] if target.is_file() else [Path(r) / f for r, _, fs in os.walk(target) for f in fs if f.lower().endswith((".exe", ".dll"))])
    out: List[Finding] = []
    for p in paths[:400]:
        label = None
        if path_prefix:
            try:
                label = f"{path_prefix[1]}/{p.relative_to(path_prefix[0]).as_posix()}"
            except ValueError:
                label = None
        try:
            out.extend(dotnet_findings(p, mapper, label))
        except Exception:
            continue    # non-.NET or malformed metadata: not an error for the intel layer
    return out
