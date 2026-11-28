"""TCP-INTEL-001..005: PE intelligence layer.

Why this exists: the original checks only report *misconfigurations*. A hardened single EXE with no config
files therefore yields ~3 findings even though a tester can learn a lot from it. This module always produces
an Application Profile (technology stack, build facts, signing, capabilities) and turns import/section/overlay
evidence into concrete, prioritised leads for manual or dynamic testing."""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.schema import Confidence, Finding, FindingStatus, PlaybookRef, Severity
from analyzer.modules.static_audit.authenticode_offline import inspect_authenticode

try:
    import pefile  # type: ignore
    HAS_PEFILE = True
except ImportError:  # pragma: no cover
    HAS_PEFILE = False

CAT = "Binary Intelligence"
MAX_READ = 400 * 1024 * 1024

# ---------------------------------------------------------------- technology stack fingerprints
STACK_MARKERS: List[Tuple[str, bytes]] = [
    ("PyInstaller (frozen Python)", b"MEI\x0c\x0b\x0a\x0b\x0e"),
    ("Python embedded/py2exe", b"PYTHONSCRIPT"),
    ("Nuitka (compiled Python)", b"Nuitka"),
    ("Go", b"Go buildinf:"),
    ("Rust", b"rustc/"),
    ("AutoIt compiled script", b"AU3!EA06"),
    ("NSIS installer", b"Nullsoft Install System"),
    ("Inno Setup installer", b"Inno Setup Setup Data"),
    ("Launch4j Java wrapper", b"launch4j"),
    ("Electron/Chromium app", b"app.asar"),
    ("Chromium Embedded Framework", b"libcef.dll"),
    ("Qt framework", b"Qt5Core"),
    ("Qt6 framework", b"Qt6Core"),
    ("Flutter desktop", b"flutter_windows.dll"),
    ("WebView2 host", b"WebView2Loader"),
    ("Delphi/C++Builder (VCL)", b"Embarcadero"),
    ("Visual Basic 6 runtime", b"MSVBVM60"),
    (".NET single-file bundle", bytes([0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7,
                                    0xa0, 0x32, 0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce,
                                    0x24, 0xb3, 0x6a, 0xae])),
]
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".petite": "Petite", ".nsp0": "NsPack", ".yp": "Yoda", ".boot": "Armadillo?", ".svkp": "SVKP",
}

# ---------------------------------------------------------------- capability map (import based)
CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "network": {"funcs": {"wsastartup", "connect", "wsaconnect", "internetopena", "internetopenw", "internetopenurla",
                          "internetopenurlw", "winhttpopen", "winhttpsendrequest", "httpsendrequesta", "httpsendrequestw",
                          "urldownloadtofilea", "urldownloadtofilew", "getaddrinfo", "gethostbyname", "wsasocketw", "socket"},
                "dlls": {"ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll"},
                "lead": "Client talks to the network: capture traffic and test auth, TLS, pinning, and server-side trust of client data."},
    "crypto_api": {"funcs": {"cryptprotectdata", "cryptunprotectdata", "bcryptencrypt", "bcryptdecrypt", "cryptencrypt",
                             "cryptdecrypt", "cryptacquirecontexta", "cryptacquirecontextw", "ncryptencrypt", "cryptderivekey",
                             "bcryptgeneratesymmetrickey", "cryptimportkey", "bcryptopenalgorithmprovider"},
                   "lead": "Uses OS crypto: hook with API Monitor/Frida to recover keys, IVs, algorithms and plaintext."},
    "dpapi": {"funcs": {"cryptprotectdata", "cryptunprotectdata", "cryptprotectmemory"},
              "lead": "DPAPI-protected data is decryptable by any process of the same user: check entropy param and where blobs are stored."},
    "process_exec": {"funcs": {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew", "shellexecuteexa",
                               "shellexecuteexw", "winexec", "createprocessasuserw", "createprocesswithlogonw"},
                     "lead": "Spawns processes: check unquoted paths, user-controlled arguments and DLL search order of children."},
    "dynamic_loading": {"funcs": {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress"},
                        "lead": "Runtime DLL loading: confirm absolute paths / LOAD_LIBRARY_SEARCH_SYSTEM32 (DLL hijacking)."},
    "injection": {"funcs": {"virtualallocex", "writeprocessmemory", "createremotethread", "ntwritevirtualmemory",
                            "queueuserapc", "setwindowshookexa", "setwindowshookexw", "ntmapviewofsection",
                            "ntunmapviewofsection", "rtlcreateuserthread", "setthreadcontext"},
                  "lead": "Process-injection primitives are unusual for a business client: verify purpose (AV/anti-cheat/hooking?)."},
    "anti_debug": {"funcs": {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                             "outputdebugstringa", "outputdebugstringw", "ntsetinformationthread", "debugactiveprocess"},
                   "lead": "Anti-debug present: expect tamper checks; plan x64dbg/ScyllaHide or Frida spawn-gating."},
    "persistence_registry": {"funcs": {"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
                                       "createservicea", "createservicew", "openscmanagera", "openscmanagerw"},
                             "lead": "Writes registry/services: diff registry & service list before/after run; check ACLs of created keys."},
    "privilege": {"funcs": {"adjusttokenprivileges", "impersonateloggedonuser", "duplicatetokenex", "logonusera",
                            "logonuserw", "setthreadtoken", "impersonatenamedpipeclient"},
                  "lead": "Privilege/token handling: look for confused-deputy and impersonation flaws."},
    "credential_store": {"funcs": {"credreada", "credreadw", "credwritea", "credwritew", "credenumeratea", "credenumeratew"},
                         "lead": "Windows Credential Manager use: dump stored creds (cmdkey/vaultcmd) after login."},
    "temp_and_links": {"funcs": {"gettemppatha", "gettemppathw", "gettempfilenamea", "gettempfilenamew", "createsymboliclinka",
                                 "createsymboliclinkw", "createhardlinka", "createhardlinkw", "movefileexa", "movefileexw"},
                       "lead": "Temp file / link handling: test for predictable names, TOCTOU and symlink/junction races."},
    "clipboard_screen_keys": {"funcs": {"getclipboarddata", "setclipboarddata", "openclipboard", "getasynckeystate",
                                        "bitblt", "printwindow", "setwineventhook"},
                              "lead": "Clipboard/keyboard/screen access: check whether secrets cross the clipboard and are cleared."},
    "cert_validation": {"funcs": {"winverifytrust", "certverifycertificatechainpolicy", "certgetcertificatechain",
                                  "crypthashcertificate", "certfindcertificateinstore"},
                        "lead": "Has certificate / signature validation primitives (good sign for updater and TLS pinning)."},
    "download": {"funcs": {"urldownloadtofilea", "urldownloadtofilew", "internetreadfile", "winhttpreaddata",
                           "urldownloadtocachefilea", "urldownloadtocachefilew"},
                 "lead": "Downloads content: if combined with process execution, test update integrity (see updater playbook)."},
}

# Microsoft SDL banned / high-risk CRT APIs (name -> why)
BANNED_APIS = {
    "strcpy", "strcpya", "strcpyw", "wcscpy", "_tcscpy", "_mbscpy", "lstrcpya", "lstrcpyw", "lstrcpy", "strcat", "strcata",
    "strcatw", "wcscat", "_tcscat", "_mbscat", "lstrcata", "lstrcatw", "lstrcat", "sprintf", "vsprintf", "wsprintfa",
    "wsprintfw", "wsprintf", "swprintf", "vswprintf", "gets", "_getws", "stpcpy", "strncpy", "_alloca", "alloca",
    "strcpyna", "strcpynw", "strcatbuffa", "strcatbuffw", "makepath", "_makepath", "_splitpath", "_snprintf",
}
HIGH_RISK_BANNED = {"gets", "_getws", "strcpy", "wcscpy", "lstrcpya", "lstrcpyw", "lstrcpy", "sprintf", "vsprintf",
                    "wsprintfa", "wsprintfw", "wsprintf", "strcat", "wcscat", "lstrcata", "lstrcatw", "lstrcat"}

SCN_MEM_EXEC, SCN_MEM_WRITE = 0x20000000, 0x80000000
EMBEDDED_MANIFEST_RE = re.compile(rb"<assembly\b[^>]*>.*?</assembly>", re.DOTALL)


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf[:2_000_000]:
        counts[b] += 1
    n = min(len(buf), 2_000_000)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _mk(check_id: str, title: str, status: FindingStatus, sev: Severity, conf: Confidence, asset: str, summary: str,
        evidence: Dict[str, Any], mapper: ComplianceMapper, remediation: str = "",
        playbook: Optional[PlaybookRef] = None) -> Finding:
    return Finding(check_id=check_id, title=title, category=CAT, status=status, severity=sev, confidence=conf,
                   affected_asset=asset, summary=summary, evidence=evidence, remediation=remediation,
                   compliance_support=mapper.resolve(check_id), manual_playbook=playbook)


def _imports(pe: "pefile.PE") -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                           pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, []) or []:
            dll = entry.dll.decode("ascii", "ignore").lower() if entry.dll else "?"
            names = out.setdefault(dll, set())
            for imp in entry.imports:
                if imp.name:
                    names.add(imp.name.decode("ascii", "ignore").lower())
    return out


def _version_info(pe: "pefile.PE") -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for fi in getattr(pe, "FileInfo", []) or []:
            for e in fi if isinstance(fi, list) else [fi]:
                if getattr(e, "Key", b"") == b"StringFileInfo":
                    for st in e.StringTable:
                        for k, v in st.entries.items():
                            info[k.decode("utf-8", "ignore")] = v.decode("utf-8", "ignore")
    except Exception:
        pass
    return info


def _manifest(pe: "pefile.PE", data: bytes, path: Path) -> Tuple[Optional[str], str]:
    m = EMBEDDED_MANIFEST_RE.search(data)
    if m:
        return m.group(0).decode("utf-8", "ignore"), "embedded"
    side = Path(str(path) + ".manifest")
    if side.exists():
        return side.read_text(encoding="utf-8", errors="ignore"), "sidecar"
    return None, "none"


def _pdb_info(pe: "pefile.PE") -> Optional[str]:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            ent = getattr(d, "entry", None)
            name = getattr(ent, "PdbFileName", None)
            if name:
                return name.split(b"\x00")[0].decode("utf-8", "ignore")
    except Exception:
        pass
    return None


def analyze_pe(path: Path) -> Dict[str, Any]:
    """Pure data extraction (no findings) so it is unit-testable and reusable by other modules."""
    data = path.read_bytes() if path.stat().st_size <= MAX_READ else path.read_bytes()[:MAX_READ]
    pe = pefile.PE(data=data, fast_load=True)
    try:
        imports = _imports(pe)
        is_dotnet = False
        try:
            clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            is_dotnet = bool(clr.VirtualAddress and clr.Size)
        except IndexError:
            pass
        ts = pe.FILE_HEADER.TimeDateStamp
        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("ascii", "ignore")
            raw = s.get_data()
            sections.append({"name": name, "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                             "entropy": round(_entropy(raw), 2), "executable": bool(s.Characteristics & SCN_MEM_EXEC),
                             "writable": bool(s.Characteristics & SCN_MEM_WRITE)})
        overlay_off = pe.get_overlay_data_start_offset()
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        overlay_size = 0
        overlay_entropy = 0.0
        if overlay_off is not None:
            overlay_size = max(len(data) - overlay_off - (sec_dir.Size or 0), 0)
            if overlay_size:
                overlay_entropy = round(_entropy(data[overlay_off:overlay_off + min(overlay_size, 2_000_000)]), 2)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = next((s["name"] for s, raw in zip(sections, pe.sections)
                           if raw.VirtualAddress <= ep < raw.VirtualAddress + max(raw.Misc_VirtualSize, raw.SizeOfRawData)), None)
        tls_callbacks = False
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
            tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
            tls_callbacks = bool(tls and tls.struct.AddressOfCallBacks)
        except Exception:
            pass
        stacks = [label for label, marker in STACK_MARKERS if marker in data]
        if is_dotnet:
            stacks.insert(0, ".NET (managed)")
        for dll, label in (("mfc140u.dll", "MFC"), ("mfc42.dll", "MFC"), ("qt5core.dll", "Qt framework"),
                           ("msvbvm60.dll", "Visual Basic 6 runtime")):
            if dll in imports and label not in stacks:
                stacks.append(label)
        if not stacks:
            stacks.append("Native C/C++ (no framework marker)")
        manifest_xml, manifest_src = _manifest(pe, data, path)
        return {
            "path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "machine": hex(pe.FILE_HEADER.Machine), "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "is_dotnet": is_dotnet, "stack": stacks, "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "linker": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
            "os_version_required": f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}",
            "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None, "timestamp_raw": ts,
            "pdb_path": _pdb_info(pe), "version_info": _version_info(pe), "sections": sections,
            "entry_point_section": ep_section, "overlay_size": overlay_size, "overlay_entropy": overlay_entropy,
            "tls_callbacks": tls_callbacks, "imports": {k: sorted(v) for k, v in imports.items()},
            "import_count": sum(len(v) for v in imports.values()), "manifest": manifest_xml, "manifest_source": manifest_src,
            "has_relocs": bool(getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0) & 0x40),
        }
    finally:
        pe.close()


def _capabilities(imports: Dict[str, List[str]]) -> Dict[str, List[str]]:
    funcs = {f for v in imports.values() for f in v}
    dlls = set(imports)
    found: Dict[str, List[str]] = {}
    for cat, spec in CAPABILITIES.items():
        hit = sorted(funcs & spec["funcs"])
        if spec.get("dlls") and (dlls & spec["dlls"]):
            hit = sorted(set(hit) | {d for d in dlls & spec["dlls"]})
        if hit:
            found[cat] = hit
    return found


def _uac(manifest: Optional[str]) -> Dict[str, Any]:
    if not manifest:
        return {}
    out: Dict[str, Any] = {}
    m = re.search(r'requestedExecutionLevel[^>]*level\s*=\s*["\']([^"\']+)["\']', manifest)
    if m:
        out["level"] = m.group(1)
    m = re.search(r'uiAccess\s*=\s*["\'](\w+)["\']', manifest)
    if m:
        out["uiAccess"] = m.group(1).lower() == "true"
    out["autoElevate"] = bool(re.search(r"autoElevate[^<]*>\s*true", manifest, re.I))
    out["dependent_assemblies"] = re.findall(r'<assemblyIdentity[^>]*name\s*=\s*["\']([^"\']+)["\']', manifest)[1:6]
    return out


def profile_findings(path: Path, mapper: ComplianceMapper) -> List[Finding]:
    f: List[Finding] = []
    p = analyze_pe(path)
    asset = str(path)
    caps = _capabilities(p["imports"])
    auth = inspect_authenticode(str(path))
    uac = _uac(p["manifest"])

    # ---- INTEL-001 Application profile (always emitted)
    leaks = []
    if p["pdb_path"]:
        m = re.search(r"[A-Za-z]:\\Users\\([^\\]+)\\", p["pdb_path"])
        if m:
            leaks.append(f"build username '{m.group(1)}' leaked via PDB path")
    summary = (f"{', '.join(p['stack'])} | {p['machine']} | {p['size']:,} bytes | built {p['timestamp'] or 'n/a'} | "
               f"{p['import_count']} imports from {len(p['imports'])} DLLs | "
               f"{'signed by ' + auth.get('subject', '?') if auth.get('signed') else 'unsigned'}")
    f.append(_mk("TCP-INTEL-001", "Application Technology & Build Profile", FindingStatus.OBSERVATION, Severity.INFO,
                 Confidence.HIGH, asset, summary,
                 {"sha256": p["sha256"], "stack": p["stack"], "machine": p["machine"], "linker": p["linker"],
                  "compile_timestamp": p["timestamp"], "pdb_path": p["pdb_path"], "version_info": p["version_info"],
                  "sections": p["sections"], "entry_point_section": p["entry_point_section"],
                  "dlls_imported": sorted(p["imports"]), "information_leaks": leaks,
                  "uac": uac, "manifest_source": p["manifest_source"]}, mapper,
                 playbook=PlaybookRef("Detect It Easy / dnSpy / Ghidra", "Pick the right reversing toolchain for the stack",
                                      [f"Stack detected: {', '.join(p['stack'])}",
                                       "Managed -> dnSpyEx/ILSpy; Native -> Ghidra/IDA; Python -> pyinstxtractor+decompyle3; Electron -> asar extract",
                                       "Record the SHA-256 in the engagement log for reproducibility"])))

    # ---- INTEL-002 packing / protection
    reasons: List[str] = []
    packer = {PACKER_SECTIONS[s["name"].lower()] for s in p["sections"] if s["name"].lower() in PACKER_SECTIONS}
    if packer:
        reasons.append(f"packer/protector section names: {', '.join(sorted(packer))}")
    hot = [s for s in p["sections"] if s["executable"] and s["entropy"] >= 7.2 and s["raw_size"] > 4096]
    if hot:
        reasons.append("high-entropy executable section(s): " + ", ".join(f"{s['name']}={s['entropy']}" for s in hot))
    wx = [s["name"] for s in p["sections"] if s["executable"] and s["writable"]]
    if wx:
        reasons.append(f"writable+executable section(s): {', '.join(wx)}")
    if p["import_count"] and p["import_count"] <= 8 and not p["is_dotnet"]:
        reasons.append(f"only {p['import_count']} imports (typical of packed / runtime-resolved code)")
    if p["entry_point_section"] and p["sections"] and not next((s["executable"] for s in p["sections"] if s["name"] == p["entry_point_section"]), True):
        reasons.append("entry point is in a non-executable section")
    if reasons:
        f.append(_mk("TCP-INTEL-002", "Packed / Protected / Self-Modifying Binary Indicators", FindingStatus.FAIL,
                     Severity.MEDIUM if (packer or wx) else Severity.LOW, Confidence.MEDIUM, asset,
                     "Static analysis is limited by packing/protection; hidden code and secrets may not be visible. " + "; ".join(reasons),
                     {"reasons": reasons, "sections": p["sections"]}, mapper,
                     remediation="Avoid W+X sections; if a protector is used for IP protection, ensure security-relevant logic is also validated server-side.",
                     playbook=PlaybookRef("Unpacker / x64dbg", "Obtain the unpacked image before analysis",
                                          ["Run in an isolated VM, dump process at OEP (Scylla / pe-sieve)", "Re-run TIRtcp on the dumped image",
                                           "Check whether integrity checks / anti-debug block patching (tamper-resistance test)"])))
    if p["overlay_size"] > 64 * 1024:
        f.append(_mk("TCP-INTEL-002", "Large Appended Data (Overlay) Beyond PE Sections", FindingStatus.OBSERVATION, Severity.LOW,
                     Confidence.MEDIUM, asset,
                     f"{p['overlay_size']:,} bytes appended after the last section (entropy {p['overlay_entropy']}). Installers, "
                     "self-extracting archives, bundled assemblies and embedded configs live here and are invisible to import/section analysis.",
                     {"overlay_size": p["overlay_size"], "overlay_entropy": p["overlay_entropy"]}, mapper,
                     playbook=PlaybookRef("binwalk / 7-Zip", "Carve the overlay payload", ["binwalk -e <file>  or  7z x <file>",
                                          "Scan extracted tree with TIRtcp (--target <dir>)"])))
    if p["tls_callbacks"]:
        f.append(_mk("TCP-INTEL-002", "TLS Callbacks Present (Code Runs Before Entry Point)", FindingStatus.OBSERVATION, Severity.LOW,
                     Confidence.HIGH, asset, "TLS callbacks execute before main(); commonly used for anti-debugging and unpacking. Breakpoint at the entry point will be too late.",
                     {"tls_callbacks": True}, mapper))

    # ---- INTEL-003 capability + banned API leads
    if caps:
        f.append(_mk("TCP-INTEL-003", "Imported Capability Map (Attack-Surface Leads)", FindingStatus.OBSERVATION, Severity.INFO,
                     Confidence.MEDIUM, asset,
                     "Capabilities inferred from the import table: " + ", ".join(sorted(caps)),
                     {"capabilities": caps, "leads": {k: CAPABILITIES[k]["lead"] for k in caps}}, mapper,
                     playbook=PlaybookRef("API Monitor / Frida / Procmon", "Confirm each capability dynamically",
                                          [CAPABILITIES[k]["lead"] for k in sorted(caps)])))
    if "injection" in caps and len(caps["injection"]) >= 3:
        f.append(_mk("TCP-INTEL-003", "Process-Injection API Combination Imported", FindingStatus.MANUAL_REQUIRED, Severity.MEDIUM,
                     Confidence.MEDIUM, asset, "Binary imports " + ", ".join(caps["injection"]) + ". Legitimate in a few product classes, but also the footprint of loaders/implants.",
                     {"apis": caps["injection"]}, mapper,
                     playbook=PlaybookRef("Ghidra / x64dbg", "Establish intent of injection primitives", ["Find xrefs to each API", "Identify target processes and payload origin"])))
    flat = {fn for v in p["imports"].values() for fn in v}
    banned = sorted(flat & BANNED_APIS)
    if banned and not p["is_dotnet"]:
        hi = sorted(set(banned) & HIGH_RISK_BANNED)
        f.append(_mk("TCP-INTEL-003", "Banned / Memory-Unsafe CRT APIs Imported", FindingStatus.FAIL,
                     Severity.MEDIUM if (hi and "network" in caps) else Severity.LOW, Confidence.LOW, asset,
                     f"Imports {len(banned)} Microsoft-SDL banned API(s) ({', '.join(banned[:8])}). Presence is a lead, not proof of a bug: confirm reachability from attacker-controlled input.",
                     {"banned_apis": banned, "high_risk": hi, "network_capable": "network" in caps}, mapper,
                     remediation="Replace with bounds-checked equivalents (strcpy_s/StringCchCopy/snprintf), enable /GS and /sdl, fuzz parsers.",
                     playbook=PlaybookRef("Ghidra + WinAFL", "Triage and fuzz callers of banned APIs",
                                          ["Locate callers of each banned API", "Trace whether the source is network/file/IPC input", "Harness the parser with WinAFL/libFuzzer"])))
    if "download" in caps and "process_exec" in caps and "cert_validation" not in caps:
        f.append(_mk("TCP-INTEL-003", "Download + Execute Without Signature-Validation Imports (Updater Integrity Lead)", FindingStatus.MANUAL_REQUIRED,
                     Severity.MEDIUM, Confidence.LOW, asset,
                     "Imports download APIs and process-creation APIs but no WinVerifyTrust / certificate-chain APIs. The updater may not verify what it runs (may also use managed or statically linked verification).",
                     {"download": caps["download"], "exec": caps["process_exec"]}, mapper,
                     playbook=PlaybookRef("mitmproxy / Burp + local HTTP server", "Updater integrity test",
                                          ["Redirect update host to a lab server", "Serve a modified manifest and an unsigned/old installer", "Verify client rejects: unsigned, wrong signer, downgrade, hash mismatch"])))

    # ---- INTEL-004 Authenticode (offline)
    if not auth.get("signed"):
        f.append(_mk("TCP-INTEL-004", "Executable Is Not Authenticode-Signed", FindingStatus.FAIL, Severity.MEDIUM, Confidence.HIGH, asset,
                     "No Authenticode signature present: users, EDR and update channels cannot verify publisher or detect tampering.",
                     {"signed": False}, mapper, remediation="Sign all shipped binaries (SHA-256 + RFC 3161 timestamp) with an EV/OV code-signing certificate."))
    else:
        issues = []
        if auth.get("digest_matches_file") is False:
            issues.append(("Signed Binary Was Modified After Signing (Digest Mismatch)", Severity.HIGH,
                           "The recomputed Authenticode digest does not match the signed digest: the file was patched/tampered after signing."))
        if auth.get("self_signed"):
            issues.append(("Signed With a Self-Signed Certificate", Severity.MEDIUM, "Leaf certificate is self-signed; it provides no publisher assurance."))
        if auth.get("expired") and not auth.get("has_timestamp"):
            issues.append(("Signing Certificate Expired Without Trusted Timestamp", Severity.MEDIUM, "Signature becomes invalid after certificate expiry because no RFC 3161 timestamp countersignature is embedded."))
        elif not auth.get("has_timestamp"):
            issues.append(("Signature Has No Trusted Timestamp", Severity.LOW, "No RFC 3161 countersignature: signature validity ends with the certificate."))
        if auth.get("digest_algorithm") in ("sha1", "md5"):
            issues.append((f"Weak Authenticode Digest Algorithm ({auth['digest_algorithm'].upper()})", Severity.MEDIUM, "SHA-1/MD5 file digests are collision-prone and distrusted by modern Windows."))
        if auth.get("public_key_algorithm") == "rsa" and (auth.get("public_key_bits") or 4096) < 2048:
            issues.append(("Weak Code-Signing Key Size", Severity.MEDIUM, f"RSA key of {auth['public_key_bits']} bits."))
        for title, sev, text in issues:
            f.append(_mk("TCP-INTEL-004", title, FindingStatus.FAIL, sev, Confidence.HIGH, asset, text, auth, mapper,
                         remediation="Re-sign with SHA-256, a publicly trusted certificate and /tr timestamp; sign as the last build step."))
        if not issues:
            f.append(_mk("TCP-INTEL-004", "Authenticode Structure Valid (Chain Trust Not Evaluated Offline)", FindingStatus.VERIFIED_PASS, Severity.INFO,
                         Confidence.MEDIUM, asset, f"Signed by {auth.get('subject')}; SHA-256-class digest matches file contents; timestamp present. Verify chain/revocation with signtool on Windows.",
                         auth, mapper))

    # ---- INTEL-005 manifest / UAC / version
    if uac.get("level", "").lower() in ("requireadministrator", "highestavailable") or uac.get("autoElevate") or uac.get("uiAccess"):
        f.append(_mk("TCP-INTEL-005", f"Elevated Execution Requested by Manifest ({uac.get('level', 'autoElevate/uiAccess')})", FindingStatus.FAIL,
                     Severity.MEDIUM, Confidence.HIGH, asset, "An elevated process widens the impact of every DLL-hijack, IPC, parsing or update flaw in this client.",
                     uac, mapper, remediation="Run as asInvoker; move privileged operations into a minimal, authenticated service."))
    if p["manifest_source"] == "none" and not p["is_dll"]:
        f.append(_mk("TCP-INTEL-005", "No Application Manifest (Legacy UAC File/Registry Virtualization Applies)", FindingStatus.OBSERVATION, Severity.LOW,
                     Confidence.MEDIUM, asset, "Without a manifest Windows may silently redirect writes to VirtualStore and apply compatibility shims.", {}, mapper))
    orig = (p["version_info"].get("OriginalFilename") or "").lower()
    if orig and orig != path.name.lower() and not orig.endswith(".tmp"):
        f.append(_mk("TCP-INTEL-005", "File Name Differs From Embedded OriginalFilename", FindingStatus.OBSERVATION, Severity.LOW, Confidence.MEDIUM, asset,
                     f"On disk '{path.name}' vs version resource '{p['version_info'].get('OriginalFilename')}': renamed, repackaged or masquerading binary.",
                     {"original_filename": p["version_info"].get("OriginalFilename")}, mapper))
    return f


def scan_pe_profiles(target: Path, mapper: ComplianceMapper, ctx: Any = None, max_files: int = 40) -> List[Finding]:
    if not HAS_PEFILE:
        return [_mk("TCP-INTEL-001", "PE Profiler Unavailable", FindingStatus.TOOLING_GAP, Severity.INFO, Confidence.HIGH, str(target),
                    "pefile is not installed.", {"missing_packages": ["pefile"]}, mapper, remediation="pip install pefile asn1crypto")]
    if ctx is not None:
        paths = [r.path for r in ctx.iter_binaries() if r.is_pe]
    elif target.is_file():
        paths = [target]
    else:
        paths = [p for p in target.rglob("*") if p.suffix.lower() in (".exe", ".dll", ".ocx", ".sys")]
    paths = sorted(paths, key=lambda x: (x.suffix.lower() != ".exe", -x.stat().st_size))[:max_files]
    out: List[Finding] = []
    for pth in paths:
        try:
            out.extend(profile_findings(pth, mapper))
        except Exception as exc:
            out.append(_mk("TCP-INTEL-001", "PE Profile Parse Error", FindingStatus.TOOLING_GAP, Severity.INFO, Confidence.LOW, str(pth),
                           f"Could not profile binary: {exc}", {"error": str(exc)}, mapper))
    return out
