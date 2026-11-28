# TIRtcp — Thick-Client Security & Compliance Scanner (v1.0.0)

**TIRtcp** is an offline-first, 4-phase security auditing and compliance verification engine built for enterprise Windows thick clients (`.NET`, Electron/Chromium, Java, and native `C/C++` PE binaries). It combines single-pass static binary intelligence, network wire-protocol inspection, managed framework & IPC auditing, and authorization-gated runtime hygiene into executive HTML, JSON, SARIF v2.1.0, and PDF reports.

---

## Key Capabilities

### Phase 0: Attack-Surface & Binary Intelligence
* **PE Profiling & Offline Authenticode Verification:** Identifies compiler toolchains, packers, capabilities, UAC manifest elevation (`requireAdministrator`), and verifies embedded PKCS#7 Authenticode digests and certificate chains offline.
* **String & Secret Intelligence:** Detects cleartext endpoints, hardcoded API keys/tokens, database connection strings, SQL queries, and PII with automatic secret redaction in report artifacts.
* **.NET & AI-Browser / Chromium Audits:** Inventories P/Invoke declarations and sensitive APIs in `.NET` assemblies, and audits embedded Chromium/AI-browser profiles for plaintext credentials, insecure cookie flags, dangerous launch switches, over-privileged extensions, and unencrypted MCP/LLM API keys.

### Phase 1: Static Binary Hardening, Supply-Chain & Host ACLs
* **Exploit Mitigations (`TCP-BIN-001`):** Audits PE/ELF/Mach-O headers for `ASLR`, 64-bit `High-Entropy ASLR`, `DEP/NX`, `Control Flow Guard (CFG)`, `Intel CET Shadow Stack`, `SafeSEH`, and `FORCE_INTEGRITY`.
* **Native Crypto & Anti-Tamper (`TCP-BIN-003`):** Flags embedded AES Rijndael S-boxes, non-cryptographic PRNG imports (`rand`/`srand`/`RtlRandom`), and extracts hardcoded TLS `sha256/...` SPKI pins and PEM trust anchors.
* **Air-Gapped SCA & KEV/EPSS Matching (`TCP-SCA-001`):** Fingerprints bundled C/C++ DLLs (`OpenSSL`, `libcurl`, `SQLite3`, `zlib`, `CEF`, `Qt`) and matches package manifests against an offline **OSV.dev + CISA KEV + FIRST EPSS** database (`config/offline_vulns.json`).
* **Filesystem & Host Posture (`TCP-HOST-001`):** Evaluates `icacls`/SDDL permissions on installation and auto-update directories, custom Trusted Root CAs, inbound Windows Firewall rules, and Windows Credential Manager targets.

### Phase 2: Network Transport & Wire-Protocol Analysis
* **PCAP/PCAPNG & Non-HTTP Dissectors (`TCP-NET-001`):** Extracts TLS SNI hostnames, flags legacy TLS handshakes, and decodes cleartext credentials/frames across HTTP, **MSSQL TDS**, **PostgreSQL**, **MQTT**, and **cleartext HTTP/2 / gRPC**.
* **Active TLS & MITM Proxy Capture:** Optional scope-allowlisted TLS version/cipher probing and local `mitmdump` / HTTP CONNECT capture (`scripts/proxy_mitm_capture.ps1`).

### Phase 3: Managed Frameworks, Decompilation & Offline IPC
* **Electron & ASAR Auditing (`TCP-ELEC-001`):** Inspects Electron Fuses and `app.asar` `webPreferences` (`nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity`).
* **DLL Search-Order Hijacking (`TCP-HOST-002`):** Correlates static PE Import Address Tables (IAT) and Procmon CSV traces to detect phantom or user-writable DLL loads.
* **Headless Decompilation & Code Rules:** Runs `ilspycmd` (`.NET`) or `jadx` (Java) with Semgrep/built-in rules to detect insecure TLS callbacks, SQL concatenation, and unsafe deserialization.
* **Runtime State-Diff & IPC (`TCP-IPC-001`):** Audits offline Named Pipes, COM/DCOM registrations, SYSTEM scheduled tasks, custom URI handlers, and pre/post execution filesystem & `Run` registry diffs (`--state-diff`).

### Phase 4: Authorization-Gated Runtime Memory Hygiene
* **Post-Logout Memory & Frida API Hooks (`TCP-MEM-001`):** Scans post-logout `.dmp` memory dumps for retained session tokens/canaries and evaluates Frida runtime API trace logs (`--runtime-hooks`) for unencrypted DPAPI calls, cleartext WinHTTP requests, and user-writable DLL loads.

---

## Installation

```powershell
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install TIRtcp and dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

Quick Start & CLI Usage
1. Offline / Static Assessment
python -m analyzer.tirtcp `
  --target "C:\Program Files\TargetApp" `
  --compliance general `
  --engagement-id ENG-2026-001 `
  --no-active-probe `
  --output .\reports

  2. Full 4-Phase Assessment (with Host Evidence, PCAP, State Diff & PDF Export)
  python -m analyzer.tirtcp `
  --target "C:\Program Files\TargetApp" `
  --evidence .\evidence\host_evidence.json `
  --pcap .\evidence\capture.pcapng `
  --procmon-csv .\evidence\procmon.csv `
  --state-diff .\evidence\state_diff.json `
  --runtime-hooks .\evidence\runtime_hooks.json `
  --memory-dump .\evidence\post_logout.dmp `
  --canary-markers "SessionSecret#2026" `
  --compliance bfsi `
  --authorized `
  --engagement-id ENG-2026-BFSI `
  --baseline-report .\reports\previous_run.json `
  --pdf `
  --output .\reports

  3. One-Command Windows Assessment Wrapper

  .\scripts\assess_target.ps1 `
  -Target "C:\Program Files\TargetApp\Client.exe" `
  -Compliance bfsi `
  -DynamicCapture `
  -FridaHook `
  -Authorized `
  -EngagementId ENG-2026-002

Compliance Frameworks Supported

General Profile (--compliance general): ISO/IEC 27001, OWASP Desktop/MASVS-aligned technical controls, and India DPDP Act / Rules 2025.

BFSI Profile (--compliance bfsi): All General controls plus RBI Digital Payment Security Controls and PCI DSS v4.0.
MDEOF

echo "[3/3] Verifying requirements.txt & running pytest regression suite..."
"$PYTHON_BIN" -m pytest -v tests/
echo "[+] requirements.txt, pyproject.toml, and README.md updated and verified!"

### Execute & Commit Documentation Update

```powershell
& "C:\Program Files\Git\bin\bash.exe" update_docs_and_reqs.sh
Remove-Item -Force .\update_docs_and_reqs.sh -ErrorAction SilentlyContinue
git add requirements.txt pyproject.toml README.md
git commit -m "Update requirements.txt, pyproject.toml, and README.md for TIRtcp v1.0.0"
git push origin main