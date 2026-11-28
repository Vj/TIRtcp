# TIRtcp — Thick Client Penetration Testing & Compliance Scanner

**TIRtcp** is the desktop/thick-client security and compliance assessment module in the **TIR** suite (alongside **TIR** for Android, **TIRiOS**, and **TIRweb**).

It decouples **target-host evidence gathering** (`collector/`) from **cross-platform offline analysis** (`analyzer/`), emits every finding in a **canonical JSON schema** (projecting cleanly to **HTML**, **JSON**, and **SARIF v2.1.0**), and maps technical evidence to global and Indian regulatory frameworks.

---

## 1. Repository Layout

```text
TIRtcp/
├── collector/
│   └── collect_host.py             # Zero-dependency Windows host evidence collector
├── analyzer/
│   ├── tirtcp.py                   # Unified CLI orchestrator (Phases 1–4)
│   ├── core/
│   │   ├── schema.py               # Canonical Finding schema + JSON/SARIF/HTML exporters
│   │   ├── compliance_loader.py    # Profile-filtered YAML compliance hydrator
│   │   └── auth_gate.py            # --authorized + --engagement-id governance gate
│   └── modules/
│       ├── static_audit/           # Binary mitigations, Authenticode/codesign, secrets/DB/logs, hybrid SCA, Electron, .NET/Java
│       ├── host_offline/           # Filesystem/updater ACLs, static IAT + Procmon DLL hijack parser, IPC/COM/URI audit
│       ├── network_protocol/       # Non-HTTP TLS inspector & offline PCAP wire-protocol analyzer
│       └── runtime_gated/          # Authorization-gated post-logout memory retention scanner
├── config/
│   └── compliance_map.yaml         # Versioned framework controls & scope filters
└── tests/
    └── test_tirtcp.py              # Unified pytest regression suite

TIRtcp/
├── collector/
│   └── collect_host.py                     # Zero-dependency Windows evidence gatherer
├── analyzer/
│   ├── tirtcp.py                           # Unified Phases 1–4 CLI orchestrator
│   ├── core/
│   │   ├── schema.py                       # Canonical Finding model + JSON/SARIF/HTML projectors
│   │   ├── compliance_loader.py            # Scope-aware YAML hydration (general vs. bfsi)
│   │   └── auth_gate.py                    # --authorized + --engagement-id governance gate
│   └── modules/
│       ├── static_audit/
│       │   ├── binary_hardening.py         # PE (x64 & x86-only SafeSEH), ELF, Mach-O mitigations
│       │   ├── signature_audit.py          # signtool / osslsigncode / codesign chain & timestamp
│       │   ├── secrets_db_audit.py         # Direct DB strings, secrets, PDBs, DPDP PII log leaks
│       │   ├── sca_fingerprint.py          # Syft/Trivy/Grype + native C/C++ DLL version banners
│       │   └── electron_unpack.py          # Electron Fuses, pure-Python ASAR reader & webPreferences
│       ├── host_offline/
│       │   ├── acl_installer.py            # Live/offline directory & auto-update ACL checks
│       │   ├── dll_hijack_parser.py        # Static IAT + Procmon NAME NOT FOUND CSV analyzer
│       │   └── ipc_uri_audit.py            # Named Pipes, COM/DCOM, SYSTEM tasks & custom URI handlers
│       ├── network_protocol/
│       │   ├── tls_inspector.py            # Non-HTTP TLS 1.0/1.1, weak cipher & certificate checker
│       │   └── pcap_analyzer.py            # Scapy + pure-Python PCAP DB wire/cleartext/HTTP updater
│       └── runtime_gated/
│           └── memory_retention.py         # Gated post-logout dump canary scanner with confidence scores
├── config/
│   └── compliance_map.yaml                 # Versioned PCI DSS v4.0.1, ASVS, MASVS, DPDP, RBI, CERT-In map
└── tests/
    └── test_tirtcp.py                 # pytest validation suite


2. Installation & Collector Packaging

Analyst Workstation Setup (Windows / Linux / macOS)

python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Linux/macOS:        source .venv/bin/activate

pip install -e ".[network,dev]"
pytest

Optional External CLI Tools (for Enhanced Coverage)
TIRtcp runs cleanly without external binaries (flagging missing tools as Tooling Gap), but automatically leverages them when present on PATH:

Code Signing: signtool.exe (Windows SDK), osslsigncode (Linux/macOS), or codesign (macOS).

Supply Chain (SCA): syft + trivy or grype (supplements built-in native C/C++ DLL version fingerprinting).

TLS Probing: testssl.sh (supplements built-in Python TLS 1.0/1.1, cipher, and certificate checks).

Building the Portable Windows Collector (tirtcp-collector.exe)
When assessing locked-down client VDIs/workstations where Python cannot be installed, package collector/collect_host.py (which uses only the Python standard library) into a standalone executable:
XXXXX
    pyinstaller --onefile --name tirtcp-collector collector/collect_host.py
XXXXXX
3. Standard Operating Procedure (SOP) for Engagements
Step 1: Collect Read-Only Host Evidence (On Target Windows Machine)
Run the portable collector under the target user context (and optionally as Administrator to inspect restricted service keys):

.\tirtcp-collector.exe `
  --app-dir "C:\Program Files\TargetClient" `
  --filter "TargetClient" `
  --output .\host_evidence.json

.\tirtcp-collector.exe `
  --app-dir "C:\Users\ADMIN\Downloads\vpro_secret\ModernPaint.exe" `
  --filter "TargetClient" `
  --output .\host_evidence.json


(Optional) Export a Process Monitor (Procmon) trace as procmon.csv during normal application workflows (login, plugin load, auto-update) and capture network traffic to capture.pcap.

Step 2: Run Offline Analysis (On Analyst Workstation)

Standard Enterprise / DPDP Assessment (--compliance general):

tirtcp \
  --target ./TargetClient \
  --evidence ./host_evidence.json \
  --pcap ./capture.pcap \
  --procmon-csv ./procmon.csv \
  --compliance general \
  --engagement-id ENG-2026-014 \
  --output ./reports

tirtcp \
  --target ./C:\Users\ADMIN\Downloads\vpro_secret\ModernPaint.exe \
  --evidence ./host_evidence.json \
  --pcap ./capture.pcap \
  --procmon-csv ./procmon.csv \
  --compliance general \
  --engagement-id ENG-2026-014 \
  --output ./reports

# 1. Install optional Frida dependency in .venv
pip install frida

# 2. Capture 20 seconds of runtime Win32/DPAPI/WinHTTP/DLL hook events
python .\scripts\frida_hook_harness.py `
  --target "C:\Users\ADMIN\Downloads\vpro_secret\ModernPaint.exe" `
  --duration 20 `
  --authorized `
  --output .\evidence\ModernPaint\runtime_hooks.json

# 3. Feed runtime_hooks.json into TIRtcp alongside static/host/PCAP evidence
tirtcp `
  --target "C:\Users\ADMIN\Downloads\vpro_secret" `
  --evidence .\evidence\ModernPaint\host_evidence.json `
  --runtime-hooks .\evidence\ModernPaint\runtime_hooks.json `
  --authorized `
  --compliance general `
  --engagement-id ENG-2026-014 `
  --no-active-probe `
  --output .\reports

BFSI / Regulated Payment Assessment (--compliance bfsi):
Activates PCI DSS v4.0.1 and RBI Digital Payment Security Controls (2021) mappings alongside DPDP Act 2023 / Rules 2025, OWASP ASVS v4.0.3 / MASVS v2.1.0, and CWE:
tirtcp \
  --target ./TargetClient \
  --evidence ./host_evidence.json \
  --pcap ./capture.pcap \
  --endpoints broker.bank.local:8443 \
  --compliance bfsi \
  --engagement-id ENG-2026-015 \
  --output ./reports

4. Authorization Gate & Regulatory Guardrails
Mandatory Authorization Gate (--authorized + --engagement-id):
Phase 4 runtime memory hygiene (--memory-dump) is locked by default. To analyze a post-logout diagnostic dump for lingering QA canary credentials, both --authorized and a valid --engagement-id must be supplied. Raw canary strings are hashed (SHA-256 prefix) and never written into reports; lingering artifacts are classified as Evidence of Retention with calibrated confidence scores (Low / Medium / High).

Compliance Posture Disclaimer:
All reports explicitly note that technical checks support gap analysis against referenced standards and do not constitute formal legal or regulatory certification. CERT-In 2022 Directions mappings are tagged strictly as informational_support rather than Pass/Fail items.

<ElicitationsGroup message="Your TIRtcp codebase and documentation are complete. Would you like to:">
  <Elicitation label="Generate a sample vulnerable thick-client fixture generator for live demos" query="Write a Python helper script scripts/create_demo_target.py that builds a safe, self-contained synthetic vulnerable thick-client directory (PE binary, config with DB string, log with PAN, app.asar, PCAP, and host_evidence.json) to test TIRtcp end-to-end."/>
  <Elicitation label="Design an executive remediation matrix template for client deliverables" query="Create a Markdown client report executive summary and remediation roadmap template tailored for TIRtcp findings across CWE, OWASP ASVS, DPDP Rules 2025, PCI DSS v4.0.1, and RBI DPSC."/>
</ElicitationsGroup>
