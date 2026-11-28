# Changelog

## v1.0.0 (Production GA)
- **4-Phase Security & Compliance Orchestrator:** Parallelized static execution with configurable `--stage-timeout` isolation, single-pass `ScanContext` file indexing, root-cause deduplication, and `0–100` risk scoring.
- **Binary, Crypto & Code Integrity Hardening:** Audits PE/ELF/Mach-O exploit mitigations (ASLR, High-Entropy ASLR, DEP/NX, Control Flow Guard, Intel CET Shadow Stack, SafeSEH, `FORCE_INTEGRITY`), embedded AES S-boxes, weak PRNGs, and TLS SPKI/PEM pinning material.
- **Wire-Protocol & Active Capture:** Offline PCAP/PCAPNG SNI & credential extraction, non-HTTP protocol dissectors (MSSQL TDS, PostgreSQL, MQTT, cleartext HTTP/2 & gRPC), and scoped MITM proxy capture (`scripts/proxy_mitm_capture.ps1`).
- **Managed Frameworks, Decompilation & Runtime Hooks:** Electron Fuses/ASAR checks, .NET/Java bytecode auditing, headless `ilspycmd`/`jadx` + Semgrep rules, Frida API hook trace auditing (`--runtime-hooks`), and pre/post execution filesystem & Run-key diffing (`--state-diff`).
- **Air-Gapped SCA & Executive Deliverables:** Offline OSV.dev + CISA KEV + FIRST EPSS vulnerability matching (`scripts/update_vuln_db.py`), baseline retest diffing (`--baseline-report`), manual triage worklist processor with `--rerender`, interactive HTML dashboard, JSON, SARIF v2.1.0, and optional `--pdf` export.
