# TIRtcp code review & automation roadmap

Scope: `TIRtcp.zip` (analyzer package, 5.0k LOC, 16 modules). Items marked **[verified]** were reproduced by running code;
**[read]** were found by reading and not executed (they need a Windows target to prove).

## 0. Blocking issues in the package as shipped
1. `collector/collect_host.py`, `config/compliance_map.yaml`, `tests/test_tirtcp.py` are referenced by the README but **not in the zip**. `python -m analyzer.tirtcp` exits with "Compliance map not found" **[verified]**. Collector-dependent modules (ACL, IPC/COM/URI, DLL hijack writability) cannot be exercised without it.
2. No `__init__.py` files (works as namespace packages, but `setuptools.packages.find` in `pyproject.toml` will NOT package them -> `pip install -e .` yields an empty wheel).
3. `__pycache__/*.pyc` (cpython-314) committed; README contains stray `XXXXX` and an `<ElicitationsGroup>` block; README says PCAPNG is supported, the code only reads classic PCAP/Scapy.

## 1. Logic bugs that produce wrong verdicts (all fixed in this bundle, each with a regression test)
| # | Module | Problem | Impact |
|---|---|---|---|
| 1 | pcap_analyzer | Flags any TLS handshake with record version 0x0301 as "TLS 1.0". Modern TLS 1.2/1.3 ClientHellos use 0x0301 for compatibility. **[verified]** | False HIGH on healthy traffic. Fix: parse Client/ServerHello + `supported_versions` (`tls_records.py`). |
| 2 | pcap_analyzer | DB signatures (`\x12\x01\x00` etc.) matched anywhere in any payload; port test was dead code. | Random-data false positives. Now port-gated. |
| 3 | pcap_analyzer | `sample_preview` stored the first 120 raw bytes of the matching packet — i.e. the cleartext password — in JSON/HTML/SARIF. **[verified]** | Violates the tool's own "never write secrets" rule. Now redacted. |
| 4 | memory_retention | Half-overlap logic double-counted a canary sitting in the chunk overlap (1 planted -> 2 hits). **[verified]** | Inflated HIGH/MEDIUM confidence. Now counts only matches ending in new data. |
| 5 | dll_hijack_parser | `os.path.dirname` on Windows paths returns `""` on Linux/macOS **[verified]** -> zero candidates -> "Verified Pass". | False negative on the analyst platforms the README advertises. Now `ntpath`. |
| 6 | dll_hijack_parser | Install dir was *assumed* writable -> HIGH for every optional-DLL probe; static-IAT compared the analyst's local path to host paths (never equal). | Noise + wrong severity. Assumption removed; IAT path issue listed in section 2. |
| 7 | secrets_db_audit | `_is_placeholder` used substring match: `MyPassword#2026!`, `Contest#9981x` were discarded as "placeholder". **[verified]** | Real secrets silently dropped. Now exact/shape match. |
| 8 | secrets_db_audit | Aadhaar regex fired on any 12 digits (e.g. timestamps), PAN regex on any `AAAAA9999A`; no card-number (PCI PAN) detection despite BFSI profile. `"log" in filename` matched `catalog.dll`. | FP flood / PCI gap. Added Verhoeff, PAN holder-type, Luhn, filename fix (`validators.py`). |
| 9 | electron_unpack | Minified bundles write `nodeIntegration:!0` / `contextIsolation:!1`; regexes only matched `true/false`. **[verified]** | The most common real-world Electron misconfig is missed, then reported "Verified Pass". |
| 10 | electron_unpack | ASAR file budget (250) consumed by `node_modules` before filtering -> app code truncated. Fuse `GrantFileProtocolExtraPrivileges` not checked. | Coverage gap. Fixed. |
| 11 | acl_installer | Matched `"(WD)"` as a substring; icacls prints combined rights like `(S,WD,AD,X,DC)` -> missed. `(DENY)(W)` was flagged as risky. **[verified]** | Both false negatives and false positives. Token parser added. |
| 12 | acl_installer / orchestrator | With no `--evidence`, ACLs of the analyst's *copy* of the app were checked and reported "Verified Pass". | False assurance. Now skipped as Tooling Gap unless `--live-host`. |
| 13 | tls_inspector | Legacy-TLS probe returned `False` for any error, incl. local OpenSSL refusing TLS1.0 (default on modern distros). Result: "rejected TLS 1.0/1.1" pass without a real test. `_run_testssl_if_available` is never called. | False pass. Probe is now tri-state (accepted / refused / inconclusive) with SECLEVEL=0. |
| 14 | sca_fingerprint | zlib regex (`zlib 1.2.x`) does not match real banners (`inflate 1.2.11 Copyright 1995-…`). | zlib never detected. |

## 2. Found by reading — not yet fixed (prioritised)
**High**
- **Active network probing is not governed.** `tls_inspector` auto-extracts `host:port` from config files and connects to them (vendor telemetry, SaaS, third parties) with no scope check; only Phase 4 is gated. Add `--scope-file` (allow-list of hosts/CIDRs); default-deny discovered endpoints outside it. `--no-active-probe` added as a stop-gap.
- **Aggregation / duplicates.** Findings are emitted per file x pattern (binary hardening, strong-name, secrets, CVEs). A real install gives hundreds of near-identical cards. Group by (check, title) with an asset list; give each finding a stable fingerprint (also feeds SARIF `partialFingerprints` and baseline diff).
- **Verified-Pass semantics.** Passes are emitted after skipped files (>25 MB, unreadable, unparsed archives), failed tools and encrypted traffic. Every module should return coverage (`files_seen/scanned/skipped`) and downgrade the pass to "Not Assessed" when coverage <100%. PCAP "pass" should report % encrypted vs unknown flows.
- **DLL hijack static IAT** flags every import not in a 40-entry KnownDLLs list (so `msvcp140.dll`, `d3d11.dll`, `mscoree.dll`… are all "missing"). Have the collector send `System32` listing + registry KnownDLLs + SafeDllSearchMode; flag only imports absent from both; treat `SetDefaultDllDirectories/AddDllDirectory` in the IAT as mitigation; escalate when the exe is `requireAdministrator`/autoElevate.
- **.NET checks are mostly string greps.** `TypeNameHandling = All` can never appear as text in compiled IL (dead check); `BinaryFormatter` substring hits framework/third-party DLLs; strong-name signing is not a security control (noise). Use `dnfile` (pure Python) to read TypeRef/MemberRef/`#US`, and check IL for `set_TypeNameHandling` with non-zero constant, `Assembly.Load(byte[])`, `Process.Start`, `ServerCertificateValidationCallback` returning true, hard-coded keys in `#US`. Move UAC-manifest check to *all* PE files (currently skipped for native EXEs).
- **Java checks** use `.*` across raw class bytes (constant-pool entries are length-prefixed, so it misses/backtracks). Parse the constant pool; recurse into nested JARs (`BOOT-INF/lib`, `WEB-INF/lib`); add empty `X509TrustManager`, `HostnameVerifier` returning true.
**Medium**
- SCA native baselines are hard-coded single numbers (OpenSSL `3.0.15` makes `3.1.0` look safe). Move to `config/baselines.yaml` keyed by *branch* with EOL flags, refresh via script (OSV / endoflife.date); Electron `MIN_SAFE_ELECTRON_MAJOR=31` will rot the same way. Add banners for Chromium/CEF, Qt, libpng, libxml2, PCRE, FreeType, Java/.NET runtime.
- Trivy/Grype: failures (no DB offline, timeout, bad JSON) are swallowed or abort the stage before native fingerprinting runs; `subprocess.run(timeout=)` raises `TimeoutExpired` out of the signature loop and loses all remaining files. Wrap per-file/per-tool; report as Tooling Gap with reason. Group CVEs per package; add KEV/EPSS enrichment.
- `signature_audit`: one `signtool` process per file (slow); catalog-signed OS files; SHA-1 digest not flagged. Use a thread pool.
- Every module re-walks and re-reads every file (6x I/O). Build one `ScanContext` inventory (path, size, sha256, magic type, cached PE/ELF parse, cached strings) and let modules subscribe.
- PCAP: no TCP reassembly (headers split across segments are missed), IPv4/Ethernet only in fallback, no VLAN, no PCAPNG, `rdpcap` loads whole file (use `PcapReader`), HTTP updater regex requires `Host:` immediately after the request line. No SMB/NTLM, LDAP simple bind, FTP/Telnet/SNMP detection; no extraction of SNI/IP:port to feed the TLS inspector.
- TLS: only the *negotiated* cipher is tested, so weak suites that are merely enabled are missed; endpoints without explicit port skipped; uses OS trust store (internal CAs = false "untrusted"); no key size / SHA-1 / SAN / expiry-soon. Call `sslyze`/`testssl.sh` when present, parse its JSON.
- SARIF: `artifactLocation.uri` receives raw Windows paths/IPs (use file URIs or logical locations); no `partialFingerprints`; `executionSuccessful` is always `True` even with module errors; evidence is embedded verbatim.
- `memory_retention`: counts hits but does not distinguish live heap vs freed pages (parse minidump memory-info list), and searches only UTF-8/UTF-16LE (add base64, URL-encoding, `Basic` header form).
**Low** — unused imports/variables (pyflakes), `ipc_uri_audit` ignores `command`, 14 blind `except Exception` blocks hide real faults, `_run_stage` uses one `check_id` per stage so errors are attributed loosely.

## 3. What was added to cut manual testing
| Capability | File | Replaces manual step |
|---|---|---|
| Synthetic weak target (PE stub, config w/ DB string, log w/ PAN/Aadhaar, ASAR, PCAP, Procmon CSV, dump, host evidence) with expected results | `scripts/create_demo_target.py` | Hand-building a lab app per regression run |
| 14-test pytest suite incl. negative controls (11 of them fail on the original code) + E2E + CI gate | `tests/` | Eyeballing reports after each change |
| One-command self-test | `scripts/run_selftest.sh` | |
| CI gate `--fail-on`, `--live-host`, `--no-active-probe` | `analyzer/tirtcp.py` | |
| Baseline diff (new/fixed), ranking, coverage warnings, auto-generated manual worklist (accesschk / reg query / Procmon filters / playbook steps) | `scripts/triage_findings.py` | Re-reading the whole report each retest; writing test commands by hand |
| SDDL/DACL classifier for pipes, COM AppIDs, services, files | `analyzer/core/sddl.py` | "Run accesschk/dcomcnfg and read the ACL" — collector only needs to dump SDDL strings |
| Checksum validators (Luhn, Verhoeff, PAN) | `analyzer/core/validators.py` | Triage of PII false positives |

### Suggested next automation (highest manual-effort reduction first)
1. **Collector v2** (stdlib only): dump SDDL for every app pipe/service/COM AppID/install dir (`Get-Acl`), service unquoted-path flags, `System32` list, KnownDLLs, SafeDllSearchMode, Run keys, firewall listeners (`netstat -ano` owner PID), then feed `sddl.classify()` so `named_pipes`, `com_dcom_appids`, `insecure_services` become Pass/Fail instead of "Manual Required".
2. **Auto Procmon**: collector runs `procmon /Quiet /BackingFile` for a scripted launch (or accepts a UI-Automation/pywinauto flow), converts PML->CSV, then runs the DLL-hijack parser plus a *correlation* step (NAME NOT FOUND in writable dir followed by SUCCESS elsewhere = hijackable; never found anywhere = phantom).
3. **Traffic -> TLS loop**: parse SNI/IPs from the PCAP, de-duplicate, intersect with `--scope-file`, then run the TLS inspector/sslyze on only those endpoints.
4. **Pinning check without Burp clicking**: mitmproxy in transparent mode in the lab VM; script launches the client, records whether the app completes a handshake with the proxy CA installed (pass/fail with confidence).
5. **Updater integrity test**: local HTTP server + modified manifest/installer; verify the client rejects unsigned/downgraded payloads (the highest-value thick-client logic flaw, currently only inferred from cleartext URLs).
6. **Frida harness** (opt-in, gated like Phase 4): hook `CryptProtectData`, `CertVerifyCertificateChainPolicy`, `LoadLibrary*`, `CreateProcess`, `RegSetValue` to log crypto/DLL/exec behaviour during a scripted session; output merges into the same schema.
7. **Business-logic fuzz harness** for non-HTTP protocols once the PCAP is parsed (replay with mutated fields, compare responses) — the part that is manual everywhere today.
8. Make `tests/` the gate: add each real engagement's anonymised false-positive/negative as a fixture.

## 4. How to apply
`patch -p1 < tirtcp_fixes.patch` against the original tree (CRLF preserved), or use the full tree in `TIRtcp_enhanced.zip`.
`pip install -e ".[network,dev]" && bash scripts/run_selftest.sh`.
The compliance map in `tests/fixtures/` is a CWE-only **stub for tests**; keep using your real `config/compliance_map.yaml`.
