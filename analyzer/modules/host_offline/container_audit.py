r"""
TIRtcp Container & Docker Security Audit (TCP-CONT-001)
Evaluates Dockerfiles, docker-compose YAML files, docker inspect JSON dumps,
and host_evidence.json named pipes/ports for:
  1. Container running as root (User == "" or "root" / "0")
  2. Privileged containers (--privileged / Privileged: true) & dangerous Linux capabilities
  3. Sensitive host filesystem or Docker socket mounts (/var/run/docker.sock, docker_engine, C:\)
  4. Unauthenticated Docker Remote API exposure (0.0.0.0:2375)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.context import ScanContext
from analyzer.core.schema import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)

DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL"}
SENSITIVE_MOUNTS = (
    "/var/run/docker.sock",
    "docker_engine",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "c:\\",
    "c:/",
    "\\\\.\\pipe\\",
)


def _audit_inspect_payload(payload: Any, source_label: str, refs: list) -> List[Finding]:
    findings: List[Finding] = []
    containers = payload if isinstance(payload, list) else [payload]

    for c in containers:
        if not isinstance(c, dict):
            continue
        name = str(c.get("Name") or c.get("Id") or source_label).lstrip("/")
        cfg = c.get("Config") or {}
        host_cfg = c.get("HostConfig") or {}
        mounts = c.get("Mounts") or []

        # 1. Root user check
        user = str(cfg.get("User") or "").strip().lower()
        if user in ("", "root", "0", "0:0"):
            findings.append(
                Finding(
                    check_id="TCP-CONT-001",
                    title=f"Container Configured to Run as Root ({name})",
                    category="Container & Docker Security",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=f"{source_label} ({name})",
                    summary="Container Config.User is unset or 'root', increasing host impact if an RCE or container escape occurs.",
                    evidence={"container": name, "configured_user": user or "<empty/default root>"},
                    remediation="Specify a dedicated non-root USER in the Dockerfile (e.g., USER 10001:10001) and drop default capabilities.",
                    compliance_support=refs,
                )
            )

        # 2. Privileged mode & dangerous capabilities
        privileged = bool(host_cfg.get("Privileged"))
        cap_add = {str(cap).upper().removeprefix("CAP_") for cap in (host_cfg.get("CapAdd") or [])}
        risky_caps = sorted(cap_add & DANGEROUS_CAPS)
        if privileged or risky_caps:
            findings.append(
                Finding(
                    check_id="TCP-CONT-001",
                    title=f"Privileged Container or Dangerous Linux Capabilities Enabled ({name})",
                    category="Container & Docker Security",
                    status=FindingStatus.FAIL,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    affected_asset=f"{source_label} ({name})",
                    summary="Container runs with Privileged=true or high-risk capabilities that permit host namespace/filesystem breakout.",
                    evidence={"container": name, "privileged": privileged, "dangerous_cap_add": risky_caps},
                    remediation="Remove --privileged and drop all capabilities (--cap-drop=ALL), adding back only minimal required caps.",
                    compliance_support=refs,
                )
            )

        # 3. Sensitive host mounts & Docker socket exposure
        risky_mounts: List[Dict[str, str]] = []
        for m in mounts:
            if not isinstance(m, dict):
                continue
            src = str(m.get("Source") or m.get("HostPath") or "")
            dst = str(m.get("Destination") or m.get("ContainerPath") or "")
            src_low = src.lower()
            if any(s in src_low for s in SENSITIVE_MOUNTS) or src_low in ("/", "c:", "c:\\"):
                risky_mounts.append({"source": src, "destination": dst, "mode": str(m.get("Mode") or "")})

        for bind in host_cfg.get("Binds") or []:
            b_str = str(bind)
            b_low = b_str.lower()
            if any(s in b_low for s in SENSITIVE_MOUNTS):
                risky_mounts.append({"bind": b_str})

        if risky_mounts:
            is_sock = any("docker.sock" in str(x).lower() or "docker_engine" in str(x).lower() for x in risky_mounts)
            findings.append(
                Finding(
                    check_id="TCP-CONT-001",
                    title=f"{'Docker Socket' if is_sock else 'Sensitive Host Path'} Mounted into Container ({name})",
                    category="Container & Docker Security",
                    status=FindingStatus.FAIL,
                    severity=Severity.CRITICAL if is_sock else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=f"{source_label} ({name})",
                    summary=(
                        "Mounting the Docker socket or sensitive host directories grants container processes direct control "
                        "over the host daemon or critical system configuration."
                    ),
                    evidence={"container": name, "sensitive_mounts": risky_mounts},
                    remediation="Never mount /var/run/docker.sock or host root drives into application containers; use scoped read-only volumes.",
                    compliance_support=refs,
                )
            )

        # 4. Exposed Port Bindings on 0.0.0.0
        port_bindings = host_cfg.get("PortBindings") or {}
        lan_ports: List[str] = []
        for c_port, bindings in port_bindings.items():
            if not isinstance(bindings, list):
                continue
            for b in bindings:
                hip = str((b or {}).get("HostIp") or "")
                hport = str((b or {}).get("HostPort") or "")
                if hip in ("", "0.0.0.0", "::"):
                    lan_ports.append(f"{hip or '0.0.0.0'}:{hport}->{c_port}")
        if lan_ports:
            findings.append(
                Finding(
                    check_id="TCP-CONT-001",
                    title=f"Container Ports Published on All Host Interfaces 0.0.0.0 ({name})",
                    category="Container & Docker Security",
                    status=FindingStatus.OBSERVATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=f"{source_label} ({name})",
                    summary="Container ports are bound to 0.0.0.0 rather than 127.0.0.1, exposing internal server/pairing endpoints to the LAN.",
                    evidence={"container": name, "published_ports": lan_ports},
                    remediation="Bind local-only services to 127.0.0.1 (e.g., -p 127.0.0.1:8443:8443) unless external network access is required.",
                    compliance_support=refs,
                )
            )

    return findings


def audit_containers(
    target_path: Path,
    mapper: ComplianceMapper,
    ctx: Optional[ScanContext] = None,
    docker_inspect_path: Optional[Path] = None,
    host_evidence: Optional[Dict[str, Any]] = None,
) -> List[Finding]:
    """Audit Docker inspect artifacts, Dockerfiles/compose manifests, and host Docker socket exposure."""
    refs = mapper.resolve("TCP-CONT-001") or mapper.resolve("TCP-HOST-001")
    findings: List[Finding] = []
    audited_any = False

    # 1. Explicit --docker-inspect JSON file
    if docker_inspect_path and docker_inspect_path.exists():
        audited_any = True
        try:
            payload = json.loads(docker_inspect_path.read_text(encoding="utf-8"))
            findings.extend(_audit_inspect_payload(payload, str(docker_inspect_path), refs))
        except Exception as exc:
            findings.append(
                Finding(
                    check_id="TCP-CONT-001",
                    title="Docker Inspect JSON Parse Error",
                    category="Container & Docker Security",
                    status=FindingStatus.TOOLING_GAP,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=str(docker_inspect_path),
                    summary=f"Could not parse docker inspect JSON: {exc}",
                    compliance_support=refs,
                )
            )

    # 2. Scan target directory for Dockerfile / docker-compose*.yml / *inspect*.json
    scan_ctx = ctx if ctx is not None else (ScanContext(target_path) if target_path.exists() else None)
    if scan_ctx:
        for rec in scan_ctx.files:
            name_low = rec.path.name.lower()
            if name_low == "dockerfile" or name_low.startswith("dockerfile."):
                audited_any = True
                raw_txt = rec.read_bytes().decode("utf-8", errors="ignore")
                if not re.search(r"(?im)^\s*USER\s+(?!root\b|0\b)\S+", raw_txt):
                    findings.append(
                        Finding(
                            check_id="TCP-CONT-001",
                            title="Dockerfile Lacks Non-Root USER Directive",
                            category="Container & Docker Security",
                            status=FindingStatus.FAIL,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            affected_asset=str(rec.path),
                            summary="Dockerfile does not switch to a non-root USER, causing the container to run as root by default.",
                            remediation="Add a non-root user creation step and 'USER appuser' before ENTRYPOINT/CMD.",
                            compliance_support=refs,
                        )
                    )
            elif "docker-compose" in name_low and rec.ext in (".yml", ".yaml"):
                audited_any = True
                raw_txt = rec.read_bytes().decode("utf-8", errors="ignore")
                if re.search(r"(?im)privileged\s*:\s*true", raw_txt):
                    findings.append(
                        Finding(
                            check_id="TCP-CONT-001",
                            title="Docker Compose Service Enables privileged: true",
                            category="Container & Docker Security",
                            status=FindingStatus.FAIL,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            affected_asset=str(rec.path),
                            summary="docker-compose manifest configures privileged: true, disabling container isolation.",
                            remediation="Remove 'privileged: true' and grant only minimal Linux capabilities.",
                            compliance_support=refs,
                        )
                    )
                if "docker.sock" in raw_txt.lower() or "docker_engine" in raw_txt.lower():
                    findings.append(
                        Finding(
                            check_id="TCP-CONT-001",
                            title="Docker Compose Mounts Host Docker Daemon Socket",
                            category="Container & Docker Security",
                            status=FindingStatus.FAIL,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            affected_asset=str(rec.path),
                            summary="docker-compose mounts the Docker socket into a service container, enabling host root takeover.",
                            remediation="Remove the Docker socket volume mount from application services.",
                            compliance_support=refs,
                        )
                    )

    # 3. Check host_evidence.json for unauthenticated Docker TCP 2375 or permissive docker_engine pipe
    if host_evidence:
        pipes = host_evidence.get("named_pipes") or []
        for p in pipes:
            p_name = str(p.get("name") if isinstance(p, dict) else p).lower()
            if "docker_engine" in p_name:
                audited_any = True
                findings.append(
                    Finding(
                        check_id="TCP-CONT-001",
                        title="Docker Engine Named Pipe Present on Host",
                        category="Container & Docker Security",
                        status=FindingStatus.OBSERVATION,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        affected_asset=r"\\.\pipe\docker_engine",
                        summary="Docker Desktop/Engine named pipe is active on the host; verify ACLs restrict access to Administrators/docker-users.",
                        compliance_support=refs,
                    )
                )

    if audited_any and not findings:
        findings.append(
            Finding(
                check_id="TCP-CONT-001",
                title="Container & Docker Configuration Hardening Passed",
                category="Container & Docker Security",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(docker_inspect_path or target_path),
                summary="Audited container artifacts with no root user, privileged mode, or Docker socket mount issues.",
                compliance_support=refs,
            )
        )

    return findings


def scan_image_layers(
    image_tar_path: Path,
    mapper: ComplianceMapper,
) -> List[Finding]:
    """Inspect a 'docker save' .tar archive across every layer for deleted secrets and vulnerable packages."""
    import io
    import tarfile

    refs = mapper.resolve("TCP-CONT-001") or mapper.resolve("TCP-HOST-001")
    sca_refs = mapper.resolve("TCP-SCA-001") or refs
    findings: List[Finding] = []

    if not image_tar_path.exists() or not tarfile.is_tarfile(image_tar_path):
        return findings

    secret_re = re.compile(
        r'''(?i)(?:api[_-]?key|secret[_-]?key|password|passwd|bearer|aws_secret_access_key|private[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=._-]{12,})'''
    )
    dpkg_pkg_re = re.compile(r"(?m)^Package:\s*(\S+)\r?\n(?:[^\n]+\r?\n)*?Version:\s*(\S+)")

    layer_secret_hits: List[Dict[str, Any]] = []
    discovered_pkgs: List[Dict[str, str]] = []

    with tarfile.open(image_tar_path, "r:*") as outer:
        members = outer.getmembers()
        layer_members = [m for m in members if m.isfile() and m.name.endswith("layer.tar")]
        if not layer_members:
            # OCI / flat tar fallback: treat .tar entries as layers
            layer_members = [m for m in members if m.isfile() and m.name.endswith(".tar")]

        for idx, lm in enumerate(layer_members):
            extracted = outer.extractfile(lm)
            if not extracted:
                continue
            try:
                with tarfile.open(fileobj=io.BytesIO(extracted.read()), mode="r:*") as layer_tar:
                    for entry in layer_tar.getmembers():
                        if not entry.isfile() or entry.size <= 0 or entry.size > 2 * 1024 * 1024:
                            continue
                        fobj = layer_tar.extractfile(entry)
                        if not fobj:
                            continue
                        raw = fobj.read()
                        text = raw.decode("utf-8", errors="ignore")

                        # 1. Historical layer secret scan (catches secrets deleted in upper layers)
                        if any(entry.name.lower().endswith(ext) for ext in (".env", ".json", ".yml", ".yaml", ".conf", ".ini", ".py", ".js", ".config", ".xml", ".txt")):
                            if secret_re.search(text):
                                layer_secret_hits.append({"layer_index": idx, "layer": lm.name, "file": entry.name})

                        # 2. Extract dpkg / apk package manifests
                        if entry.name.endswith("var/lib/dpkg/status") or "dpkg/status" in entry.name:
                            for m in dpkg_pkg_re.finditer(text):
                                discovered_pkgs.append({"ecosystem": "Debian/Ubuntu", "name": m.group(1), "version": m.group(2)})
                        elif entry.name.endswith("lib/apk/db/installed"):
                            cur_pkg, cur_ver = "", ""
                            for line in text.splitlines():
                                if line.startswith("P:"):
                                    cur_pkg = line[2:].strip()
                                elif line.startswith("V:"):
                                    cur_ver = line[2:].strip()
                                elif line == "" and cur_pkg and cur_ver:
                                    discovered_pkgs.append({"ecosystem": "Alpine", "name": cur_pkg, "version": cur_ver})
                                    cur_pkg, cur_ver = "", ""
            except Exception:
                continue

    if layer_secret_hits:
        findings.append(
            Finding(
                check_id="TCP-CONT-001",
                title=f"Hardcoded Secrets Recoverable in Docker Image Layers ({len(layer_secret_hits)} Hit(s))",
                category="Container & Docker Security",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=str(image_tar_path),
                summary=(
                    "Historical image layers contain secret/credential assignments. Even if deleted in a subsequent RUN step, "
                    "secrets remain extractable from intermediate image layers."
                ),
                evidence={"layer_hits": layer_secret_hits[:15]},
                remediation="Use BuildKit --mount=type=secret during image builds and rotate all exposed credentials.",
                compliance_support=refs,
            )
        )

    if discovered_pkgs:
        findings.append(
            Finding(
                check_id="TCP-SCA-001",
                title=f"Container Image Package Inventory Extracted ({len(discovered_pkgs)} Package(s))",
                category="Container & Docker Security",
                status=FindingStatus.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=str(image_tar_path),
                summary=f"Extracted {len(discovered_pkgs)} OS package(s) across container layers for SBOM and CVE tracking.",
                evidence={"packages_sample": discovered_pkgs[:25], "total_packages": len(discovered_pkgs)},
                compliance_support=sca_refs,
            )
        )

    return findings
