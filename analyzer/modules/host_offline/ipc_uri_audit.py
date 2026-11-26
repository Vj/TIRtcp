"""
TIRtcp Host & Offline Audit Module: IPC, Named Pipes, COM/DCOM, Scheduled Tasks & URI Handlers
Integrates analyzer.core.sddl.classify() to turn SDDL-backed Pipe and COM/DCOM checks into
automated Pass/Fail verdicts.
"""

from __future__ import annotations

from typing import Any, Dict, List

from analyzer.core.compliance_loader import ComplianceMapper
from analyzer.core.sddl import classify as classify_sddl
from analyzer.core.schema import (
    ComplianceRef,
    ComplianceRelation,
    Confidence,
    Finding,
    FindingStatus,
    PlaybookRef,
    Severity,
)


def _resolve_ipc_compliance(mapper: ComplianceMapper) -> List[ComplianceRef]:
    refs = mapper.resolve("TCP-IPC-001")
    if refs:
        return refs
    return [
        ComplianceRef(
            framework="CWE",
            version="4.16",
            control_id="CWE-284 / CWE-88",
            control_title="Improper Access Control / Improper Neutralization of Argument Delimiters",
            relation=ComplianceRelation.DIRECT,
            scope="general",
        ),
        ComplianceRef(
            framework="OWASP_MASVS",
            version="2.1.0",
            control_id="MASVS-PLATFORM-1",
            control_title="Secure Inter-Process Communication and Custom URI Handling",
            relation=ComplianceRelation.SUPPORTS,
            scope="general",
        ),
    ]


def _audit_custom_uri_handlers(
    handlers: List[Dict[str, Any]],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    for item in handlers:
        scheme = item.get("scheme", "unknown")
        unquoted = bool(item.get("unquoted_url_argument", False))

        if unquoted:
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"Custom URI Handler Passes Unquoted %1 Argument ({scheme}://)",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\{scheme}\\shell\\open\\command",
                    summary=(
                        f"Registered URI protocol '{scheme}://' invokes its executable with an unquoted %1 "
                        "parameter, enabling argument injection via browsers or external applications."
                    ),
                    evidence=item,
                    remediation=f'Enclose %1 in double quotes (e.g., "C:\\Path\\To\\App.exe" "%1") and validate URI parameters.',
                    compliance_support=compliance_refs,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"Custom URI Protocol Handler Registered ({scheme}://)",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\{scheme}",
                    summary=f"Application registers custom URI scheme '{scheme}://' with quoted %1; review handler logic for unsafe actions.",
                    evidence=item,
                    compliance_support=compliance_refs,
                )
            )
    return findings


def _audit_named_pipes(
    pipes: List[Dict[str, Any]],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    unclassified_pipes: List[Dict[str, Any]] = []
    verified_pipes = 0

    for p in pipes:
        full_path = p.get("full_path", p.get("pipe_name", "Unknown Pipe"))
        sddl = p.get("sddl")

        if sddl:
            verdict = classify_sddl(sddl)
            if verdict["risky"] or verdict["has_null_dacl"]:
                findings.append(
                    Finding(
                        check_id="TCP-IPC-001",
                        title=f"Permissive Named Pipe DACL Allows Low-Privileged Write ({full_path})",
                        category="IPC & Protocol Handlers",
                        status=FindingStatus.FAIL,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_asset=full_path,
                        summary=(
                            f"Named Pipe '{full_path}' grants write/generic rights to low-privileged principals "
                            "or uses a NULL DACL, allowing unauthorized local command injection."
                        ),
                        evidence={"pipe": full_path, "sddl": sddl, "sddl_analysis": verdict},
                        remediation="Initialize Named Pipes with explicit SECURITY_ATTRIBUTES restricting access to the current user SID or Administrators.",
                        compliance_support=compliance_refs,
                    )
                )
            else:
                verified_pipes += 1
        else:
            unclassified_pipes.append(p)

    if verified_pipes > 0 and not findings and not unclassified_pipes:
        findings.append(
            Finding(
                check_id="TCP-IPC-001",
                title=f"Restrictive Named Pipe DACLs Verified via SDDL ({verified_pipes} Pipe(s))",
                category="IPC & Protocol Handlers",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=", ".join(p.get("full_path", "") for p in pipes[:5]),
                summary=f"Evaluated SDDL security descriptors for {verified_pipes} Named Pipe(s); no low-privileged write ACEs detected.",
                evidence={"verified_pipe_count": verified_pipes},
                compliance_support=compliance_refs,
            )
        )

    if unclassified_pipes:
        pipe_names = [p.get("full_path", p.get("pipe_name", "")) for p in unclassified_pipes]
        findings.append(
            Finding(
                check_id="TCP-IPC-001",
                title=f"Named Pipes Without SDDL Metadata ({len(unclassified_pipes)} Endpoint(s))",
                category="IPC & Protocol Handlers",
                status=FindingStatus.MANUAL_REQUIRED,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                affected_asset=", ".join(pipe_names[:5]),
                summary="Collector could not read DACL SDDL for these Named Pipe(s) (often due to access restrictions); verify manually.",
                evidence={"named_pipes": unclassified_pipes[:25]},
                manual_playbook=PlaybookRef(
                    tool="Sysinternals AccessChk",
                    objective="Inspect DACLs on Named Pipes whose SDDL could not be dumped.",
                    steps=[
                        "Run `accesschk.exe -accepteula -v \\\\.\\pipe\\<pipe_name>` on an authorized test host.",
                        "Confirm Everyone and BUILTIN\\Users do not hold FILE_WRITE_DATA or GENERIC_ALL rights.",
                    ],
                ),
                compliance_support=compliance_refs,
            )
        )

    return findings


def _audit_com_dcom(
    dcom_entries: List[Dict[str, Any]],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    for entry in dcom_entries:
        appid = entry.get("appid", "Unknown AppID")
        desc = entry.get("description") or appid
        run_as = entry.get("run_as")
        launch_sddl = entry.get("launch_permission_sddl")
        access_sddl = entry.get("access_permission_sddl")

        risky_details: Dict[str, Any] = {}
        if launch_sddl:
            l_res = classify_sddl(launch_sddl)
            if l_res["risky"] or l_res["has_null_dacl"]:
                risky_details["launch_permission"] = l_res
        if access_sddl:
            a_res = classify_sddl(access_sddl)
            if a_res["risky"] or a_res["has_null_dacl"]:
                risky_details["access_permission"] = a_res

        if risky_details:
            is_elevated_runas = bool(run_as and "interactive user" not in run_as.lower())
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"Permissive COM/DCOM Launch or Access SDDL ({desc})",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH if is_elevated_runas else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\AppID\\{appid}",
                    summary=(
                        f"DCOM AppID '{desc}' ({appid}) grants launch/access rights to low-privileged principals"
                        + (f" while configured with RunAs='{run_as}'." if run_as else ".")
                    ),
                    evidence={"entry": entry, "sddl_analysis": risky_details},
                    remediation="Restrict DCOM LaunchPermission and AccessPermission SDDL descriptors via dcomcnfg.exe to Administrators.",
                    compliance_support=compliance_refs,
                )
            )
        elif launch_sddl or access_sddl:
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"COM/DCOM AppID Permissions Hardened via SDDL ({desc})",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.VERIFIED_PASS,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\AppID\\{appid}",
                    summary=f"Evaluated Launch/Access SDDL for '{desc}'; no low-privileged ACEs detected.",
                    evidence=entry,
                    compliance_support=compliance_refs,
                )
            )
        elif run_as and "interactive user" not in run_as.lower():
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"COM/DCOM AppID Uses Explicit RunAs Identity Without Custom SDDL ({desc})",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\AppID\\{appid}",
                    summary=f"DCOM component '{desc}' specifies RunAs='{run_as}' and inherits default machine COM ACLs.",
                    evidence=entry,
                    compliance_support=compliance_refs,
                )
            )
    return findings


def _audit_scheduled_tasks(
    tasks: List[Dict[str, Any]],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    for task in tasks:
        run_as = task.get("run_as_user", "")
        if "SYSTEM" in run_as.upper():
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"Application Scheduled Task Runs as SYSTEM ({task.get('task_name', 'Unknown')})",
                    category="Host & Privilege Boundaries",
                    status=FindingStatus.FAIL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=task.get("task_to_run", task.get("task_name", "Scheduled Task")),
                    summary=(
                        f"Scheduled task '{task.get('task_name')}' executes '{task.get('task_to_run')}' "
                        f"under '{run_as}'."
                    ),
                    evidence=task,
                    remediation="Run scheduled tasks under a least-privilege service account and lock down target binary ACLs.",
                    compliance_support=compliance_refs,
                )
            )
    return findings


def audit_ipc_and_handlers(
    host_evidence: Dict[str, Any],
    mapper: ComplianceMapper,
) -> List[Finding]:
    compliance_refs = _resolve_ipc_compliance(mapper)
    findings: List[Finding] = []

    uri_handlers = host_evidence.get("custom_uri_handlers", [])
    named_pipes = host_evidence.get("named_pipes", [])
    com_dcom = host_evidence.get("com_dcom_appids", [])
    sched_tasks = host_evidence.get("scheduled_tasks", [])

    findings.extend(_audit_custom_uri_handlers(uri_handlers, compliance_refs))
    findings.extend(_audit_named_pipes(named_pipes, compliance_refs))
    findings.extend(_audit_com_dcom(com_dcom, compliance_refs))
    findings.extend(_audit_scheduled_tasks(sched_tasks, compliance_refs))

    if not findings:
        findings.append(
            Finding(
                check_id="TCP-IPC-001",
                title="No Exposed Custom URI Handlers, Risky COM AppIDs, or SYSTEM Tasks Flagged",
                category="IPC & Protocol Handlers",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=host_evidence.get("hostname", "Offline Host Bundle"),
                summary="Evaluated host_evidence.json IPC and handler sections with zero risky configurations flagged.",
                evidence={
                    "uri_handlers_checked": len(uri_handlers),
                    "named_pipes_checked": len(named_pipes),
                    "com_appids_checked": len(com_dcom),
                    "scheduled_tasks_checked": len(sched_tasks),
                },
                compliance_support=compliance_refs,
            )
        )

    return findings