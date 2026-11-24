"""
TIRtcp Host & Offline Audit Module: IPC, Named Pipes, COM/DCOM, Scheduled Tasks & URI Handlers
Evaluates offline host_evidence.json sections:
- custom_uri_handlers (unquoted %1 argument passing & handler exposure)
- named_pipes (application IPC endpoints requiring DACL / impersonation review)
- com_dcom_appids (custom LaunchPermission/AccessPermission & RunAs elevation context)
- scheduled_tasks (non-OS tasks executing under NT AUTHORITY\\SYSTEM)
Maps to check_id: TCP-IPC-001 (with fallback compliance refs if not in compliance_map.yaml)
"""

from __future__ import annotations

from typing import Any, Dict, List

from analyzer.core.compliance_loader import ComplianceMapper
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
        command = item.get("command", "")
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
                        f"Registered URI protocol '{scheme}://' invokes its target executable with an "
                        "unquoted %1 parameter, enabling argument injection when invoked via browsers or external apps."
                    ),
                    evidence=item,
                    remediation=(
                        f'Enclose the %1 placeholder in double quotes inside the registry command '
                        f'(e.g., "C:\\Path\\To\\App.exe" "%1") and strictly validate/parse URI arguments inside the client.'
                    ),
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
                    summary=(
                        f"Application registers custom URI scheme '{scheme}://'. While %1 is quoted, "
                        "the handler logic must be reviewed for unsafe parameter handling or state-changing actions without user confirmation."
                    ),
                    evidence=item,
                    remediation="Ensure custom URI handlers enforce strict input validation and require user confirmation for privileged actions.",
                    compliance_support=compliance_refs,
                    manual_playbook=PlaybookRef(
                        tool="API Monitor / Source Review",
                        objective=f"Verify how '{scheme}://' URI arguments are parsed and sanitized on application startup.",
                        steps=[
                            "Inspect the command-line argument parser in the client entry point (Main / WinMain).",
                            "Confirm that unknown flags or unexpected URI paths are rejected before triggering sensitive workflows.",
                        ],
                    ),
                )
            )
    return findings


def _audit_named_pipes(
    pipes: List[Dict[str, Any]],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    if not pipes:
        return []

    pipe_names = [p.get("full_path", p.get("pipe_name", "")) for p in pipes]
    return [
        Finding(
            check_id="TCP-IPC-001",
            title=f"Application Named Pipes Detected ({len(pipes)} Active IPC Endpoint(s))",
            category="IPC & Protocol Handlers",
            status=FindingStatus.MANUAL_REQUIRED,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_asset=", ".join(pipe_names[:5]),
            summary=(
                "Application exposes Windows Named Pipe(s) for local IPC. Overly permissive pipe DACLs "
                "(e.g., Everyone or Authenticated Users with write access) can allow unauthorized local command injection."
            ),
            evidence={"named_pipes": pipes[:25]},
            remediation=(
                "Initialize Named Pipes with explicit SECURITY_ATTRIBUTES restricting read/write access "
                "to the current user SID or Administrators, and reject client impersonation unless strictly required."
            ),
            compliance_support=compliance_refs,
            manual_playbook=PlaybookRef(
                tool="AccessChk / Sysinternals Pipelist",
                objective="Verify DACLs on each discovered application Named Pipe.",
                steps=[
                    "Run `accesschk.exe -v \\\\.\\pipe\\<pipe_name>` on an authorized test system.",
                    "Confirm that 'Everyone' and 'BUILTIN\\Users' do not hold FILE_WRITE_DATA or GENERIC_ALL rights on privileged service pipes.",
                ],
            ),
        )
    ]


def _audit_com_dcom(
    dcom_entries: List[Dict[str, Any]],
    compliance_refs: List[ComplianceRef],
) -> List[Finding]:
    findings: List[Finding] = []
    for entry in dcom_entries:
        appid = entry.get("appid", "Unknown AppID")
        desc = entry.get("description") or appid
        run_as = entry.get("run_as")
        has_custom_perms = bool(
            entry.get("custom_launch_permission") or entry.get("custom_access_permission")
        )

        if run_as and "interactive user" not in run_as.lower():
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"COM/DCOM AppID Configured with Explicit RunAs Identity ({desc})",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\AppID\\{appid}",
                    summary=(
                        f"DCOM component '{desc}' ({appid}) is configured with RunAs='{run_as}'. "
                        "If LaunchPermission or AccessPermission grants rights to low-privileged users, "
                        "local privilege escalation across security boundaries may occur."
                    ),
                    evidence=entry,
                    remediation="Audit LaunchPermission and AccessPermission SDDL descriptors via dcomcnfg.exe and restrict activation to Administrators.",
                    compliance_support=compliance_refs,
                    manual_playbook=PlaybookRef(
                        tool="dcomcnfg.exe / OleViewDotNet",
                        objective=f"Inspect Launch and Access SDDL permissions for AppID {appid}.",
                        steps=[
                            "Open Component Services (`dcomcnfg.exe`) -> DCOM Config and locate the AppID.",
                            "Review 'Launch and Activation Permissions' and 'Access Permissions' under the Security tab to ensure standard users cannot activate the elevated COM server.",
                        ],
                    ),
                )
            )
        elif has_custom_perms:
            findings.append(
                Finding(
                    check_id="TCP-IPC-001",
                    title=f"COM/DCOM AppID Defines Custom Launch/Access Permissions ({desc})",
                    category="IPC & Protocol Handlers",
                    status=FindingStatus.MANUAL_REQUIRED,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    affected_asset=f"HKLM\\SOFTWARE\\Classes\\AppID\\{appid}",
                    summary=f"DCOM component '{desc}' overrides default system COM ACLs with custom binary SDDL descriptors.",
                    evidence=entry,
                    remediation="Verify custom SDDL descriptors adhere to least privilege.",
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
                        f"under '{run_as}'. Any weak ACL on the target binary or arguments enables local privilege escalation."
                    ),
                    evidence=task,
                    remediation=(
                        "Run scheduled tasks under a dedicated low-privileged service account or LocalService "
                        "instead of SYSTEM, and ensure the target executable and parent directory are writable only by Administrators."
                    ),
                    compliance_support=compliance_refs,
                )
            )
    return findings


def audit_ipc_and_handlers(
    host_evidence: Dict[str, Any],
    mapper: ComplianceMapper,
) -> List[Finding]:
    """
    Evaluate offline host_evidence.json for custom URI protocol handlers, Named Pipes,
    COM/DCOM AppID permissions, and SYSTEM scheduled tasks.
    """
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
                title="No Exposed Custom URI Handlers, Elevated COM AppIDs, or SYSTEM Tasks Flagged",
                category="IPC & Protocol Handlers",
                status=FindingStatus.VERIFIED_PASS,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_asset=host_evidence.get("hostname", "Offline Host Bundle"),
                summary=(
                    "Evaluated host_evidence.json IPC and handler sections; zero unquoted URI handlers "
                    "or SYSTEM-privileged application tasks were flagged."
                ),
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