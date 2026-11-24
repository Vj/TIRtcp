#!/usr/bin/env python3
"""
TIRtcp Host Configuration & Evidence Collector (Windows)
Zero-dependency standard-library script (compatible with PyInstaller --onefile)
that gathers read-only host configuration metadata into host_evidence.json for
offline compliance and security posture analysis.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if platform.system() == "Windows":
    import winreg  # type: ignore
else:
    winreg = None  # type: ignore


LOW_PRIV_PRINCIPALS = (
    r"BUILTIN\Users",
    r"NT AUTHORITY\Authenticated Users",
    r"Everyone",
    r"BUILTIN\Guests",
)
WRITE_MASKS = ("(F)", "(M)", "(W)", "(WD)", "(AD)", "(WA)")
CRITICAL_EXTS = {".exe", ".dll", ".msi", ".sys", ".bat", ".ps1", ".cmd"}


def _is_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_cmd(cmd: List[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout or ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 1. Filesystem ACLs (Installation & Updater Paths)
# ---------------------------------------------------------------------------
def collect_weak_acls(target_dir: Path) -> List[Dict[str, Any]]:
    """Inspect target directory and critical binaries for write permissions granted to standard users."""
    weak_entries: List[Dict[str, Any]] = []
    if not target_dir.exists():
        return weak_entries

    paths_to_check: List[Path] = [target_dir]
    if target_dir.is_dir():
        for root, dirs, files in os.walk(target_dir):
            root_p = Path(root)
            for d in dirs:
                paths_to_check.append(root_p / d)
            for f in files:
                fp = root_p / f
                if fp.suffix.lower() in CRITICAL_EXTS:
                    paths_to_check.append(fp)

    for path_item in paths_to_check:
        out = _run_cmd(["icacls", str(path_item)], timeout=10)
        for line in out.splitlines():
            clean = line.strip()
            if not clean:
                continue
            for principal in LOW_PRIV_PRINCIPALS:
                if principal.lower() in clean.lower() and any(m in clean for m in WRITE_MASKS):
                    weak_entries.append(
                        {
                            "path": str(path_item),
                            "principal": principal,
                            "acl_entry": clean,
                        }
                    )
    return weak_entries


# ---------------------------------------------------------------------------
# 2. Windows Services (Unquoted Paths & SYSTEM Execution)
# ---------------------------------------------------------------------------
def collect_services(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Enumerate Windows services from HKLM\\SYSTEM\\CurrentControlSet\\Services."""
    findings: List[Dict[str, Any]] = []
    if winreg is None:
        return findings

    services_key_path = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path) as root_key:
            subkey_count, _, _ = winreg.QueryInfoKey(root_key)
            for idx in range(subkey_count):
                svc_name = winreg.EnumKey(root_key, idx)
                try:
                    with winreg.OpenKey(root_key, svc_name) as svc_key:
                        image_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                        svc_type, _ = winreg.QueryValueEx(svc_key, "Type")
                        try:
                            obj_name, _ = winreg.QueryValueEx(svc_key, "ObjectName")
                        except FileNotFoundError:
                            obj_name = "LocalSystem"

                        # Filter to Win32 services (0x10 = Own Process, 0x20 = Share Process)
                        if not (int(svc_type) & 0x30):
                            continue

                        img_str = str(image_path).strip()
                        if app_keyword and app_keyword.lower() not in (svc_name + img_str).lower():
                            continue

                        # Check unquoted path containing spaces (excluding system32/svchost)
                        exe_part = img_str.split(" -")[0].split(" /")[0].strip()
                        is_unquoted_space = (
                            not exe_part.startswith('"')
                            and " " in exe_part
                            and not exe_part.lower().startswith(r"c:\windows\system32")
                        )
                        runs_as_system = str(obj_name).lower() in ("localsystem", r"nt authority\system")

                        if is_unquoted_space or (app_keyword and runs_as_system):
                            issues: List[str] = []
                            if is_unquoted_space:
                                issues.append("Unquoted service binary path containing spaces")
                            if runs_as_system:
                                issues.append(f"Service runs with high privilege ({obj_name})")

                            findings.append(
                                {
                                    "service_name": svc_name,
                                    "bin_path": img_str,
                                    "account": str(obj_name),
                                    "unquoted_path": is_unquoted_space,
                                    "runs_as_system": runs_as_system,
                                    "issue": "; ".join(issues),
                                }
                            )
                except (FileNotFoundError, PermissionError, OSError):
                    continue
    except OSError:
        pass

    return findings


# ---------------------------------------------------------------------------
# 3. Scheduled Tasks (Non-Microsoft Tasks Running as SYSTEM)
# ---------------------------------------------------------------------------
def collect_scheduled_tasks(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query scheduled tasks via schtasks CSV output for non-OS SYSTEM tasks."""
    tasks: List[Dict[str, Any]] = []
    out = _run_cmd(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=25)
    if not out:
        return tasks

    import csv
    import io

    reader = csv.DictReader(io.StringIO(out))
    for row in reader:
        task_name = row.get("TaskName", "")
        if not task_name or task_name.startswith(r"\Microsoft\Windows"):
            continue
        run_as = row.get("Run As User", "")
        task_to_run = row.get("Task To Run", "")

        if app_keyword and app_keyword.lower() not in (task_name + task_to_run).lower():
            continue

        if "SYSTEM" in run_as.upper() or app_keyword:
            tasks.append(
                {
                    "task_name": task_name,
                    "task_to_run": task_to_run,
                    "run_as_user": run_as,
                    "status": row.get("Status", ""),
                }
            )
    return tasks


# ---------------------------------------------------------------------------
# 4. Named Pipes Inventory
# ---------------------------------------------------------------------------
def collect_named_pipes(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """List active Windows Named Pipes under \\\\.\\pipe\\."""
    pipes: List[Dict[str, Any]] = []
    try:
        pipe_names = os.listdir(r"\\.\pipe\\")
    except OSError:
        return pipes

    for name in sorted(pipe_names):
        if app_keyword and app_keyword.lower() not in name.lower():
            continue
        full_pipe = rf"\\.\pipe\{name}"
        pipes.append({"pipe_name": name, "full_path": full_pipe})
    return pipes


# ---------------------------------------------------------------------------
# 5. COM / DCOM AppID Configurations
# ---------------------------------------------------------------------------
def collect_com_dcom(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Inspect HKLM\\SOFTWARE\\Classes\\AppID for custom DCOM Launch/Access permissions and RunAs identity."""
    dcom_entries: List[Dict[str, Any]] = []
    if winreg is None:
        return dcom_entries

    appid_root = r"SOFTWARE\Classes\AppID"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, appid_root) as root:
            count, _, _ = winreg.QueryInfoKey(root)
            for idx in range(count):
                sub_name = winreg.EnumKey(root, idx)
                if not sub_name.startswith("{"):
                    continue
                try:
                    with winreg.OpenKey(root, sub_name) as app_key:
                        try:
                            desc, _ = winreg.QueryValueEx(app_key, "")
                        except FileNotFoundError:
                            desc = ""

                        if app_keyword and app_keyword.lower() not in str(desc).lower():
                            continue

                        has_launch_perm = False
                        has_access_perm = False
                        run_as = None
                        try:
                            winreg.QueryValueEx(app_key, "LaunchPermission")
                            has_launch_perm = True
                        except FileNotFoundError:
                            pass
                        try:
                            winreg.QueryValueEx(app_key, "AccessPermission")
                            has_access_perm = True
                        except FileNotFoundError:
                            pass
                        try:
                            run_as, _ = winreg.QueryValueEx(app_key, "RunAs")
                        except FileNotFoundError:
                            pass

                        if has_launch_perm or has_access_perm or run_as or app_keyword:
                            dcom_entries.append(
                                {
                                    "appid": sub_name,
                                    "description": str(desc),
                                    "custom_launch_permission": has_launch_perm,
                                    "custom_access_permission": has_access_perm,
                                    "run_as": str(run_as) if run_as else None,
                                }
                            )
                except OSError:
                    continue
    except OSError:
        pass
    return dcom_entries


# ---------------------------------------------------------------------------
# 6. Custom URI Protocol Handlers (e.g., myapp://)
# ---------------------------------------------------------------------------
def collect_custom_uri_handlers(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Enumerate registered URL protocol schemes in HKCR and HKLM\\SOFTWARE\\Classes."""
    handlers: List[Dict[str, Any]] = []
    if winreg is None:
        return handlers

    builtin_schemes = {"http", "https", "mailto", "ftp", "file", "tel", "ms-settings", "ms-windows-store"}
    classes_path = r"SOFTWARE\Classes"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, classes_path) as root:
            count, _, _ = winreg.QueryInfoKey(root)
            for idx in range(count):
                scheme = winreg.EnumKey(root, idx)
                if scheme.startswith(".") or scheme.lower() in builtin_schemes:
                    continue
                try:
                    with winreg.OpenKey(root, scheme) as scheme_key:
                        # A custom URI handler defines the "URL Protocol" value
                        winreg.QueryValueEx(scheme_key, "URL Protocol")
                        cmd_str = ""
                        try:
                            with winreg.OpenKey(scheme_key, r"shell\open\command") as cmd_key:
                                cmd_val, _ = winreg.QueryValueEx(cmd_key, "")
                                cmd_str = str(cmd_val)
                        except FileNotFoundError:
                            pass

                        if app_keyword and app_keyword.lower() not in (scheme + cmd_str).lower():
                            continue

                        # Flag unquoted %1 argument passing (common argument injection vector)
                        unquoted_arg = bool(re.search(r'(?<!")%1(?!")', cmd_str))
                        handlers.append(
                            {
                                "scheme": scheme,
                                "command": cmd_str,
                                "unquoted_url_argument": unquoted_arg,
                            }
                        )
                except (FileNotFoundError, OSError):
                    continue
    except OSError:
        pass
    return handlers


# ---------------------------------------------------------------------------
# 7. Installed Software Inventory (for Offline Dependency / Version Context)
# ---------------------------------------------------------------------------
def collect_installed_software() -> List[Dict[str, str]]:
    """Read DisplayName and DisplayVersion from Windows Uninstall registry keys."""
    software: List[Dict[str, str]] = []
    if winreg is None:
        return software

    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    seen: set[tuple[str, str]] = set()
    for hive, reg_path in uninstall_paths:
        try:
            with winreg.OpenKey(hive, reg_path) as root:
                count, _, _ = winreg.QueryInfoKey(root)
                for idx in range(count):
                    sub = winreg.EnumKey(root, idx)
                    try:
                        with winreg.OpenKey(root, sub) as item:
                            name, _ = winreg.QueryValueEx(item, "DisplayName")
                            try:
                                ver, _ = winreg.QueryValueEx(item, "DisplayVersion")
                            except FileNotFoundError:
                                ver = "unknown"
                            try:
                                publisher, _ = winreg.QueryValueEx(item, "Publisher")
                            except FileNotFoundError:
                                publisher = ""

                            key = (str(name).strip(), str(ver).strip())
                            if key[0] and key not in seen:
                                seen.add(key)
                                software.append(
                                    {
                                        "name": key[0],
                                        "version": key[1],
                                        "publisher": str(publisher).strip(),
                                    }
                                )
                    except (FileNotFoundError, OSError):
                        continue
        except OSError:
            continue

    return sorted(software, key=lambda x: x["name"].lower())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="collect_host",
        description="TIRtcp Zero-Dependency Windows Host Evidence Collector",
    )
    parser.add_argument(
        "--app-dir",
        type=Path,
        required=True,
        help="Target thick-client installation directory to inspect ACLs.",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Optional application keyword filter for services, tasks, pipes, COM, and URI handlers.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("host_evidence.json"),
        help="Output JSON evidence bundle path (default: host_evidence.json).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if platform.system() != "Windows":
        print(
            "[!] Warning: collect_host.py is designed for Windows target hosts. "
            "Windows registry/service collectors will emit empty lists on non-Windows OS.",
            file=sys.stderr,
        )

    evidence: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "os_release": platform.platform(),
        "collector_elevated_admin": _is_admin(),
        "target_app_dir": str(args.app_dir),
        "filter_keyword": args.filter,
        "weak_acls": collect_weak_acls(args.app_dir),
        "insecure_services": collect_services(args.filter),
        "scheduled_tasks": collect_scheduled_tasks(args.filter),
        "named_pipes": collect_named_pipes(args.filter),
        "com_dcom_appids": collect_com_dcom(args.filter),
        "custom_uri_handlers": collect_custom_uri_handlers(args.filter),
        "installed_software": collect_installed_software(),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"[+] Host evidence written to: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())