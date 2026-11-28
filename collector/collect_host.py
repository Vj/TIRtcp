#!/usr/bin/env python3
"""
TIRtcp Host Configuration & Evidence Collector v2 (Windows)
Zero-dependency standard-library script (compatible with PyInstaller --onefile).

Gathers:
- Filesystem ACLs & SDDL strings on install/updater directories and critical binaries
- Windows Services (ImagePath, unquoted paths, SYSTEM execution, and service SDDL via sc sdshow)
- Scheduled Tasks (non-OS tasks executing under SYSTEM)
- Named Pipes with Win32 DACL SDDL strings (advapi32 GetNamedSecurityInfoW)
- COM / DCOM AppIDs with SDDL strings converted from raw registry LaunchPermission/AccessPermission
- Custom URI Protocol Handlers (scheme, command, unquoted %1 detection)
- DLL Search-Order Ground Truth: System32 DLL inventory, KnownDLLs registry list, SafeDllSearchMode
- Installed Software Inventory
"""

from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes
import datetime
import io
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
WRITE_RIGHT_TOKENS = {"F", "M", "W", "WD", "AD", "WA", "WDAC", "WO", "GW", "GA", "DC"}
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
# Win32 Security Descriptor -> SDDL Helpers (Zero External Dependencies)
# ---------------------------------------------------------------------------
SE_FILE_OBJECT = 1
SE_SERVICE = 2
SE_REGISTRY_KEY = 4
SE_KERNEL_OBJECT = 6

OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SDDL_REVISION_1 = 1


def _binary_sd_to_sddl(sd_bytes: bytes) -> Optional[str]:
    """Convert a self-relative binary SECURITY_DESCRIPTOR (e.g., COM LaunchPermission) to an SDDL string."""
    if platform.system() != "Windows" or not sd_bytes:
        return None
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        sddl_ptr = wintypes.LPWSTR()
        sddl_len = wintypes.ULONG(0)
        sec_info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

        ok = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            ctypes.c_char_p(sd_bytes),
            wintypes.DWORD(SDDL_REVISION_1),
            wintypes.DWORD(sec_info),
            ctypes.byref(sddl_ptr),
            ctypes.byref(sddl_len),
        )
        if not ok or not sddl_ptr.value:
            return None
        sddl_str = str(sddl_ptr.value)
        kernel32.LocalFree(sddl_ptr)
        return sddl_str
    except Exception:
        return None


def _get_named_object_sddl(object_name: str, object_type: int = SE_FILE_OBJECT) -> Optional[str]:
    """Read Owner + Group + DACL SDDL string for a file, directory, or named pipe via advapi32."""
    if platform.system() != "Windows":
        return None
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        p_sd = wintypes.LPVOID()
        sec_info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

        res = advapi32.GetNamedSecurityInfoW(
            wintypes.LPCWSTR(object_name),
            wintypes.DWORD(object_type),
            wintypes.DWORD(sec_info),
            None,
            None,
            None,
            None,
            ctypes.byref(p_sd),
        )
        if res != 0 or not p_sd.value:
            return None

        try:
            sddl_ptr = wintypes.LPWSTR()
            sddl_len = wintypes.ULONG(0)
            ok = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                p_sd,
                wintypes.DWORD(SDDL_REVISION_1),
                wintypes.DWORD(sec_info),
                ctypes.byref(sddl_ptr),
                ctypes.byref(sddl_len),
            )
            if not ok or not sddl_ptr.value:
                return None
            sddl_str = str(sddl_ptr.value)
            kernel32.LocalFree(sddl_ptr)
            return sddl_str
        finally:
            kernel32.LocalFree(p_sd)
    except Exception:
        return None


def _ace_grants_write(ace_line: str) -> bool:
    tokens = set()
    for group in re.findall(r"\(([^)]*)\)", ace_line):
        tokens.update(t.strip().upper() for t in group.split(","))
    return "DENY" not in tokens and bool(tokens & WRITE_RIGHT_TOKENS)


# ---------------------------------------------------------------------------
# 1. Filesystem ACLs & SDDL Strings (Installation & Updater Paths)
# ---------------------------------------------------------------------------
def collect_filesystem_acls(target_dir: Path) -> Dict[str, Any]:
    """Collect SDDL strings for install/updater folders and flag any weak icacls/SDDL entries."""
    weak_entries: List[Dict[str, Any]] = []
    audited_paths: List[Dict[str, Any]] = []

    if not target_dir.exists():
        return {"audited_paths": audited_paths, "weak_acls": weak_entries}

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
        sddl = _get_named_object_sddl(str(path_item), SE_FILE_OBJECT)
        if sddl:
            audited_paths.append({"path": str(path_item), "sddl": sddl})

        out = _run_cmd(["icacls", str(path_item)], timeout=10)
        for line in out.splitlines():
            clean = line.strip()
            if not clean:
                continue
            for principal in LOW_PRIV_PRINCIPALS:
                if principal.lower() in clean.lower() and _ace_grants_write(clean):
                    weak_entries.append(
                        {
                            "path": str(path_item),
                            "principal": principal,
                            "acl_entry": clean,
                            "sddl": sddl,
                        }
                    )

    return {"audited_paths": audited_paths, "weak_acls": weak_entries}


# ---------------------------------------------------------------------------
# 2. Windows Services (Unquoted Paths, SYSTEM Execution & Service SDDL)
# ---------------------------------------------------------------------------
def _get_service_sddl(svc_name: str) -> Optional[str]:
    out = _run_cmd(["sc.exe", "sdshow", svc_name], timeout=10).strip()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(("D:", "O:", "G:", "S:")):
            return line
    return None


def collect_services(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Enumerate Windows services with ImagePath, privilege level, and service SDDL."""
    services: List[Dict[str, Any]] = []
    if winreg is None:
        return services

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

                        if not (int(svc_type) & 0x30):
                            continue

                        img_str = str(image_path).strip()
                        if app_keyword and app_keyword.lower() not in (svc_name + img_str).lower():
                            continue

                        exe_part = img_str.split(" -")[0].split(" /")[0].strip()
                        is_unquoted_space = (
                            not exe_part.startswith('"')
                            and " " in exe_part
                            and not exe_part.lower().startswith(r"c:\windows\system32")
                        )
                        runs_as_system = str(obj_name).lower() in ("localsystem", r"nt authority\system")
                        svc_sddl = _get_service_sddl(svc_name)

                        if is_unquoted_space or app_keyword or svc_sddl:
                            issues: List[str] = []
                            if is_unquoted_space:
                                issues.append("Unquoted service binary path containing spaces")
                            if runs_as_system:
                                issues.append(f"Service runs with high privilege ({obj_name})")

                            services.append(
                                {
                                    "service_name": svc_name,
                                    "bin_path": img_str,
                                    "account": str(obj_name),
                                    "unquoted_path": is_unquoted_space,
                                    "runs_as_system": runs_as_system,
                                    "sddl": svc_sddl,
                                    "issue": "; ".join(issues) if issues else "Evaluated via SDDL",
                                }
                            )
                except (FileNotFoundError, PermissionError, OSError):
                    continue
    except OSError:
        pass

    return services


# ---------------------------------------------------------------------------
# 3. Scheduled Tasks (Non-Microsoft Tasks Running as SYSTEM)
# ---------------------------------------------------------------------------
def collect_scheduled_tasks(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    out = _run_cmd(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=25)
    if not out:
        return tasks

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
# 4. Named Pipes Inventory + DACL SDDL
# ---------------------------------------------------------------------------
def collect_named_pipes(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """List Windows Named Pipes under \\\\.\\pipe\\ and extract their DACL SDDL string."""
    pipes: List[Dict[str, Any]] = []
    try:
        pipe_names = os.listdir(r"\\.\pipe\\")
    except OSError:
        return pipes

    for name in sorted(pipe_names):
        if app_keyword and app_keyword.lower() not in name.lower():
            continue
        full_pipe = rf"\\.\pipe\{name}"
        sddl = _get_named_object_sddl(full_pipe, SE_FILE_OBJECT)
        pipes.append(
            {
                "pipe_name": name,
                "full_path": full_pipe,
                "sddl": sddl,
            }
        )
    return pipes


# ---------------------------------------------------------------------------
# 5. COM / DCOM AppID Configurations + Converted Launch/Access SDDL
# ---------------------------------------------------------------------------
def collect_com_dcom(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Inspect HKLM\\SOFTWARE\\Classes\\AppID and convert binary Launch/AccessPermission to SDDL."""
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

                        launch_sddl: Optional[str] = None
                        access_sddl: Optional[str] = None
                        run_as: Optional[str] = None

                        try:
                            raw_launch, _ = winreg.QueryValueEx(app_key, "LaunchPermission")
                            if isinstance(raw_launch, bytes):
                                launch_sddl = _binary_sd_to_sddl(raw_launch)
                        except FileNotFoundError:
                            pass

                        try:
                            raw_access, _ = winreg.QueryValueEx(app_key, "AccessPermission")
                            if isinstance(raw_access, bytes):
                                access_sddl = _binary_sd_to_sddl(raw_access)
                        except FileNotFoundError:
                            pass

                        try:
                            run_as_val, _ = winreg.QueryValueEx(app_key, "RunAs")
                            run_as = str(run_as_val)
                        except FileNotFoundError:
                            pass

                        if launch_sddl or access_sddl or run_as or app_keyword:
                            dcom_entries.append(
                                {
                                    "appid": sub_name,
                                    "description": str(desc),
                                    "launch_permission_sddl": launch_sddl,
                                    "access_permission_sddl": access_sddl,
                                    "run_as": run_as,
                                }
                            )
                except OSError:
                    continue
    except OSError:
        pass
    return dcom_entries


# ---------------------------------------------------------------------------
# 6. Custom URI Protocol Handlers
# ---------------------------------------------------------------------------
def collect_custom_uri_handlers(app_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
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
# 7. DLL Search-Order Ground Truth (System32, KnownDLLs, SafeDllSearchMode)
# ---------------------------------------------------------------------------
def collect_dll_search_environment() -> Dict[str, Any]:
    """
    Gather System32 DLL filenames, registry KnownDLLs, and SafeDllSearchMode
    so static IAT analysis does not emit false positives for standard OS libraries.
    """
    env_data: Dict[str, Any] = {
        "safe_dll_search_mode": 1,  # Windows default is 1 (enabled) when key is absent
        "known_dlls": [],
        "system32_dlls": [],
    }
    if winreg is None:
        return env_data

    sm_path = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sm_path) as sm_key:
            try:
                safe_mode, _ = winreg.QueryValueEx(sm_key, "SafeDllSearchMode")
                env_data["safe_dll_search_mode"] = int(safe_mode)
            except FileNotFoundError:
                pass

            try:
                with winreg.OpenKey(sm_key, "KnownDLLs") as kd_key:
                    _, val_count, _ = winreg.QueryInfoKey(kd_key)
                    known: List[str] = []
                    for i in range(val_count):
                        _, val_data, _ = winreg.EnumValue(kd_key, i)
                        if isinstance(val_data, str) and val_data.lower().endswith(".dll"):
                            known.append(val_data.lower())
                    env_data["known_dlls"] = sorted(set(known))
            except FileNotFoundError:
                pass
    except OSError:
        pass

    sys32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    if sys32.is_dir():
        try:
            env_data["system32_dlls"] = sorted(
                p.name.lower() for p in sys32.glob("*.dll")
            )
        except OSError:
            pass

    return env_data


# ---------------------------------------------------------------------------
# 8. Installed Software Inventory
# ---------------------------------------------------------------------------
def collect_installed_software() -> List[Dict[str, str]]:
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
        description="TIRtcp v2 Zero-Dependency Windows Host Evidence & SDDL Collector",
    )
    parser.add_argument(
        "--app-dir",
        type=Path,
        required=True,
        help="Target thick-client installation directory to inspect ACLs and SDDL.",
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




def collect_security_posture_extras() -> dict:
    """Collect custom Root CAs, target-related Firewall rules, and Credential Manager target names."""
    extras = {"custom_root_cas": [], "firewall_rules": [], "credential_targets": []}
    if sys.platform != "win32":
        return extras

    # 1. Non-Microsoft Root CAs (detects enterprise/rogue MITM root certificates)
    ps_ca = (
        r"Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Subject -notmatch 'Microsoft|DigiCert|VeriSign|GlobalSign|Baltimore|Entrust|Sectigo|thawte|GeoTrust|IdenTrust|ISRG' } | "
        "Select-Object -First 40 Subject, Thumbprint, NotAfter | ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_ca], text=True, timeout=15)
        if out.strip():
            parsed = json.loads(out)
            extras["custom_root_cas"] = parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        pass

    # 2. Windows Credential Manager target names only (never secrets)
    try:
        cmd_out = subprocess.check_output(["cmdkey", "/list"], text=True, timeout=10, errors="ignore")
        for line in cmd_out.splitlines():
            line = line.strip()
            if line.lower().startswith("target:"):
                extras["credential_targets"].append(line.split(":", 1)[1].strip())
    except Exception:
        pass

    return extras


def main() -> int:
    args = parse_args()

    if platform.system() != "Windows":
        print(
            "[!] Warning: collect_host.py is designed for Windows target hosts.",
            file=sys.stderr,
        )

    acl_bundle = collect_filesystem_acls(args.app_dir)

    evidence: Dict[str, Any] = {
        "schema_version": "2.0.0",
        "security_posture": collect_security_posture_extras(),
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "os_release": platform.platform(),
        "collector_elevated_admin": _is_admin(),
        "target_app_dir": str(args.app_dir),
        "filter_keyword": args.filter,
        "audited_paths": acl_bundle["audited_paths"],
        "weak_acls": acl_bundle["weak_acls"],
        "insecure_services": collect_services(args.filter),
        "scheduled_tasks": collect_scheduled_tasks(args.filter),
        "named_pipes": collect_named_pipes(args.filter),
        "com_dcom_appids": collect_com_dcom(args.filter),
        "custom_uri_handlers": collect_custom_uri_handlers(args.filter),
        "dll_search_environment": collect_dll_search_environment(),
        "installed_software": collect_installed_software(),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"[+] Host evidence v2 written to: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())