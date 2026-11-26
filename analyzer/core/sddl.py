"""SDDL / DACL risk classifier.

Turns what used to be MANUAL checks (named-pipe DACLs, COM Launch/Access permissions, service and
file DACLs) into automatic verdicts. The collector only has to dump SDDL strings
(Get-Acl .Sddl, `sc sdshow`, or the COM AppID LaunchPermission value converted to SDDL)."""
from __future__ import annotations

import re
from typing import Dict, List

LOW_PRIV_SIDS: Dict[str, str] = {
    "WD": "Everyone", "BU": "BUILTIN\\Users", "AU": "Authenticated Users", "IU": "Interactive Users",
    "AN": "Anonymous", "BG": "BUILTIN\\Guests", "NU": "Network Users", "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-4": "Interactive",
    "S-1-5-7": "Anonymous", "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-2": "Network",
}
# Generic / specific write-class rights (file/pipe/service/COM)
WRITE_RIGHTS = {"GA", "GW", "FA", "FW", "WD", "AD", "WO", "WD", "DT", "SD", "WP", "DC", "CC", "RC_WDAC"}
SERVICE_DANGEROUS = {"GA", "GW", "WD", "WO", "DC", "RP_CONFIG"}  # change config / write DAC / owner
_ACE_RE = re.compile(r"\((?P<type>[AD]|OA|OD|AU)\;(?P<flags>[^;]*)\;(?P<rights>[^;]*)\;(?P<obj>[^;]*)\;(?P<inh>[^;]*)\;(?P<sid>[^)]+)\)")
_HEX_MASK = re.compile(r"0x[0-9a-fA-F]+")

# Hex access-mask bits that imply write/modify/takeover
_MASK_WRITE = 0x00000002 | 0x00000004 | 0x00000100 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000


def _rights_tokens(rights: str) -> List[str]:
    return [rights[i:i + 2] for i in range(0, len(rights), 2)] if not rights.startswith("0x") else []


def risky_aces(sddl: str) -> List[Dict[str, str]]:
    """Return allow-ACEs granting write-class rights to low-privileged principals."""
    out: List[Dict[str, str]] = []
    for m in _ACE_RE.finditer(sddl or ""):
        if m["type"] != "A" and m["type"] != "OA":
            continue
        sid = m["sid"].strip()
        who = LOW_PRIV_SIDS.get(sid)
        if not who:
            continue
        rights = m["rights"]
        if rights.startswith("0x"):
            writes = bool(int(rights, 16) & _MASK_WRITE)
        else:
            writes = bool(set(_rights_tokens(rights)) & WRITE_RIGHTS)
        if writes:
            out.append({"principal": who, "sid": sid, "rights": rights, "ace": m.group(0)})
    return out


def classify(sddl: str) -> Dict[str, object]:
    aces = risky_aces(sddl)
    return {"risky": bool(aces), "risky_aces": aces, "has_null_dacl": sddl.strip() in ("", "D:NO_ACCESS_CONTROL")}
