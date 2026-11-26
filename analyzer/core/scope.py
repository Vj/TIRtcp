"""
TIRtcp Network Scope Allow-List Validator (--scope-file).
Prevents active network probes from connecting to unapproved third-party telemetry,
CDN, or SaaS hosts discovered inside client configuration files.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import List, Union

NetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class NetworkScope:
    def __init__(self, scope_file: Path | None = None) -> None:
        self.configured = scope_file is not None
        self.host_patterns: List[str] = []
        self.cidrs: List[NetworkType] = []

        if scope_file and scope_file.exists():
            for raw_line in scope_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.split("#", 1)[0].strip().lower()
                if not line:
                    continue
                # Strip optional :port suffix if user wrote host:port
                if ":" in line and not line.count(":") > 1:
                    line = line.split(":", 1)[0]
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    self.cidrs.append(net)
                except ValueError:
                    self.host_patterns.append(line)

    def is_allowed(self, host: str) -> bool:
        if not self.configured:
            return False
        h = host.strip().lower()
        try:
            ip = ipaddress.ip_address(h)
            return any(ip in net for net in self.cidrs)
        except ValueError:
            return any(fnmatch.fnmatch(h, pat) for pat in self.host_patterns)