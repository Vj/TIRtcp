"""Extract assemblies from a .NET single-file (apphost) bundle so the managed/string analyzers can see them.

A single-file publish (`PublishSingleFile=true`) packs every managed DLL, deps.json and runtimeconfig.json inside
the EXE, so scanning the file as one opaque PE (as before) finds nothing. Layout (bundle v1-v6+):
  [marker 32B][...files...][header]  with an int64 header offset stored in the 8 bytes right before the marker."""
from __future__ import annotations

import struct
import tempfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

BUNDLE_MARKER = bytes([0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
                       0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae])
TYPE_NAMES = {0: "unknown", 1: "assembly", 2: "native", 3: "deps.json", 4: "runtimeconfig.json", 5: "symbols"}
MAX_ENTRIES, MAX_TOTAL = 4000, 400 * 1024 * 1024


class _R:
    def __init__(self, b: bytes, pos: int) -> None:
        self.b, self.p = b, pos

    def u8(self) -> int:
        v = self.b[self.p]; self.p += 1; return v

    def fmt(self, f: str):
        v = struct.unpack_from(f, self.b, self.p)[0]; self.p += struct.calcsize(f); return v

    def string(self) -> str:
        n = shift = 0
        while True:
            c = self.u8(); n |= (c & 0x7F) << shift; shift += 7
            if not c & 0x80:
                break
        s = self.b[self.p:self.p + n].decode("utf-8", "replace"); self.p += n; return s


def find_bundle(data: bytes) -> Optional[Tuple[int, Dict]]:
    """Return (header_offset, header_info) or None."""
    pos = data.rfind(BUNDLE_MARKER)
    if pos < 8:
        return None
    header_off = struct.unpack_from("<q", data, pos - 8)[0]
    if not 0 < header_off < len(data):
        return None        # un-bundled apphost template still carries the marker with a zero offset
    r = _R(data, header_off)
    try:
        major, minor, count = r.fmt("<I"), r.fmt("<I"), r.fmt("<i")
        bundle_id = r.string()
        if major >= 2:
            for _ in range(4):
                r.fmt("<q")
            r.fmt("<Q")
        if not 0 < count <= MAX_ENTRIES:
            return None
        entries: List[Dict] = []
        for _ in range(count):
            off, size = r.fmt("<q"), r.fmt("<q")
            csize = r.fmt("<q") if major >= 6 else 0
            etype = r.u8(); path = r.string()
            entries.append({"offset": off, "size": size, "compressed_size": csize, "type": etype, "path": path})
        return header_off, {"major": major, "minor": minor, "bundle_id": bundle_id, "entries": entries}
    except (struct.error, IndexError):
        return None


def extract_bundle(exe: Path, out_dir: Optional[Path] = None) -> Optional[Dict]:
    data = exe.read_bytes()
    found = find_bundle(data)
    if not found:
        return None
    _, info = found
    out_dir = out_dir or Path(tempfile.mkdtemp(prefix="tirtcp_bundle_"))
    total, written, skipped = 0, [], []
    for e in info["entries"]:
        rel = PurePosixPath(e["path"].replace("\\", "/"))
        if rel.is_absolute() or ".." in rel.parts:
            skipped.append(f"{e['path']}: unsafe path"); continue          # zip-slip guard
        raw = data[e["offset"]:e["offset"] + (e["compressed_size"] or e["size"])]
        try:
            blob = zlib.decompress(raw, -15) if e["compressed_size"] else raw
        except zlib.error:
            skipped.append(f"{e['path']}: bad deflate"); continue
        total += len(blob)
        if total > MAX_TOTAL:
            skipped.append("size cap reached"); break
        dest = out_dir.joinpath(*rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)
        written.append({"path": e["path"], "type": TYPE_NAMES.get(e["type"], str(e["type"])), "size": len(blob)})
    return {"dir": out_dir, "bundle_version": f"{info['major']}.{info['minor']}", "bundle_id": info["bundle_id"],
            "files": written, "skipped": skipped}
