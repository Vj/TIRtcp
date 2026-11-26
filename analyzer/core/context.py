"""
TIRtcp Single-Pass Target Inventory, Lazy Cache & Coverage Tracker.
Eliminates redundant disk walks and file reads across static/host modules while
tracking exact coverage (files_seen, files_scanned, files_skipped) so modules
never emit a false 'Verified Pass' when files were skipped or unreadable.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024

TEXT_EXTS = {
    ".config", ".xml", ".json", ".yaml", ".yml", ".ini", ".properties",
    ".env", ".conf", ".cfg", ".toml", ".bat", ".ps1", ".sh", ".py",
    ".js", ".mjs", ".cjs", ".html", ".htm", ".txt", ".log", ".trace", ".out",
}
PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".scr"}
ARCHIVE_EXTS = {".jar", ".war", ".ear", ".asar", ".zip"}


@dataclass
class CoverageStats:
    stage: str
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    skip_reasons: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return self.files_skipped == 0

    def record_skip(self, path: Path, reason: str) -> None:
        self.files_skipped += 1
        if len(self.skip_reasons) < 15:
            self.skip_reasons.append(f"{path.name}: {reason}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "files_seen": self.files_seen,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "complete_coverage": self.is_complete,
            "sample_skip_reasons": self.skip_reasons,
        }


@dataclass
class FileRecord:
    path: Path
    rel_path: str
    size: int
    ext: str
    magic: bytes = b""
    is_pe: bool = False
    is_elf: bool = False
    is_macho: bool = False
    is_binary: bool = False
    _sha256: Optional[str] = field(default=None, repr=False)
    _raw_bytes: Optional[bytes] = field(default=None, repr=False)
    _text: Optional[str] = field(default=None, repr=False)
    _printable_strings: Optional[str] = field(default=None, repr=False)

    def read_bytes(self, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Optional[bytes]:
        if self.size == 0 or self.size > max_bytes:
            return None
        if self._raw_bytes is None:
            try:
                self._raw_bytes = self.path.read_bytes()
            except OSError:
                return None
        return self._raw_bytes

    @property
    def sha256(self) -> Optional[str]:
        if self._sha256 is None:
            data = self.read_bytes(max_bytes=100 * 1024 * 1024)
            if data is not None:
                self._sha256 = hashlib.sha256(data).hexdigest()
        return self._sha256

    def read_text(self, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Optional[str]:
        if self._text is None:
            data = self.read_bytes(max_bytes=max_bytes)
            if data is None:
                return None
            self._text = data.decode("utf-8", errors="ignore")
        return self._text

    def printable_strings(self, min_len: int = 6, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Optional[str]:
        """Cached ASCII + UTF-16LE string extraction shared across secrets, SCA, and Electron modules."""
        if self._printable_strings is None:
            data = self.read_bytes(max_bytes=max_bytes)
            if data is None:
                return None
            ascii_matches = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
            utf16_matches = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
            parts = [m.decode("ascii", errors="ignore") for m in ascii_matches]
            parts.extend(m.decode("utf-16le", errors="ignore") for m in utf16_matches)
            self._printable_strings = "\n".join(parts)
        return self._printable_strings


class ScanContext:
    """Single-pass directory inventory and lazy content cache for TIRtcp."""

    def __init__(self, target_path: Path) -> None:
        self.target_path = target_path
        self.root_dir = target_path if target_path.is_dir() else target_path.parent
        self.files: List[FileRecord] = []
        self.walk_errors: List[str] = []
        self._build_inventory()

    def _inspect_magic(self, fpath: Path) -> bytes:
        try:
            with fpath.open("rb") as fh:
                return fh.read(16)
        except OSError as exc:
            self.walk_errors.append(f"{fpath}: {exc}")
            return b""

    def _build_inventory(self) -> None:
        raw_paths: List[Path] = []
        if self.target_path.is_file():
            raw_paths.append(self.target_path)
        elif self.target_path.is_dir():
            for root, _, fnames in os.walk(self.target_path, onerror=lambda e: self.walk_errors.append(str(e))):
                for fname in sorted(fnames):
                    raw_paths.append(Path(root) / fname)

        for fpath in raw_paths:
            try:
                st = fpath.stat()
            except OSError as exc:
                self.walk_errors.append(f"{fpath}: {exc}")
                continue

            magic = self._inspect_magic(fpath) if st.st_size > 0 else b""
            ext = fpath.suffix.lower()
            is_pe = magic[:2] == b"MZ"
            is_elf = magic[:4] == b"\x7fELF"
            is_macho = magic[:4] in {
                b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
            }
            is_binary = is_pe or is_elf or is_macho or (b"\x00" in magic)

            try:
                rel = str(fpath.relative_to(self.root_dir))
            except ValueError:
                rel = fpath.name

            self.files.append(
                FileRecord(
                    path=fpath,
                    rel_path=rel,
                    size=st.st_size,
                    ext=ext,
                    magic=magic,
                    is_pe=is_pe,
                    is_elf=is_elf,
                    is_macho=is_macho,
                    is_binary=is_binary,
                )
            )

    def iter_by_exts(self, exts: Set[str]) -> Iterable[FileRecord]:
        for rec in self.files:
            if rec.ext in exts:
                yield rec

    def iter_binaries(self) -> Iterable[FileRecord]:
        for rec in self.files:
            if rec.is_pe or rec.is_elf or rec.is_macho or rec.ext in PE_EXTS or rec.ext in {".so", ".dylib"}:
                yield rec