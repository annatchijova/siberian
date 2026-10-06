"""
siberian/shimcache_parser.py
============================
Windows AppCompatCache (Shimcache) parser.

Shimcache is stored in the Windows Registry at:
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

The AppCompatCache value is REG_BINARY. The exact format varies by Windows
version.

It does **not** decode the documented shimcache record layout. It performs a
heuristic scan: it looks for a 4-byte length, then searches the surrounding
bytes for a UTF-16-LE path string, and reports that path. A timestamp is only
reported when an 8-byte window in that region decodes to a FILETIME between
2010 and 2030.

Every entry carries ``parse_method`` so a heuristic recovery is never mistaken
for a decoded record ("length-scan" or "path-scan"). ``flags`` is never
populated: a constant 0 would be indistinguishable from a real zero flag.

Validation status: **no SYSTEM hive exists in this workspace**, so neither the
record layout nor the registry value name is confirmed against real evidence.
See docs/red-team/NIVEL6_SHIMCACHE_AUDIT.md.

Design constraints:
- No external dependencies (stdlib only)
- Terminal-only output
- Each entry is an independent evidence item
- Format is documented as best-effort; unparsed entries are noted
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# FILETIME epoch
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


# Value names this parser will accept for the AppCompatCache data. Windows
# versions are not consistent about the spelling, so both are tried and the one
# that matched is recorded. Widening a name match cannot fabricate structure.
CACHE_VALUE_NAMES = ("AppCompatCache", "AppCompatibilityCache")


@dataclass
class ShimcacheEntry:
    """One heuristically recovered AppCompatCache path.

    ``parse_method`` records how the entry was obtained, so a heuristic
    recovery is never presented as a decoded record.
    """

    path: str
    last_modified: Optional[datetime] = None
    # Never populated by this parser. Present only so the absence is explicit
    # rather than defaulted to a plausible-looking 0.
    flags: Optional[int] = None
    entry_size: int = 0
    raw_offset: int = 0
    parse_method: str = "length-scan"
    # Provenance of the containing registry value, when known.
    control_set: Optional[str] = None
    value_name: Optional[str] = None
    # Set when the value was located only by being binary, i.e. its name was not
    # one this parser recognises.
    degraded: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "flags": self.flags,
            "entry_size": self.entry_size,
            "raw_offset": self.raw_offset,
            "parse_method": self.parse_method,
            "control_set": self.control_set,
            "value_name": self.value_name,
            "degraded": self.degraded,
            "error": self.error,
        }


def _filetime(ts: int) -> Optional[datetime]:
    """Convert NTFS FILETIME to datetime."""
    if ts <= 0:
        return None
    try:
        microseconds = ts // 10
        return _FILETIME_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, OSError):
        return None


def _extract_utf16_paths(data: bytes) -> List[Tuple[int, str]]:
    """Extract all UTF-16-LE strings that look like file paths."""
    results = []
    # Look for null-terminated UTF-16-LE strings
    i = 0
    while i < len(data) - 4:
        # Try to decode a UTF-16-LE string starting at byte offset i
        try:
            # Look for null terminator (2 null bytes in UTF-16)
            end = data.find(b'\x00\x00', i)
            if end == -1 or end >= i + 2048:
                i += 2
                continue
            candidate = data[i:end].decode('utf-16-le', errors='ignore').strip('\x00')
            if len(candidate) > 3 and (candidate[1:3] == ':\\' or candidate[1:3] == ':/' or candidate.startswith('\\\\')):
                results.append((i, candidate))
            i = end + 2
        except (UnicodeDecodeError, IndexError):
            i += 2
    return results


def parse_shimcache_binary(data: bytes) -> List[ShimcacheEntry]:
    """
    Parse Windows 10 AppCompatCache binary blob.
    
    Args:
        data: Raw REG_BINARY bytes from AppCompatCache value
    
    Returns:
        List of ShimcacheEntry objects
    """
    if len(data) < 8:
        return [ShimcacheEntry(path="", error="Data too small")]

    entries: List[ShimcacheEntry] = []

    # Windows 10 format heuristic:
    # Each entry starts with a 4-byte LE size field
    offset = 0
    entry_count = 0

    while offset < len(data) - 8 and entry_count < 10000:
        # Try to read entry size
        try:
            entry_size = struct.unpack_from("<I", data, offset)[0]
        except struct.error:
            break

        if entry_size < 8 or entry_size > len(data) - offset or entry_size > 4096:
            # Invalid size - probably not an entry boundary, try scanning for next valid entry
            # Look for UTF-16 path marker (e.g. 'C' param)
            offset += 2
            continue

        entry_data = data[offset + 4:offset + entry_size]
        if len(entry_data) < 4:
            offset += entry_size
            continue

        # Try to find a path in this entry
        path_info = None
        for start_offset in range(0, min(len(entry_data), 512), 2):
            try:
                decoded = entry_data[start_offset:].decode('utf-16-le', errors='ignore')
                # Find null terminator
                null_idx = decoded.find('\x00')
                if null_idx > 2:
                    candidate = decoded[:null_idx].strip('\x00').strip()
                    if len(candidate) > 3 and (candidate[1:3] == ':\\' or candidate.startswith('\\\\')):
                        path_info = candidate
                        break
            except (UnicodeDecodeError, IndexError):
                continue

        if path_info:
            # Try to find FILETIME near the path
            last_modified = None
            for t_off in range(0, len(entry_data) - 8, 2):
                try:
                    ts = struct.unpack_from("<Q", entry_data, t_off)[0]
                    ft = _filetime(ts)
                    # Filter reasonable FILETIME values (2010-2020)
                    if ft and 2010 <= ft.year <= 2030:
                        last_modified = ft
                        break
                except (struct.error, IndexError):
                    pass

            entries.append(ShimcacheEntry(
                path=path_info,
                last_modified=last_modified,
                entry_size=entry_size,
                raw_offset=offset,
            ))

        offset += entry_size
        entry_count += 1

    # Fallback: if no entries found with heuristic, use UTF-16 path extraction
    if not entries:
        paths = _extract_utf16_paths(data)
        for offset_in_data, path in paths:
            entries.append(ShimcacheEntry(
                path=path,
                raw_offset=offset_in_data,
                entry_size=0,
                parse_method="path-scan",
            ))

    return entries if entries else [ShimcacheEntry(path="", error="No entries parsed - format may be unsupported for this Windows version")]


def parse_shimcache_from_registry(hive_path: Path) -> List[ShimcacheEntry]:
    """Locate and heuristically parse the AppCompatCache value in a SYSTEM hive.

    The lookup accepts either known value name and records which one matched.
    When nothing is found, the error names the control sets and Session Manager
    value names that were actually present, so a failed lookup is diagnosable
    instead of indistinguishable from a hive that never had shimcache.
    """
    try:
        from Registry import Registry
    except ImportError:
        return [ShimcacheEntry(
            path="",
            error="python-registry not installed: pip install python-registry",
            degraded="registry parsing unavailable",
        )]

    try:
        hive = Registry.Registry(str(hive_path))
    except Exception as exc:
        return [ShimcacheEntry(path="", error=f"Cannot open hive: {exc}")]

    try:
        root = hive.root()
    except Exception as exc:
        return [ShimcacheEntry(path="", error=f"Cannot read hive root: {exc}")]

    control_sets = []
    seen_value_names: List[str] = []
    reached_session_manager = False

    for control_set in _safe(root.subkeys):
        cs_name = control_set.name()
        if not (cs_name.startswith("ControlSet") or cs_name == "CurrentControlSet"):
            continue
        control_sets.append(cs_name)

        session_manager = _safe_subkey(control_set, "Control\\Session Manager")
        if session_manager is None:
            continue
        reached_session_manager = True

        # Record what is actually present, for the failure message.
        for value in _safe(session_manager.values):
            try:
                seen_value_names.append(value.name())
            except Exception:
                continue
        if _safe_subkey(session_manager, "AppCompatCache") is not None:
            for value in _safe(_safe_subkey(session_manager, "AppCompatCache").values):
                try:
                    seen_value_names.append(
                        f"AppCompatCache\\{value.name()}"
                    )
                except Exception:
                    continue

        # Case A: the data is a value directly on Session Manager.
        for value in _safe(session_manager.values):
            try:
                name = value.name()
                data = value.value()
            except Exception:
                continue
            if name in CACHE_VALUE_NAMES and isinstance(data, bytes):
                return _tag(parse_shimcache_binary(data), cs_name, name)

        # Case B: an AppCompatCache subkey holds the value.
        cache_key = _safe_subkey(session_manager, "AppCompatCache")
        if cache_key is not None:
            for value in _safe(cache_key.values):
                try:
                    name = value.name()
                    data = value.value()
                except Exception:
                    continue
                if not isinstance(data, bytes):
                    continue
                if name in CACHE_VALUE_NAMES:
                    return _tag(parse_shimcache_binary(data), cs_name, name)

    # Nothing matched. Say what was looked at, so this is diagnosable.
    detail = f"control sets seen: {', '.join(control_sets) or 'none'}"
    if seen_value_names:
        detail += f"; values present: {', '.join(sorted(set(seen_value_names)))}"
    elif reached_session_manager:
        detail += "; Session Manager holds no values"
    else:
        detail += "; Session Manager not reachable"
    return [ShimcacheEntry(
        path="",
        error=(
            "AppCompatCache value not found. Looked for "
            f"{' and '.join(CACHE_VALUE_NAMES)} under "
            "ControlSet\\Control\\Session Manager. " + detail
        ),
    )]


def _tag(entries: List[ShimcacheEntry], control_set: str, value_name: str) -> List[ShimcacheEntry]:
    """Attach provenance to every entry recovered from one registry value."""
    for entry in entries:
        entry.control_set = control_set
        entry.value_name = value_name
    return entries


def _safe(getter):
    """Call a python-registry accessor, returning an empty list on failure.

    Navigation errors must not be silently swallowed and then reported as
    "not found"; they surface as an empty listing that the failure message
    makes explicit.
    """
    try:
        return list(getter())
    except Exception:
        return []


def _safe_subkey(key, path: str):
    try:
        return key.subkey(path)
    except Exception:
        return None


def format_shimcache_summary(entry: ShimcacheEntry) -> str:
    """Format one entry as a single terminal line.

    The recovery method is always shown: a path found by scanning a blob is not
    the same claim as a decoded record, and the terminal line is where an
    analyst will read it.
    """
    if entry.error:
        return f"ERROR: {entry.error}"
    modified = entry.last_modified.isoformat() if entry.last_modified else "not recovered"
    source = entry.value_name or entry.control_set or "?"
    return (
        f"{entry.path:56s} | last_modified: {modified:32s} "
        f"| via: {entry.parse_method:12s} | source: {source}"
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m siberian.shimcache_parser <SYSTEM_hive> [max_entries]")
        sys.exit(1)
    hive_path = Path(sys.argv[1])
    max_entries = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    entries = parse_shimcache_from_registry(hive_path)
    print(f"Parsed {len(entries)} Shimcache entries")
    for entry in entries[:max_entries or 100]:
        print(format_shimcache_summary(entry))
    if max_entries > 0 and len(entries) > max_entries:
        print(f"... and {len(entries) - max_entries} more")