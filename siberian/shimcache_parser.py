"""
siberian/shimcache_parser.py
============================
Windows AppCompatCache (Shimcache) parser.

Shimcache is stored in the Windows Registry at:
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

The AppCompatCache value is REG_BINARY. The exact format varies by Windows
version. This parser handles Windows 10+ format heuristically:
- Each entry starts with a 4-byte little-endian size
- Entry contains a path (UTF-16-LE) and a last-modified timestamp

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


@dataclass
class ShimcacheEntry:
    """Parsed AppCompatCache entry."""
    path: str
    last_modified: Optional[datetime] = None
    flags: int = 0
    entry_size: int = 0
    raw_offset: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "flags": self.flags,
            "entry_size": self.entry_size,
            "raw_offset": self.raw_offset,
            "error": self.error,
        }


def _filetime(ts: int) -> Optional[datetime]:
    """Convert NTFS FILETIME to datetime."""
    if ts == 0:
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
            ))

    return entries if entries else [ShimcacheEntry(path="", error="No entries parsed - format may be unsupported for this Windows version")]


def parse_shimcache_from_registry(hive_path: Path) -> List[ShimcacheEntry]:
    """
    Parse Shimcache from SYSTEM Registry hive.
    
    Args:
        hive_path: Path to SYSTEM hive file
    
    Returns:
        List of ShimcacheEntry objects
    """
    try:
        from Registry import Registry
    except ImportError:
        return [ShimcacheEntry(path="", error="python-registry not installed: pip install python-registry")]

    try:
        reg = Registry.Registry(str(hive_path))
    except Exception as e:
        return [ShimcacheEntry(path="", error=f"Cannot open hive: {e}")]

    try:
        # Navigate to: ControlSet001 -> Control -> Session Manager -> AppCompatCache
        # Or CurrentControlSet -> Control -> Session Manager -> AppCompatCache
        root = reg.root()
        target_key = None

        for control_set in root.subkeys():
            cs_name = control_set.name()
            if not cs_name.startswith("ControlSet") and cs_name != "CurrentControlSet":
                continue
            try:
                session_manager = control_set.subkey("Control\\Session Manager")
                if session_manager is None:
                    session_manager = control_set.subkey("Control\\Session Manager\\AppCompatCache")
                if session_manager:
                    try:
                        appcompat_cache_key = session_manager.subkey("AppCompatCache")
                        if appcompat_cache_key is None:
                            # AppCompatCache might be a value in Session Manager directly
                            for value in session_manager.values():
                                if value.name() == "AppCompatCache":
                                    data = value.value()
                                    if isinstance(data, bytes):
                                        return parse_shimcache_binary(data)
                        else:
                            for value in appcompat_cache_key.values():
                                if value.name() == "AppCompatCache" or isinstance(value.value(), bytes):
                                    data = value.value()
                                    if isinstance(data, bytes):
                                        return parse_shimcache_binary(data)
                    except Exception:
                        pass
            except Exception:
                pass

        return [ShimcacheEntry(path="", error="AppCompatCache key not found in SYSTEM hive")]
    except Exception as e:
        return [ShimcacheEntry(path="", error=f"Error parsing SYSTEM hive: {e}")]


def format_shimcache_summary(entry: ShimcacheEntry) -> str:
    """Format one entry as a human-readable summary line."""
    if entry.error:
        return f"ERROR: {entry.error}"
    modified = entry.last_modified.isoformat() if entry.last_modified else "unknown"
    return f"{entry.path:60s} | last modified: {modified} | size: {entry.entry_size}"


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