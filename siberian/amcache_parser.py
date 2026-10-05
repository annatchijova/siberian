"""
siberian/amcache_parser.py
==========================
Windows Amcache.hve (Application TimelineCache) registry hive parser.

Amcache.hve is a Windows registry hive stored at:
    C:\\Windows\\AppCompat\\Programs\\Amcache.hve

Contains records of executed applications with:
- Full path to executable
- SHA1 hash of the file
- Publisher/memory info
- File creation/modification timestamps
- Program ID

Design constraints:
- Uses `Registry` module (python-registry, pure Python)
- Terminal-only output
- Each application entry is an independent evidence item
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
class AmcacheEntry:
    """Parsed Amcache.hve application entry."""
    key_name: str
    name: Optional[str] = None
    publisher: Optional[str] = None
    path: Optional[str] = None
    sha1: Optional[str] = None
    first_execution_time: Optional[datetime] = None
    last_execution_time: Optional[datetime] = None
    program_id: Optional[str] = None
    product_id: Optional[str] = None
    file_size: Optional[int] = None
    entry_type: str = "unknown"  # "Program", "Device", "Driver", "File", "Unknown"
    error: Optional[str] = None
    raw_values: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_name": self.key_name,
            "name": self.name,
            "publisher": self.publisher,
            "path": self.path,
            "sha1": self.sha1,
            "first_execution_time": self.first_execution_time.isoformat() if self.first_execution_time else None,
            "last_execution_time": self.last_execution_time.isoformat() if self.last_execution_time else None,
            "program_id": self.program_id,
            "product_id": self.product_id,
            "file_size": self.file_size,
            "entry_type": self.entry_type,
            "error": self.error,
            "raw_values": self.raw_values,
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


def _parse_filetime_bytes(data: bytes) -> Optional[datetime]:
    """Parse an 8-byte FILETIME from raw bytes."""
    if len(data) < 8:
        return None
    try:
        ts = struct.unpack("<Q", data[:8])[0]
        return _filetime(ts)
    except (struct.error, IndexError):
        return None


# Application-related value names in Amcache
_APP_VALUE_NAMES = {
    "Name", "Publisher", "Path", "InstallDate", "Version",
    "ProgramId", "ProductId", "FileDescription", "CompanyName",
    "DataDir", "InstallSource",
}

_TIME_VALUE_PREFIXES = ("First", "Last", "Timestamp", "Execution")


def parse_amcache_hive(hive_path: Path) -> List[AmcacheEntry]:
    """
    Parse Amcache.hve registry hive and extract application entries.
    
    Args:
        hive_path: Path to Amcache.hve file
    
    Returns:
        List of AmcacheEntry objects
    """
    try:
        from Registry import Registry
    except ImportError:
        # Fallback: return empty list with error message
        return [AmcacheEntry(
            key_name="<error>",
            entry_type="Error",
            error=None,
            raw_values={"error": "python-registry (Registry module) not installed. Install with: pip install python-registry"},
        )]

    entries: List[AmcacheEntry] = []
    try:
        reg = Registry.Registry(str(hive_path))
    except Exception as e:
        return [AmcacheEntry(
            key_name="<error>",
            entry_type="Error",
            error=None,
            raw_values={"error": f"Cannot open hive: {e}"},
        )]

    def _walk_key(key, parent_path: str = "") -> None:
        path = f"{parent_path}\\{key.name()}" if parent_path else key.name()
        values: Dict[str, Any] = {}
        for v in key.values():
            try:
                val = v.value()
                if isinstance(val, bytes) and len(val) >= 8:
                    # Try to interpret as FILETIME
                    ft = _parse_filetime_bytes(val)
                    if ft:
                        values[v.name()] = ft.isoformat()
                    else:
                        values[v.name()] = val.hex()[:16]
                else:
                    values[v.name()] = val
            except Exception:
                values[v.name()] = "<error>"

        # Check if this key looks like an application entry
        app_keys = set(values.keys()) & _APP_VALUE_NAMES
        if app_keys:
            entry = AmcacheEntry(
                key_name=key.name(),
                name=values.get("Name") or values.get("FileDescription"),
                publisher=values.get("Publisher") or values.get("CompanyName"),
                path=values.get("Path"),
                raw_values=values,
                entry_type="Program" if "ProgramId" in values or "ProductId" in values else "File",
            )
            # Try to extract program ID
            entry.program_id = values.get("ProgramId")
            entry.product_id = values.get("ProductId")
            # Try to find timestamps
            for vk, vv in values.items():
                if isinstance(vv, str) and "T" in vv:
                    if "first" in vk.lower() or "firstexecution" in vk.lower():
                        try:
                            entry.first_execution_time = datetime.fromisoformat(vv.replace("Z", "+00:00"))
                        except ValueError:
                            pass
                    elif "last" in vk.lower() or "lastexecution" in vk.lower():
                        try:
                            entry.last_execution_time = datetime.fromisoformat(vv.replace("Z", "+00:00"))
                        except ValueError:
                            pass
                elif isinstance(vv, int) and vk.lower() in ("filesize", "size"):
                    entry.file_size = vv
            entries.append(entry)

        # Recurse into subkeys
        for subkey in key.subkeys():
            _walk_key(subkey, path)

    # Start from root
    try:
        root_key = reg.root()
        _walk_key(root_key)
    except Exception as e:
        return [AmcacheEntry(
            key_name="<error>",
            entry_type="Error",
            raw_values={"error": f"Error walking hive: {e}"},
        )]

    return entries


def format_amcache_summary(entry: AmcacheEntry) -> str:
    """Format one entry as a human-readable summary line."""
    name = entry.name or entry.key_name
    path = entry.path or "<no path>"
    pub = entry.publisher or "<unknown>"
    if entry.entry_type == "Error":
        err = entry.raw_values.get("error", "unknown error")
        return f"ERROR: {err}"
    return f"{name:40s} | {path:60s} | publisher: {pub:30s} | type: {entry.entry_type}"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m siberian.amcache_parser <Amcache.hve> [max_entries]")
        sys.exit(1)
    hive_path = Path(sys.argv[1])
    max_entries = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    entries = parse_amcache_hive(hive_path)
    print(f"Parsed {len(entries)} Amcache entries")
    for entry in entries[:max_entries or 100]:
        print(format_amcache_summary(entry))
    if max_entries > 0 and len(entries) > max_entries:
        print(f"... and {len(entries) - max_entries} more")