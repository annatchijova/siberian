"""
siberian/shellbags_parser.py
============================
Windows Shellbags parser.

Shellbags store Windows Explorer folder view settings and are located in:
    NTUSER.DAT:  Software\\Microsoft\\Windows\\Shell\\Bags, BagMRU
    USRCLASS.DAT: Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags, BagMRU

Each Bags subkey contains binary values. The BagMRU tree encodes the folder
path hierarchy. This parser extracts folder paths and timestamps from the
binary data, providing evidence of user folder access even after deletion.

Design constraints:
- No external dependencies except python-registry (already used for Amcache)
- Terminal-only output
- Each Bags entry is an independent evidence item
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# FILETIME epoch
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass
class ShellbagEntry:
    """Parsed Shellbags entry."""
    bag_type: str  # "BagMRU" or "Bags"
    key_path: str  # Registry key path
    folder_path: Optional[str] = None
    view_mode: Optional[str] = None
    sort_mode: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_value_name: str = ""
    raw_value_size: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bag_type": self.bag_type,
            "key_path": self.key_path,
            "folder_path": self.folder_path,
            "view_mode": self.view_mode,
            "sort_mode": self.sort_mode,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_value_name": self.raw_value_name,
            "raw_value_size": self.raw_value_size,
            "error": self.error,
        }


# Common view mode values
_VIEW_MODE_MAP = {
    0: "SmallIcons",
    1: "List",
    2: "Details",
    3: "Tiles",
    4: "Content",
    5: "LargeIcons",
    6: "ExtraLargeIcons",
}

# Common sort mode values
_SORT_MODE_MAP = {
    0: "Name",
    1: "Size",
    2: "ItemType",
    3: "DateModified",
    4: "Name (desc)",
    5: "Size (desc)",
    6: "ItemType (desc)",
    7: "DateModified (desc)",
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


def _extract_path_from_binary(data: bytes) -> Optional[str]:
    """Try to extract a folder path from binary blob."""
    # Look for UTF-16-LE strings that contain ':\\' or '\\\\'
    i = 0
    while i < len(data) - 4:
        try:
            end = data.find(b'\x00\x00', i)
            if end == -1 or end > i + 2048:
                i += 2
                continue
            candidate = data[i:end].decode('utf-16-le', errors='ignore').strip('\x00')
            if len(candidate) > 3 and (candidate[1:3] == ':\\' or candidate.startswith('\\\\')):
                return candidate
            i = end + 2
        except (UnicodeDecodeError, IndexError):
            i += 2
    return None


def parse_shellbags_from_registry(hive_path: Path, bag_type: str = "BagMRU") -> List[ShellbagEntry]:
    """
    Parse Shellbags from a registry hive.
    
    Args:
        hive_path: Path to registry hive (NTUSER.DAT or USRCLASS.DAT)
        bag_type: "BagMRU" or "Bags" - which subkey to parse
    
    Returns:
        List of ShellbagEntry objects
    """
    try:
        from Registry import Registry
    except ImportError:
        return [ShellbagEntry(bag_type=bag_type, key_path="", error="python-registry not installed")]

    entries: List[ShellbagEntry] = []

    try:
        reg = Registry.Registry(str(hive_path))
    except Exception as e:
        return [ShellbagEntry(bag_type=bag_type, key_path="", error=f"Cannot open hive: {e}")]

    def _walk_shell_keys(key, parent_path: str, target_subkey: str) -> None:
        for subkey in key.subkeys():
            name = subkey.name()
            current_path = f"{parent_path}\\{name}"

            if name == target_subkey:
                # This is the BagMRU or Bags subkey - iterate its values
                for value in subkey.values():
                    data = value.value()
                    if not isinstance(data, bytes):
                        continue
                    # Try to extract info from this binary value
                    folder = _extract_path_from_binary(data)
                    # Try to read view mode (usually at some offset)
                    view_mode = None
                    sort_mode = None
                    try:
                        # Look for view mode byte in data
                        for offset in [4, 8, 12, 16, 20, 24, 28, 32, 36, 40]:
                            if offset < len(data):
                                vm = data[offset]
                                if vm in _VIEW_MODE_MAP:
                                    view_mode = _VIEW_MODE_MAP[vm]
                                    break
                        for offset in [4, 8, 12, 16, 20, 24, 28, 32, 36, 40]:
                            if offset < len(data):
                                sm = data[offset]
                                if sm in _SORT_MODE_MAP:
                                    sort_mode = _SORT_MODE_MAP[sm]
                                    break
                    except (IndexError, TypeError):
                        pass

                    # Extract FILETIME if data is large enough
                    timestamp = None
                    if len(data) >= 8:
                        try:
                            ts = struct.unpack_from("<Q", data, len(data) - 8)[0]
                            ft = _filetime(ts)
                            if ft and 2000 <= ft.year <= 2030:
                                timestamp = ft
                        except (struct.error, ValueError):
                            pass

                    entries.append(ShellbagEntry(
                        bag_type=target_subkey,
                        key_path=current_path,
                        folder_path=folder,
                        view_mode=view_mode,
                        sort_mode=sort_mode,
                        timestamp=timestamp,
                        raw_value_name=value.name(),
                        raw_value_size=len(data),
                    ))

            # Recurse into subkeys
            _walk_shell_keys(subkey, current_path, target_subkey)

    try:
        root = reg.root()
        # Search for Shell keys at common locations
        search_paths = [
            "Software\\Microsoft\\Windows\\Shell",
            "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
        ]
        for search_path in search_paths:
            try:
                target = root
                for part in search_path.split("\\"):
                    found = None
                    for sk in target.subkeys():
                        if sk.name() == part:
                            found = sk
                            break
                    if found is None:
                        target = None
                        break
                    target = found
                if target:
                    _walk_shell_keys(target, search_path, bag_type)
            except Exception:
                continue

        if not entries:
            return [ShellbagEntry(bag_type=bag_type, key_path="", error=f"No {bag_type} entries found in {hive_path}")]

    except Exception as e:
        return [ShellbagEntry(bag_type=bag_type, key_path="", error=f"Error parsing hive: {e}")]

    return entries


def format_shellbag_summary(entry: ShellbagEntry) -> str:
    """Format one entry as a human-readable summary line."""
    if entry.error:
        return f"ERROR: {entry.error}"
    folder = entry.folder_path or "<unknown path>"
    view = entry.view_mode or "?"
    sort = entry.sort_mode or "?"
    ts = entry.timestamp.isoformat() if entry.timestamp else "unknown"
    return f"{folder:50s} | view: {view:12s} | sort: {sort:20s} | accessed: {ts}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m siberian.shellbags_parser <hive_path> [bag_type]")
        print("  bag_type: BagMRU (default) or Bags")
        sys.exit(1)
    hive_path = Path(sys.argv[1])
    bag_type = sys.argv[2] if len(sys.argv) > 2 else "BagMRU"

    entries = parse_shellbags_from_registry(hive_path, bag_type=bag_type)
    print(f"Parsed {len(entries)} Shellbag entries ({bag_type})")
    for entry in entries[:100]:
        print(format_shellbag_summary(entry))
    if len(entries) > 100:
        print(f"... and {len(entries) - 100} more")