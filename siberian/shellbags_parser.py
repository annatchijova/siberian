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
    """One folder path recovered from a Shellbags value.

    Only the path is reported. View mode, sort mode and an "accessed"
    timestamp were previously invented by matching arbitrary bytes against
    lookup tables; those fields are gone rather than kept as unverified
    guesses. See docs/red-team/NIVEL6_SHELLBAGS_AUDIT.md.
    """

    bag_type: str  # "BagMRU" or "Bags"
    key_path: str  # Registry key path
    folder_path: Optional[str] = None
    raw_value_name: str = ""
    raw_value_size: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bag_type": self.bag_type,
            "key_path": self.key_path,
            "folder_path": self.folder_path,
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
    if ts <= 0:
        return None
    try:
        microseconds = ts // 10
        return _FILETIME_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, OSError):
        return None


def _extract_utf16_paths(data: bytes, max_chars: int = 1024) -> List[Tuple[int, str]]:
    """Extract UTF-16-LE path strings from a binary blob.

    Alignment matters. UTF-16-LE code units are two bytes, so a scan must start
    on an even offset and must stop on an even offset; otherwise the slice has an
    odd length and decoding silently drops the final character.

    The previous implementation searched for b"\x00\x00" from a moving offset
    and sliced to wherever that landed. On an odd offset it produced
    "C:\\Users\\Bob\\Deskto" for "C:\\Users\\Bob\\Desktop" -- a wrong
    path that still looks like a real one -- and it missed paths preceded by
    other bytes almost every time (199 of 200 in testing).

    Returns (offset, path) pairs. Order is stable: ascending offset.
    """
    # A registry value's payload may begin at either byte alignment relative to
    # the original structure, so both parities are scanned and identical strings
    # are reported once.
    results: List[Tuple[int, str]] = []
    seen: set = set()
    for parity in (0, 1):
        i = parity
        while i + 1 < len(data):
            chars: List[str] = []
            j = i
            while j + 1 < len(data) and len(chars) < max_chars:
                unit = data[j] | (data[j + 1] << 8)
                if unit == 0:
                    break
                # Reject control characters: a real path is printable text.
                if unit < 0x20 or unit in (0xFFFE, 0xFFFF):
                    break
                chars.append(chr(unit))
                j += 2

            text = "".join(chars)
            if len(text) > 3 and _looks_like_path(text) and text not in seen:
                seen.add(text)
                results.append((i, text))
                i = j + 2
                continue
            i += 2
    results.sort(key=lambda pair: pair[0])
    return results


def _looks_like_path(text: str) -> bool:
    """True when the text plausibly is a filesystem path."""
    if len(text) < 4:
        return False
    if text.startswith("\\\\"):
        return True
    # Drive-letter form: "C:\..." or "C:/..."
    return len(text) > 3 and text[1] == ":" and text[2] in ("\\", "/")


def _extract_path_from_binary(data: bytes) -> Optional[str]:
    """Return the first path in the blob, or None."""
    found = _extract_utf16_paths(data)
    return found[0][1] if found else None


def parse_shellbags_from_registry(
    hive_path: Path, bag_type: str = "BagMRU"
) -> List[ShellbagEntry]:
    """Recover folder paths from Shellbags values in a user registry hive.

    Both tree levels are read. In a real hive the per-entry data lives in the
    numbered subkeys *below* ``BagMRU``/``Bags``, not on those keys themselves;
    the previous revision read only the latter and so recovered nothing from a
    real hive. Both levels are now read.

    Only folder paths are reported. No view mode, sort mode or timestamp is
    emitted: those were previously matched by scanning arbitrary bytes against
    lookup tables, which produced confident values with no positional
    justification.

    Args:
        hive_path: Path to a registry hive (NTUSER.DAT or UsrClass.dat)
        bag_type: "BagMRU" or "Bags"

    Returns:
        List of ShellbagEntry. Failures are returned as a single entry carrying
        an explicit error rather than as a silent empty result.
    """
    hive_path = Path(hive_path)
    try:
        from Registry import Registry
    except ImportError:
        return [ShellbagEntry(
            bag_type=bag_type,
            key_path="",
            error="python-registry not installed: pip install python-registry",
        )]

    try:
        hive = Registry.Registry(str(hive_path))
    except Exception as exc:
        return [ShellbagEntry(
            bag_type=bag_type, key_path="", error=f"Cannot open hive: {exc}"
        )]

    try:
        root = hive.root()
    except Exception as exc:
        return [ShellbagEntry(
            bag_type=bag_type, key_path="", error=f"Cannot read hive root: {exc}"
        )]

    # Locations that hold Shellbags. Classes-based paths live in UsrClass.dat.
    search_roots = [
        r"Software\Microsoft\Windows\Shell",
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell",
    ]

    entries: List[ShellbagEntry] = []
    searched: List[str] = []
    found_roots = 0

    for search_root in search_roots:
        node = _resolve(root, search_root)
        if node is None:
            continue
        found_roots += 1
        searched.append(search_root)
        _collect(node, search_root, bag_type, entries, depth=0)

    if found_roots == 0:
        return [ShellbagEntry(
            bag_type=bag_type,
            key_path="",
            error=(
                f"No Shell\\{bag_type} location found. Looked under: "
                + "; ".join(search_roots)
            ),
        )]

    if not entries:
        return [ShellbagEntry(
            bag_type=bag_type,
            key_path="",
            error=(
                f"No folder paths recovered from {bag_type} under "
                + "; ".join(searched)
                + ". The keys exist but no UTF-16 path was decoded from their "
                "binary values; this parser does not decode the shellbag "
                "record layout."
            ),
        )]

    return entries


# Guard against a pathological or cyclic hive.
_MAX_DEPTH = 8


def _collect(node, path: str, bag_type: str, entries: List[ShellbagEntry], depth: int) -> None:
    """Read values at this level and descend, when this node is a bag key."""
    if depth > _MAX_DEPTH:
        return

    for value in _safe(node.values):
        try:
            data = value.value()
            name = value.name()
        except Exception:
            continue
        if not isinstance(data, bytes) or len(data) < 8:
            continue
        # Skip the well-known bookkeeping values that are not entry records.
        if name in ("MRUList", "NodeSlotCapacity"):
            continue
        folder = _extract_path_from_binary(data)
        if not folder:
            continue
        entries.append(ShellbagEntry(
            bag_type=bag_type,
            key_path=path,
            folder_path=folder,
            raw_value_name=name,
            raw_value_size=len(data),
        ))

    for subkey in _safe(node.subkeys):
        try:
            child_name = subkey.name()
        except Exception:
            continue
        child_path = f"{path}\\{child_name}"
        # The bag keys hold entry data both directly and one level down.
        if child_name == bag_type or _is_bag_child(child_name):
            _collect(subkey, child_path, bag_type, entries, depth + 1)


def _is_bag_child(name: str) -> bool:
    """BagMRU/Bags children are hexadecimal slot indices ("0", "1a", "2f", ...)."""
    if not name:
        return False
    try:
        int(name, 16)
    except ValueError:
        return False
    return True


def _resolve(root, path: str):
    """Walk a backslash-separated registry path, returning None if absent."""
    node = root
    for part in path.split("\\"):
        if not part:
            continue
        nxt = None
        for sk in _safe(node.subkeys):
            try:
                if sk.name() == part:
                    nxt = sk
                    break
            except Exception:
                continue
        if nxt is None:
            return None
        node = nxt
    return node


def _safe(getter) -> List[Any]:
    try:
        return list(getter())
    except Exception:
        return []


def format_shellbag_summary(entry: ShellbagEntry) -> str:
    """Format one entry as a human-readable summary line."""
    if entry.error:
        return f"ERROR: {entry.error}"
    folder = entry.folder_path or "<no path recovered>"
    return f"{folder:64s} | {entry.bag_type:8s} | {entry.key_path}"


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