"""
siberian/amcache_parser.py
==========================
Windows Amcache.hve (Application Compatibility Cache) parser.

Amcache.hve lives at ``C:\\Windows\\AppCompat\\Programs\\Amcache.hve`` and is a
registry hive holding records of programs the compatibility cache observed.

Structure actually parsed
-------------------------
Only the two documented sections are read, matching the mature `regipy`
implementation:

    \\Root\\File
    \\Root\\InventoryApplicationFile

Subkey values are named either by field name or by a **hexadecimal index**
(``program_id`` is ``"100"``, ``sha1`` is ``"101"``, ...). Both forms are
accepted.

Design constraints and honesty notes
------------------------------------
* **No generic registry scan.** A previous revision walked every key in the
  hive and treated any key containing a value called "Name" or "Path" as an
  application entry. Amcache.hve is a registry hive full of unrelated keys;
  that scan reports programs that do not exist. Only the sections above are
  read, and a hive lacking both is reported as *not an Amcache hive*.

* **No guessed timestamps.** A previous revision interpreted every binary value
  of 8 bytes or more as a FILETIME. Only the three documented timestamp fields
  are converted; the key's own header timestamp is reported separately. An
  unrecognised field stays exactly as it was read.

* **Failures are not entries.** A previous revision returned a synthetic
  "Error" entry whose ``error`` attribute was ``None``, so a caller checking
  ``entry.error`` saw success while the CLI printed "Parsed 1 entries" and
  exited 0. Failures now surface as ``AmcacheResult.errors`` and the CLI exits
  nonzero.

* **Unvalidated against a real hive.** No Amcache.hve exists in this workspace
  and neither python-registry nor regipy can author one, so the field mapping
  is tested against the documented layout but has never run on real evidence.
  See docs/red-team/NIVEL6_AMCACHE_AUDIT.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# The sections that hold file records. Anything else in the hive is not
# treated as an application entry.
AMCACHE_SECTIONS = ("File", "InventoryApplicationFile")

# Hex value-name -> field name. From the mature regipy Amcache plugin.
AMCACHE_FIELD_NUMERIC_MAPPINGS = {
    "0": "product_name",
    "1": "company_name",
    "2": "file_version_number",
    "3": "language_code",
    "4": "switchback_context",
    "5": "file_version",
    "6": "file_size",
    "7": "pe_header_hash",
    "8": "unknown1",
    "9": "pe_header_checksum",
    "a": "unknown2",
    "b": "unknown3",
    "c": "file_description",
    "d": "unknown4",
    "f": "linker_compile_time",
    "10": "unknown5",
    "11": "last_modified_timestamp",
    "12": "created_timestamp",
    "15": "full_path",
    "16": "unknown6",
    "17": "last_modified_timestamp_2",
    "100": "program_id",
    "101": "sha1",
}

# The ONLY fields converted from FILETIME.
AMCACHE_TIMESTAMP_FIELDS = (
    "last_modified_timestamp",
    "created_timestamp",
    "last_modified_timestamp_2",
)

# Fields stored as a hex string carrying a 4-byte binary prefix.
AMCACHE_PREFIXED_FIELDS = ("sha1", "program_id", "file_id")


@dataclass
class AmcacheEntry:
    """One Amcache file record."""

    key_path: str
    section: str
    full_path: Optional[str] = None
    product_name: Optional[str] = None
    company_name: Optional[str] = None
    file_description: Optional[str] = None
    file_version: Optional[str] = None
    file_version_number: Optional[str] = None
    file_size: Optional[int] = None
    sha1: Optional[str] = None
    program_id: Optional[str] = None
    pe_header_hash: Optional[str] = None
    link_date: Optional[int] = None
    is_pe_file: Optional[bool] = None
    is_os_component: Optional[bool] = None
    last_modified_timestamp: Optional[datetime] = None
    created_timestamp: Optional[datetime] = None
    last_modified_timestamp_2: Optional[datetime] = None
    key_timestamp: Optional[datetime] = None
    raw_values: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_path": self.key_path,
            "section": self.section,
            "full_path": self.full_path,
            "product_name": self.product_name,
            "company_name": self.company_name,
            "file_description": self.file_description,
            "file_version": self.file_version,
            "file_version_number": self.file_version_number,
            "file_size": self.file_size,
            "sha1": self.sha1,
            "program_id": self.program_id,
            "pe_header_hash": self.pe_header_hash,
            "link_date": self.link_date,
            "is_pe_file": self.is_pe_file,
            "is_os_component": self.is_os_component,
            "last_modified_timestamp": (
                self.last_modified_timestamp.isoformat()
                if self.last_modified_timestamp
                else None
            ),
            "created_timestamp": (
                self.created_timestamp.isoformat() if self.created_timestamp else None
            ),
            "last_modified_timestamp_2": (
                self.last_modified_timestamp_2.isoformat()
                if self.last_modified_timestamp_2
                else None
            ),
            "key_timestamp": self.key_timestamp.isoformat() if self.key_timestamp else None,
            "raw_values": self.raw_values,
        }


@dataclass
class AmcacheResult:
    """Outcome of parsing an Amcache hive.

    ``entries`` is empty when the hive could not be read. Failures live in
    ``errors`` and ``degraded`` — never in a fabricated entry.
    """

    entries: List[AmcacheEntry] = field(default_factory=list)
    sections_found: List[str] = field(default_factory=list)
    sections_absent: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    degraded: Optional[str] = None

    @property
    def ok(self) -> bool:
        return not self.errors and self.degraded is None and bool(self.entries)


def _filetime_to_datetime(ts: Any) -> Optional[datetime]:
    """Convert a FILETIME to datetime. Exact integer arithmetic, no float."""
    if isinstance(ts, bytes):
        if len(ts) < 8:
            return None
        ts = int.from_bytes(ts[:8], "little")
    if not isinstance(ts, int) or ts <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ts // 10)
    except (OverflowError, OSError, ValueError):
        return None


def _strip_four_byte_prefix(value: Any) -> Optional[str]:
    """Drop the 4-byte (8 hex char) binary prefix some fields carry.

    Output is uppercased regardless of the input's case, so a digest renders
    identically whether the hive stored it as a hex string or as raw bytes.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        if len(value) <= 4:
            return None
        return value[4:].hex().upper()
    if isinstance(value, str):
        stripped = value[8:] if len(value) > 8 else value
        return stripped.upper()
    return None


def _to_int(value: Any) -> Optional[int]:
    """Coerce a registry value to int, treating hex strings as hex."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        try:
            return int.from_bytes(value, "little")
        except (TypeError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16)
        except ValueError:
            try:
                return int(text)
            except ValueError:
                return None
    return None


def normalise_value_names(values: Dict[str, Any]) -> Dict[str, Any]:
    """Map hexadecimal value names onto field names, leaving others intact."""
    out: Dict[str, Any] = {}
    for name, value in values.items():
        key = str(name)
        out[AMCACHE_FIELD_NUMERIC_MAPPINGS.get(key.lower(), key)] = value
    return out


def parse_amcache_entry(
    values: Dict[str, Any],
    key_timestamp: Any = None,
    key_path: str = "",
    section: str = "",
) -> AmcacheEntry:
    """Build one AmcacheEntry from a subkey's raw values.

    Pure function: no registry access, so the field mapping is directly
    testable. ``values`` may use either field names or hexadecimal indices.
    """
    fields = normalise_value_names(values)

    entry = AmcacheEntry(
        key_path=key_path,
        section=section,
        raw_values=dict(fields),
    )

    entry.full_path = _as_text(fields.get("full_path"))
    entry.product_name = _as_text(fields.get("product_name"))
    entry.company_name = _as_text(fields.get("company_name"))
    entry.file_description = _as_text(fields.get("file_description"))
    entry.file_version = _as_text(fields.get("file_version"))
    entry.file_version_number = _as_text(fields.get("file_version_number"))

    # file_size is stored as a hex string.
    entry.file_size = _to_int(fields.get("file_size"))

    for name in AMCACHE_PREFIXED_FIELDS:
        if name in fields:
            stripped = _strip_four_byte_prefix(fields[name])
            if name == "sha1":
                entry.sha1 = stripped
            elif name == "program_id":
                entry.program_id = stripped

    entry.pe_header_hash = _as_text(fields.get("pe_header_hash"))
    entry.link_date = _to_int(fields.get("link_date"))

    for flag in ("is_pe_file", "is_os_component"):
        if flag in fields:
            raw = fields[flag]
            setattr(
                entry,
                flag,
                bool(_to_int(raw)) if isinstance(raw, (int, bytes, str)) else bool(raw),
            )

    # Timestamps: only the documented fields, plus the key header timestamp.
    for name in AMCACHE_TIMESTAMP_FIELDS:
        if name in fields:
            setattr(entry, name, _filetime_to_datetime(fields[name]))
    entry.key_timestamp = _filetime_to_datetime(key_timestamp)

    return entry


def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le").rstrip("\x00") or None
        except UnicodeDecodeError:
            return value.hex()
    text = str(value).rstrip("\x00")
    return text or None


def parse_amcache_hive(hive_path: Path) -> AmcacheResult:
    """Parse an Amcache.hve registry hive.

    Only ``\\Root\\File`` and ``\\Root\\InventoryApplicationFile`` are read.
    A hive without either is reported as not an Amcache hive rather than
    scanned for anything that resembles a program record.
    """
    hive_path = Path(hive_path)
    result = AmcacheResult()

    try:
        from Registry import Registry
    except ImportError:
        result.degraded = (
            "python-registry (Registry module) not installed: the hive cannot "
            "be read at all. No entries are reported rather than guessed."
        )
        return result

    if not hive_path.is_file():
        result.errors.append(f"Hive not found: {hive_path}")
        return result

    try:
        hive = Registry.Registry(str(hive_path))
    except Exception as exc:
        result.errors.append(f"Cannot open hive: {exc}")
        return result

    try:
        root = hive.root()
    except Exception as exc:
        result.errors.append(f"Cannot read hive root: {exc}")
        return result

    for section in AMCACHE_SECTIONS:
        try:
            section_key = root.subkey(section)
        except Exception:
            section_key = root.subkey(f"Root\\{section}")
        if section_key is None:
            result.sections_absent.append(section)
            continue

        result.sections_found.append(section)
        for subkey in _safe_subkeys(section_key):
            key_path = _safe_path(subkey, section)
            try:
                values = {v.name(): v.value() for v in subkey.values()}
            except Exception as exc:
                result.errors.append(f"{key_path}: cannot read values: {exc}")
                continue
            try:
                timestamp = subkey.timestamp()
            except Exception:
                timestamp = None
            result.entries.append(
                parse_amcache_entry(
                    values,
                    key_timestamp=timestamp,
                    key_path=key_path,
                    section=section,
                )
            )

    if not result.sections_found:
        result.errors.append(
            "Not an Amcache hive: neither "
            + " nor ".join(f"\\Root\\{s}" for s in AMCACHE_SECTIONS)
            + " is present."
        )

    return result


def _safe_subkeys(key) -> List[Any]:
    try:
        return list(key.subkeys())
    except Exception:
        return []


def _safe_path(subkey, section: str) -> str:
    try:
        return subkey.path()
    except Exception:
        name = subkey.name() if hasattr(subkey, "name") else "?"
        return f"\\Root\\{section}\\{name}"


def format_amcache_summary(entry: AmcacheEntry) -> str:
    """Format one entry as a single terminal line."""
    path = entry.full_path or entry.key_path
    product = entry.product_name or "<unknown product>"
    size = entry.file_size if entry.file_size is not None else "?"
    return (
        f"{path[:60]:60s} | {product[:32]:32s} | size={str(size):>12s} "
        f"| section={entry.section}"
    )
