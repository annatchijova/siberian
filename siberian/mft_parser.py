"""
siberian/mft_parser.py
======================
NTFS $MFT (Master File Table) record parser — extracts file metadata from
raw $MFT binary files acquired from Windows systems.

Design constraints:
- No external dependencies (stdlib only)
- Terminal-only output
- Each MFT record is an independent evidence item
- Output compatible with SIBERIAN case file format

MFT Record Binary Format:
    Offset  Size  Description
    0x00    4     Signature ("FILE" = 0x454C4946 LE)
    0x04    2     Fixup array offset
    0x06    2     Fixup array size
    0x08    8     $LogFile sequence number
    0x10    2     Sequence number
    0x12    2     Hard link count
    0x14    2     First attribute offset
    0x16    2     Flags (bit 0: in-use, bit 1: directory)
    0x18    4     Real record size
    0x1C    4     Allocated record size (typically 1024)
    0x20    8     Base record reference (for extension records)
    0x28    2     Next attribute ID
    0x2A    2     Reserved
    0x2C    4     Record number

Attribute header:
    Offset  Size  Description
    0x00    4     Type ID (e.g. 0x10=$STANDARD_INFORMATION, 0x30=$FILE_NAME)
    0x04    4     Size (including header; 0xFFFFFFFF if non-resident continuation)
    0x08    1     Name length
    0x09    1     Name offset
    0x0A    2     Flags
    0x0C    2     Attribute ID
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# NTFS epoch: 1601-01-01 00:00:00 UTC
# NTFS timestamps are 64-bit FILETIME (100-nanosecond intervals since 1601-01-01)
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FILETIME_INTERVAL = timedelta(microseconds=0.1)  # 100ns


class MftParseError(Exception):
    """Raised when MFT record parsing fails."""


# MFT record signatures
MFT_RECORD_SIGNATURE = b"FILE"

# Attribute type IDs
ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_VOLUME_NAME = 0x60
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_LOGGED_UTILITY_STREAM = 0x100


@dataclass
class MftAttributeHeader:
    """Parsed MFT attribute header."""
    attr_type: int
    size: int
    name_length: int
    name_offset: int
    flags: int
    attr_id: int
    raw_data: bytes = b""
    is_resident: bool = True


@dataclass
class StandardInformation:
    """$STANDARD_INFORMATION attribute content."""
    creation_time: Optional[datetime] = None
    modification_time: Optional[datetime] = None
    mft_modification_time: Optional[datetime] = None
    access_time: Optional[datetime] = None
    file_attributes: int = 0
    max_versions: int = 0
    version_number: int = 0
    class_id: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "creation_time": self.creation_time.isoformat() if self.creation_time else None,
            "modification_time": self.modification_time.isoformat() if self.modification_time else None,
            "mft_modification_time": self.mft_modification_time.isoformat() if self.mft_modification_time else None,
            "access_time": self.access_time.isoformat() if self.access_time else None,
            "file_attributes": self.file_attributes,
            "max_versions": self.max_versions,
            "version_number": self.version_number,
            "class_id": self.class_id,
        }


@dataclass
class FileNameAttribute:
    """$FILE_NAME attribute content."""
    parent_directory: Optional[int] = None
    creation_time: Optional[datetime] = None
    modification_time: Optional[datetime] = None
    mft_modification_time: Optional[datetime] = None
    access_time: Optional[datetime] = None
    file_size: int = 0
    real_size: int = 0
    flags: int = 0
    name: Optional[str] = None
    namespace: int = 0  # 0=POSIX, 1=WIN32, 2=DOS, 3=WIN32+DOS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parent_directory": self.parent_directory,
            "creation_time": self.creation_time.isoformat() if self.creation_time else None,
            "modification_time": self.modification_time.isoformat() if self.modification_time else None,
            "mft_modification_time": self.mft_modification_time.isoformat() if self.mft_modification_time else None,
            "access_time": self.access_time.isoformat() if self.access_time else None,
            "file_size": self.file_size,
            "real_size": self.real_size,
            "flags": self.flags,
            "name": self.name,
            "namespace": self.namespace,
        }


@dataclass
class MftRecord:
    """Parsed MFT record."""
    record_number: int
    sequence_number: int
    flags: int
    is_in_use: bool = False
    is_directory: bool = False
    real_size: int = 0
    allocated_size: int = 0
    first_attr_offset: int = 0
    hard_link_count: int = 0
    # Provenance / integrity
    expected_record_number: Optional[int] = None  # index supplied by the caller
    record_number_matches: Optional[bool] = None   # embedded vs expected
    fixups_applied: bool = False
    # Parsed attributes
    standard_info: Optional[StandardInformation] = None
    file_names: List[FileNameAttribute] = field(default_factory=list)
    raw_attributes: List[MftAttributeHeader] = field(default_factory=list)
    # Validity
    is_valid: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_number": self.record_number,
            "expected_record_number": self.expected_record_number,
            "record_number_matches": self.record_number_matches,
            "sequence_number": self.sequence_number,
            "flags": self.flags,
            "is_in_use": self.is_in_use,
            "is_directory": self.is_directory,
            "real_size": self.real_size,
            "allocated_size": self.allocated_size,
            "first_attr_offset": self.first_attr_offset,
            "hard_link_count": self.hard_link_count,
            "fixups_applied": self.fixups_applied,
            "standard_info": self.standard_info.to_dict() if self.standard_info else None,
            "file_names": [fn.to_dict() for fn in self.file_names],
            "attribute_count": len(self.raw_attributes),
            "attribute_types": [a.attr_type for a in self.raw_attributes],
            "is_valid": self.is_valid,
            "error": self.error,
        }


def _ntfs_timestamp_to_datetime(ts: int) -> Optional[datetime]:
    """Convert NTFS FILETIME (100ns intervals since 1601-01-01) to datetime.

    Uses integer division (ts // 10) rather than float division so the
    conversion stays exact and reproducible: FILETIME counts 100-nanosecond
    units, so whole microseconds are ts // 10 with the sub-microsecond
    remainder dropped deterministically.
    """
    if ts == 0:
        return None
    if ts < 0:
        return None
    try:
        delta = timedelta(microseconds=ts // 10)
        return NTFS_EPOCH + delta
    except (OverflowError, OSError, ValueError):
        return None


def _filetime_to_epoch_offset(ts: int) -> Optional[float]:
    """Return seconds since Unix epoch, or None if invalid/zero."""
    if ts == 0:
        return None
    try:
        dt = _ntfs_timestamp_to_datetime(ts)
        if dt is None:
            return None
        return dt.timestamp()
    except (OverflowError, OSError):
        return None


def apply_fixups(data: bytes) -> Tuple[bytes, Optional[str]]:
    """Apply the MFT update sequence array (fixups) to a raw record.

    NTFS does not store the last two bytes of each sector verbatim. On write it
    replaces them with the 16-bit update sequence number, and keeps the real
    bytes in the "fixup array" at fixup_offset. A record read straight off disk
    therefore has a corrupted signature ("FIL0" instead of "FILE") and
    corrupted trailing values until the fixups are applied.

    Fixups MUST be applied before the signature or any other field is trusted.

    Args:
        data: raw record bytes as read from the volume

    Returns:
        (fixed_bytes, None) on success, or (data, error_message) on failure
    """
    if len(data) < 8:
        return data, "Record too small for fixup header"

    fixup_offset = struct.unpack_from("<H", data, 4)[0]
    fixup_count = struct.unpack_from("<H", data, 6)[0]

    # fixup_count includes the update sequence number itself, so the number of
    # protected positions is fixup_count - 1. A count of 0 or 1 means no
    # sectors are protected.
    if fixup_count == 0:
        return data, None
    if fixup_count < 1:
        return data, f"Invalid fixup count: {fixup_count}"
    if fixup_offset + fixup_count * 2 > len(data):
        return data, (
            f"Fixup array out of bounds: offset={fixup_offset} "
            f"count={fixup_count} record_size={len(data)}"
        )
    if fixup_offset < 8 or fixup_offset % 2:
        return data, f"Invalid fixup array offset: {fixup_offset}"

    update_sequence_number = struct.unpack_from("<H", data, fixup_offset)[0]

    buf = bytearray(data)
    # Each entry after the first provides the real bytes for one sector tail.
    for i in range(1, fixup_count):
        saved = struct.unpack_from("<H", data, fixup_offset + i * 2)[0]
        sector_end = (i - 1) * 512 + 510
        if sector_end + 2 > len(buf):
            return data, f"Fixup target out of bounds: offset={sector_end}"
        # Only overwrite if the on-disk tail still holds the update sequence
        # number. If it does not, the record was written without fixups (or was
        # already repaired) and silently rewriting would corrupt real data.
        current = struct.unpack_from("<H", buf, sector_end)[0]
        if current == update_sequence_number:
            struct.pack_into("<H", buf, sector_end, saved)
    return bytes(buf), None


def parse_mft_attribute_list(data: bytes, offset: int) -> Optional[MftAttributeHeader]:
    """Parse one attribute header at the given offset.

    Handles the resident/non-resident distinction: a resident attribute carries
    an 8-byte resident header after the 16-byte generic header, and its content
    begins at the resident content offset (normally 0x18), NOT at +16. Reading
    content from +16 shifts every resident field by 8 bytes, which silently
    misreports e.g. creation time as modification time.
    """
    if offset + 16 > len(data):
        return None
    attr_type, size, name_len, name_off, flags, attr_id = struct.unpack_from("<IIBBHH", data, offset)
    if attr_type == 0xFFFFFFFF:
        return None  # End of attribute list
    if size < 16 or size > len(data) - offset:
        return None

    is_resident = not (flags & 0x0001)

    if is_resident:
        # Resident header: 0x10 content length, 0x14 content offset, 0x16 indexed flag
        if offset + 24 > len(data):
            return None
        content_length = struct.unpack_from("<I", data, offset + 16)[0]
        content_offset = struct.unpack_from("<H", data, offset + 20)[0]
        if content_offset < 24 or content_offset > size:
            return None
        content_end = min(offset + content_offset + content_length, offset + size)
        raw_data = data[offset + content_offset:content_end]
    else:
        # Non-resident: raw_data holds the run list / mapping pairs, not content.
        raw_data = data[offset + 16:offset + size]

    attr = MftAttributeHeader(
        attr_type=attr_type,
        size=size,
        name_length=name_len,
        name_offset=name_off,
        flags=flags,
        attr_id=attr_id,
        raw_data=raw_data,
        is_resident=is_resident,
    )
    return attr


def parse_standard_information(data: bytes) -> StandardInformation:
    """Parse $STANDARD_INFORMATION attribute (resident, 72 bytes)."""
    if len(data) < 48:
        return StandardInformation()
    creation, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", data, 0)
    file_attrs, max_versions, version, class_id = struct.unpack_from("<IIII", data, 32)
    return StandardInformation(
        creation_time=_ntfs_timestamp_to_datetime(creation),
        modification_time=_ntfs_timestamp_to_datetime(modified),
        mft_modification_time=_ntfs_timestamp_to_datetime(mft_modified),
        access_time=_ntfs_timestamp_to_datetime(accessed),
        file_attributes=file_attrs,
        max_versions=max_versions,
        version_number=version,
        class_id=class_id,
    )


def parse_file_name_attribute(data: bytes) -> FileNameAttribute:
    """Parse $FILE_NAME attribute."""
    if len(data) < 66:
        return FileNameAttribute()
    parent_ref, creation, modified, mft_modified, accessed = struct.unpack_from("<QQQQQ", data, 0)
    file_size, real_size = struct.unpack_from("<QQ", data, 40)
    flags, name_len, namespace = struct.unpack_from("<IBB", data, 56)
    parent_directory = parent_ref >> 48
    name_offset = 66
    if name_offset + name_len * 2 > len(data):
        return FileNameAttribute(parent_directory=parent_directory)
    try:
        name = data[name_offset:name_offset + name_len * 2].decode("utf-16-le")
    except UnicodeDecodeError:
        name = None
    return FileNameAttribute(
        parent_directory=parent_directory,
        creation_time=_ntfs_timestamp_to_datetime(creation),
        modification_time=_ntfs_timestamp_to_datetime(modified),
        mft_modification_time=_ntfs_timestamp_to_datetime(mft_modified),
        access_time=_ntfs_timestamp_to_datetime(accessed),
        file_size=file_size,
        real_size=real_size,
        flags=flags,
        name=name,
        namespace=namespace,
    )


def parse_mft_record(data: bytes, record_number: int, record_size: int = 1024) -> MftRecord:
    """Parse one MFT record from raw bytes as read off the volume.

    Applies the update sequence array before validating the signature, because
    on-disk records have their signature's last byte replaced by the update
    sequence number. Validating first would reject every genuine record.

    Args:
        data: raw record bytes
        record_number: expected record number (the caller's index)
        record_size: allocated record size, used for bounds checks
    """
    if len(data) < 42:
        return MftRecord(
            record_number=record_number,
            sequence_number=0,
            flags=0,
            expected_record_number=record_number,
            is_valid=False,
            error=f"Record buffer too small: {len(data)} < 42",
        )

    # Fixups first — nothing below is trustworthy until they are applied.
    fixed, fixup_error = apply_fixups(data)
    if fixup_error is not None:
        return MftRecord(
            record_number=record_number,
            sequence_number=0,
            flags=0,
            expected_record_number=record_number,
            is_valid=False,
            error=f"Fixup failure: {fixup_error}",
        )

    if fixed[0:4] != MFT_RECORD_SIGNATURE:
        return MftRecord(
            record_number=record_number,
            sequence_number=0,
            flags=0,
            expected_record_number=record_number,
            fixups_applied=True,
            is_valid=False,
            error=f"Invalid signature after fixups: {fixed[0:4]!r}",
        )

    fixup_offset = struct.unpack_from("<H", fixed, 4)[0]
    fixup_size = struct.unpack_from("<H", fixed, 6)[0]
    seq = struct.unpack_from("<H", fixed, 16)[0]
    hard_links = struct.unpack_from("<H", fixed, 18)[0]
    first_attr_offset = struct.unpack_from("<H", fixed, 20)[0]
    flags = struct.unpack_from("<H", fixed, 22)[0]
    real_size = struct.unpack_from("<I", fixed, 24)[0]
    allocated_size = struct.unpack_from("<I", fixed, 28)[0]
    # Record number is authoritative in the record itself (0x2C), not the
    # caller's index. Comparing the two is itself provenance worth keeping.
    embedded_record_number = struct.unpack_from("<I", fixed, 44)[0]

    is_in_use = bool(flags & 0x01)
    is_directory = bool(flags & 0x02)

    record = MftRecord(
        record_number=embedded_record_number,
        expected_record_number=record_number,
        record_number_matches=embedded_record_number == record_number,
        sequence_number=seq,
        flags=flags,
        is_in_use=is_in_use,
        is_directory=is_directory,
        real_size=real_size,
        allocated_size=allocated_size,
        first_attr_offset=first_attr_offset,
        hard_link_count=hard_links,
        fixups_applied=True,
    )

    # Bounds-check the attribute area before walking it. The first attribute
    # must sit after the 42+ byte header and inside the record.
    if first_attr_offset < 42 or first_attr_offset >= len(fixed):
        record.error = (
            f"first_attr_offset out of bounds: {first_attr_offset} "
            f"(record size {len(fixed)})"
        )
        return record

    limit = min(allocated_size if allocated_size else len(fixed), len(fixed))

    offset = first_attr_offset
    while offset + 4 <= limit:
        attr = parse_mft_attribute_list(fixed, offset)
        if attr is None:
            break
        record.raw_attributes.append(attr)
        # $STANDARD_INFORMATION and $FILE_NAME are always resident; a
        # non-resident instance means we are not looking at real content and
        # must not interpret the run list as timestamps/names.
        if attr.attr_type == ATTR_STANDARD_INFORMATION and attr.is_resident:
            record.standard_info = parse_standard_information(attr.raw_data)
        elif attr.attr_type == ATTR_FILE_NAME and attr.is_resident:
            record.file_names.append(parse_file_name_attribute(attr.raw_data))
        if attr.size < 16:
            break
        offset += attr.size

    return record


def detect_mft_record_size(first_record: bytes) -> int:
    """Determine the MFT record size from record 0's allocated size.

    $MFT records are 1024 bytes on most volumes but 4096 on large/dynamic
    volumes. Hardcoding 1024 misaligns every subsequent record, which then
    fails signature validation and looks like corruption.

    Falls back to 1024 when record 0 cannot be inspected.
    """
    if len(first_record) < 48:
        return 1024
    allocated = struct.unpack_from("<I", first_record, 28)[0]
    # Accept only sane power-of-two-ish record sizes within the buffer.
    if allocated in (256, 512, 1024, 2048, 4096) and allocated <= len(first_record):
        return allocated
    return 1024


def parse_mft_file(mft_path: Path, max_records: int = 0) -> List[MftRecord]:
    """Parse $MFT binary file and return list of parsed records.

    The record size is detected from the volume's first record rather than
    assumed, so 4096-byte records parse correctly.

    Args:
        mft_path: Path to $MFT file
        max_records: Maximum number of records to parse (0 = all)

    Returns:
        List of MftRecord objects, in file order. Records that failed to parse
        are returned with is_valid=False and an explicit error, never dropped
        silently and never substituted with a guess.
    """
    records: List[MftRecord] = []
    try:
        with open(mft_path, "rb") as f:
            probe = f.read(4096)
            if not probe:
                return []
            record_size = detect_mft_record_size(probe)
            f.seek(0)

            record_index = 0
            while True:
                chunk = f.read(record_size)
                if not chunk:
                    break
                if len(chunk) < record_size:
                    # Trailing partial record: report it rather than silently
                    # discarding evidence that something is off.
                    records.append(
                        MftRecord(
                            record_number=record_index,
                            expected_record_number=record_index,
                            sequence_number=0,
                            flags=0,
                            is_valid=False,
                            error=(
                                f"Truncated final record: {len(chunk)} bytes "
                                f"< record size {record_size}"
                            ),
                        )
                    )
                    break
                records.append(parse_mft_record(chunk, record_index, record_size=record_size))
                record_index += 1
                if max_records > 0 and record_index >= max_records:
                    break
    except (IOError, OSError) as e:
        raise IOError(f"Cannot read MFT file: {e}") from e
    return records


# ---------------------------------------------------------------------------
# CLI and utility functions
# ---------------------------------------------------------------------------

def format_mft_record_summary(record: MftRecord) -> str:
    """Format one record as a human-readable summary line."""
    if not record.is_valid:
        return f"Record {record.record_number}: INVALID ({record.error})"
    status = "IN_USE" if record.is_in_use else "DELETED"
    type_ = "DIR" if record.is_directory else "FILE"
    name = record.file_names[0].name if record.file_names and record.file_names[0].name else "<unknown>"
    si = record.standard_info
    created = si.creation_time.isoformat() if si and si.creation_time else "N/A"
    modified = si.modification_time.isoformat() if si and si.modification_time else "N/A"
    return f"Record {record.record_number:5d} | {status:8s} | {type_:4s} | {name:40s} | created: {created} | modified: {modified}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m siberian.mft_parser <path_to_$MFT> [max_records]")
        sys.exit(1)
    mft_path = Path(sys.argv[1])
    max_records = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    records = parse_mft_file(mft_path, max_records=max_records)
    print(f"Parsed {len(records)} records")
    for record in records[:100]:
        print(format_mft_record_summary(record))
    if len(records) > 100:
        print(f"... and {len(records) - 100} more")