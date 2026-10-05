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
    # Parsed attributes
    standard_info: Optional[StandardInformation] = None
    file_names: List[FileNameAttribute] = field(default_factory=list)
    raw_attributes: List[MftAttributeHeader] = field(default_factory=list)
    # Validity
    is_valid: bool = True
    error: Optional[str] = None


def _ntfs_timestamp_to_datetime(ts: int) -> Optional[datetime]:
    """Convert NTFS FILETIME (100ns intervals since 1601-01-01) to datetime."""
    if ts == 0:
        return None
    try:
        # FILETIME is 100-nanosecond intervals
        delta = timedelta(microseconds=ts / 10)
        return NTFS_EPOCH + delta
    except (OverflowError, OSError):
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


def parse_mft_attribute_list(data: bytes, offset: int) -> Optional[MftAttributeHeader]:
    """Parse one attribute header at the given offset."""
    if offset + 16 > len(data):
        return None
    attr_type, size, name_len, name_off, flags, attr_id = struct.unpack_from("<IIBBHH", data, offset)
    if attr_type == 0xFFFFFFFF:
        return None  # End of attribute list
    if size < 16 or size > len(data) - offset:
        return None
    attr = MftAttributeHeader(
        attr_type=attr_type,
        size=size,
        name_length=name_len,
        name_offset=name_off,
        flags=flags,
        attr_id=attr_id,
        raw_data=data[offset + 16:offset + size] if size >= 16 else b"",
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


def parse_mft_record(data: bytes, record_number: int) -> MftRecord:
    """Parse one MFT record from raw bytes (assumes record-sized buffer)."""
    if len(data) < 1024:
        return MftRecord(record_number=record_number, sequence_number=0, flags=0, is_valid=False, error=f"Record buffer too small: {len(data)} < 1024")
    # Verify signature
    if data[0:4] != MFT_RECORD_SIGNATURE:
        return MftRecord(record_number=record_number, sequence_number=0, flags=0, is_valid=False, error=f"Invalid signature: {data[0:4]}")
    # Manual parse of header fields (struct.unpack is fragile with many fields)
    fixup_offset = struct.unpack_from("<H", data, 4)[0]
    fixup_size = struct.unpack_from("<H", data, 6)[0]
    seq = struct.unpack_from("<H", data, 16)[0]
    hard_links = struct.unpack_from("<H", data, 18)[0]
    first_attr_offset = struct.unpack_from("<H", data, 20)[0]
    flags = struct.unpack_from("<H", data, 22)[0]
    real_size = struct.unpack_from("<I", data, 24)[0]
    allocated_size = struct.unpack_from("<I", data, 28)[0]
    record_number_le = struct.unpack_from("<I", data, 44)[0]

    is_in_use = bool(flags & 0x01)
    is_directory = bool(flags & 0x02)

    record = MftRecord(
        record_number=record_number,
        sequence_number=seq,
        flags=flags,
        is_in_use=is_in_use,
        is_directory=is_directory,
        real_size=real_size,
        allocated_size=allocated_size,
        first_attr_offset=first_attr_offset,
        hard_link_count=hard_links,
    )

    # Parse attributes
    offset = first_attr_offset
    while offset < allocated_size and offset < len(data):
        attr = parse_mft_attribute_list(data, offset)
        if attr is None:
            break
        record.raw_attributes.append(attr)
        # For resident attributes, data follows immediately
        if attr.attr_type == ATTR_STANDARD_INFORMATION:
            # Resident: content is in raw_data (offset 16 within attribute)
            # The raw_data already contains the attribute content after the header
            si = parse_standard_information(attr.raw_data)
            record.standard_info = si
        elif attr.attr_type == ATTR_FILE_NAME:
            fn = parse_file_name_attribute(attr.raw_data)
            record.file_names.append(fn)
        offset += attr.size

    return record


def parse_mft_file(mft_path: Path, max_records: int = 0) -> List[MftRecord]:
    """Parse $MFT binary file and return list of parsed records.
    
    Args:
        mft_path: Path to $MFT file
        max_records: Maximum number of records to parse (0 = all)
    
    Returns:
        List of MftRecord objects
    """
    records: List[MftRecord] = []
    # MFT record size is typically 1024 bytes
    record_size = 1024
    try:
        with open(mft_path, "rb") as f:
            record_index = 0
            while True:
                chunk = f.read(record_size)
                if not chunk or len(chunk) < record_size:
                    break
                record = parse_mft_record(chunk, record_index)
                records.append(record)
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