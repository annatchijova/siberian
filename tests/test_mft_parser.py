"""Tests for NTFS $MFT binary parser."""
from __future__ import annotations

import struct
from pathlib import Path

from siberian.mft_parser import parse_mft_record, MftParseError, MftRecord, _ntfs_timestamp_to_datetime


def _make_minimal_mft_record(
    record_number: int = 0,
    sequence: int = 1,
    flags: int = 0x01,  # in-use
) -> bytes:
    """Build a minimal valid MFT record (1024 bytes) with one $STANDARD_INFORMATION attribute."""
    record = bytearray(1024)
    # Signature
    record[0:4] = b"FILE"
    # Fixup (simplified: no fixup applied)
    struct.pack_into("<H", record, 4, 0)  # fixup offset = 0
    struct.pack_into("<H", record, 6, 0)  # fixup size = 0
    # Logfile seq
    struct.pack_into("<Q", record, 8, 0)
    # Sequence number
    struct.pack_into("<H", record, 16, sequence)
    # Hard link count
    struct.pack_into("<H", record, 18, 1)
    # First attribute offset - point to offset 56 (after the 1024-byte record header region)
    # Actually, first attribute offset is typically around 0x38 (56)
    struct.pack_into("<H", record, 20, 56)
    # Flags
    struct.pack_into("<H", record, 22, flags)
    # Real record size
    struct.pack_into("<I", record, 24, 0x38 + 56 + 16)  # approx
    # Allocated size
    struct.pack_into("<I", record, 28, 1024)
    # Base record reference
    struct.pack_into("<Q", record, 32, 0)
    # Next attribute ID
    struct.pack_into("<H", record, 40, 0)
    # Record number
    struct.pack_into("<I", record, 44, record_number)

    # Standard Information attribute at offset 56
    attr_offset = 56
    # Attribute type
    struct.pack_into("<I", record, attr_offset, 0x10)  # $STANDARD_INFORMATION
    # Attribute size (resident, not counting name)
    # SI resident content is 48 bytes (4 FILETIME + 4 uint32 fields)
    si_content_size = 48
    attr_size = 16 + si_content_size  # header + content
    struct.pack_into("<I", record, attr_offset + 4, attr_size)
    record[attr_offset + 8] = 0  # name length
    record[attr_offset + 9] = 0  # name offset
    struct.pack_into("<H", record, attr_offset + 10, 0)  # flags
    struct.pack_into("<H", record, attr_offset + 12, 0)  # attr_id
    # Resident content: content offset
    struct.pack_into("<H", record, attr_offset + 20, 24)  # content starts at offset 24 in attr header
    struct.pack_into("<I", record, attr_offset + 16, si_content_size)  # content size

    # $STANDARD_INFORMATION content: 4 FILETIME + 4 uint32
    si_offset = attr_offset + 24
    # FILETIME: creation, modified, mft_modified, accessed
    now_filetime = int((datetime_offset := 0) or 0)
    struct.pack_into("<Q", record, si_offset, 0)  # creation
    struct.pack_into("<Q", record, si_offset + 8, 0)  # modified
    struct.pack_into("<Q", record, si_offset + 16, 0)  # mft_modified
    struct.pack_into("<Q", record, si_offset + 24, 0)  # accessed
    struct.pack_into("<I", record, si_offset + 32, 0)  # file_attributes
    struct.pack_into("<I", record, si_offset + 36, 0)  # max_versions
    struct.pack_into("<I", record, si_offset + 40, 1)  # version
    struct.pack_into("<I", record, si_offset + 44, 0)  # class_id

    # End marker
    end_offset = attr_offset + attr_size
    struct.pack_into("<I", record, end_offset, 0xFFFFFFFF)

    return bytes(record)


def test_parse_minimal_record():
    """Test parsing a minimal valid MFT record."""
    record_data = _make_minimal_mft_record(record_number=42, sequence=1, flags=0x01)
    record = parse_mft_record(record_data, record_number=42)
    assert record.record_number == 42
    assert record.sequence_number == 1
    assert record.is_in_use is True
    assert record.is_directory is False
    assert record.is_valid is True


def test_parse_directory_flag():
    """Test that directory flag is correctly parsed."""
    record_data = _make_minimal_mft_record(record_number=0, sequence=1, flags=0x01 | 0x02)
    record = parse_mft_record(record_data, record_number=0)
    assert record.is_directory is True


def test_parse_invalid_signature():
    """Test that invalid signature fails."""
    record_data = bytearray(1024)
    record_data[0:4] = b"BAD!"
    record = parse_mft_record(bytes(record_data), record_number=0)
    assert record.is_valid is False
    assert "Invalid signature" in (record.error or "")


def test_parse_too_short():
    """Test that a too-short record fails."""
    record_data = b"FILE" + b"\x00" * 10
    record = parse_mft_record(record_data, record_number=0)
    assert record.is_valid is False
    assert "too small" in (record.error or "")


def test_ntfs_timestamp_conversion():
    """Test NTFS FILETIME to datetime conversion."""
    # 2026-10-01T00:00:00Z in FILETIME
    # (2026-1601) = 425 years * 365.25 days* 86400 * 10_000_000
    # Approximate test with a known value
    ts = 133635840000000000  # 2024-01-01 roughly
    dt = _ntfs_timestamp_to_datetime(ts)
    assert dt is not None


def test_empty_timestamp():
    """Test that zero FILETIME returns None."""
    assert _ntfs_timestamp_to_datetime(0) is None