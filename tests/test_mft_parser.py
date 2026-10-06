"""Tests for NTFS $MFT binary parser."""
from __future__ import annotations

import struct
from pathlib import Path

from siberian.mft_parser import (
    apply_fixups,
    detect_mft_record_size,
    parse_mft_file,
    parse_mft_record,
    MftParseError,
    MftRecord,
    _ntfs_timestamp_to_datetime,
)


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


# ---------------------------------------------------------------------------
# Regression tests for defects found by red-team review.
#
# These use DISTINCT, NON-ZERO timestamps and realistic fixups on purpose:
# the previous fixture wrote all-zero timestamps, so a field-offset shift of
# 8 bytes produced None in both the right and the wrong place and no test could
# detect it. A test that cannot fail is not a test.
# ---------------------------------------------------------------------------

import datetime as _dt

_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


def _ft(year: int, month: int, day: int) -> int:
    """Build a FILETIME for a UTC date."""
    target = _dt.datetime(year, month, day, tzinfo=_dt.timezone.utc)
    return int((target - _EPOCH).total_seconds()) * 10_000_000


def _make_record_with_resident_si(
    record_number: int = 42,
    first_attr_offset: int = 56,
    record_size: int = 1024,
    flags: int = 0x01,
    timestamps: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Build a record with one resident $STANDARD_INFORMATION and fixups applied.

    Timestamps default to four DISTINCT dates so any field misalignment shifts a
    real value into the wrong slot instead of silently yielding None.
    """
    if timestamps is None:
        timestamps = (_ft(2024, 3, 1), _ft(2024, 3, 2), _ft(2024, 3, 3), _ft(2024, 3, 4))

    si = bytearray(72)
    for i, value in enumerate(timestamps):
        struct.pack_into("<Q", si, i * 8, value)

    # Attribute: 16-byte generic header + 8-byte resident header + content.
    attr = bytearray(24)
    struct.pack_into("<I", attr, 0, 0x10)          # $STANDARD_INFORMATION
    struct.pack_into("<I", attr, 4, 24 + len(si))  # attribute length
    struct.pack_into("<B", attr, 8, 0)             # name length
    struct.pack_into("<B", attr, 9, 0)             # name offset
    struct.pack_into("<H", attr, 10, 0)            # flags: resident
    struct.pack_into("<H", attr, 12, 1)            # attribute id
    struct.pack_into("<I", attr, 16, len(si))      # resident content length
    struct.pack_into("<H", attr, 20, 24)           # resident content offset
    attr += si

    record = bytearray(record_size)
    record[0:4] = b"FILE"
    fixup_offset = first_attr_offset - 8  # keep the array ahead of the attributes
    struct.pack_into("<H", record, 4, fixup_offset)
    struct.pack_into("<H", record, 6, record_size // 512 + 1)
    struct.pack_into("<H", record, 16, 1)          # sequence number
    struct.pack_into("<H", record, 18, 1)          # hard link count
    struct.pack_into("<H", record, 20, first_attr_offset)
    struct.pack_into("<H", record, 22, flags)
    struct.pack_into("<I", record, 24, record_size)   # used size
    struct.pack_into("<I", record, 28, record_size)   # allocated size
    struct.pack_into("<I", record, 44, record_number)  # embedded record number

    # Write the update sequence array the way NTFS does on disk: the USN at the
    # array head, the real trailing bytes for each sector after it, and the USN
    # itself written over each sector tail.
    usn = 0x0007
    struct.pack_into("<H", record, fixup_offset, usn)
    saved = bytes(record[510:512])
    for i in range(1, record_size // 512 + 1):
        sector_end = (i - 1) * 512 + 510
        struct.pack_into("<H", record, fixup_offset + i * 2, struct.unpack_from("<H", saved, 0)[0])
        struct.pack_into("<H", record, sector_end, usn)

    record[first_attr_offset:first_attr_offset + len(attr)] = attr
    struct.pack_into("<I", record, first_attr_offset + len(attr), 0xFFFFFFFF)
    return bytes(record)


def test_resident_si_timestamps_are_not_field_shifted():
    """$STANDARD_INFORMATION timestamps must land in the correct fields.

    Regression: resident content starts at the resident content offset (0x18),
    not at +16. Reading from +16 shifts every timestamp by 8 bytes, so
    modification_time reported the CREATION time — a confidently false claim
    about when a file's contents last changed.
    """
    record = parse_mft_record(_make_record_with_resident_si(), record_number=42)
    assert record.is_valid, record.error
    assert record.standard_info is not None

    si = record.standard_info
    assert si.creation_time.date() == _dt.date(2024, 3, 1)
    assert si.modification_time.date() == _dt.date(2024, 3, 2)
    assert si.mft_modification_time.date() == _dt.date(2024, 3, 3)
    assert si.access_time.date() == _dt.date(2024, 3, 4)


def test_fixups_restore_sector_tail_bytes():
    """The update sequence array must be applied to recover sector tails.

    Without this, any field sitting at a sector boundary is whatever the USN
    happened to be on disk.
    """
    raw = _make_record_with_resident_si()
    # Pre-condition: on disk, the sector tail holds the update sequence number.
    assert struct.unpack_from("<H", raw, 510)[0] == 0x0007

    fixed, error = apply_fixups(raw)
    assert error is None
    assert struct.unpack_from("<H", fixed, 510)[0] != 0x0007

    # And the record still parses.
    record = parse_mft_record(raw, record_number=42)
    assert record.is_valid, record.error
    assert record.fixups_applied is True


def test_fixups_do_not_corrupt_already_repaired_record():
    """Applying fixups twice must not overwrite real data.

    Guards the idempotence case: a record that has already been repaired (or was
    written without fixups) has a sector tail that is NOT the USN, and silently
    rewriting it would destroy genuine bytes.
    """
    raw = _make_record_with_resident_si()
    once, _ = apply_fixups(raw)
    twice, error = apply_fixups(once)
    assert error is None
    assert twice == once


def test_embedded_record_number_is_authoritative():
    """The record number at 0x2C must win over the caller's index, and any
    disagreement must be recorded rather than hidden."""
    record = parse_mft_record(_make_record_with_resident_si(record_number=42), record_number=7)
    assert record.record_number == 42
    assert record.expected_record_number == 7
    assert record.record_number_matches is False


def test_record_number_agreement_recorded():
    """When the embedded number matches the index, that agreement is recorded."""
    record = parse_mft_record(_make_record_with_resident_si(record_number=9), record_number=9)
    assert record.record_number == 9
    assert record.record_number_matches is True


def test_non_resident_standard_information_is_not_read_as_timestamps():
    """A non-resident $STANDARD_INFORMATION carries a run list, not timestamps.

    Interpreting that run list as FILETIMEs would fabricate timestamps.
    """
    record_data = bytearray(1024)
    record_data[0:4] = b"FILE"
    struct.pack_into("<H", record_data, 4, 0)
    struct.pack_into("<H", record_data, 6, 0)
    struct.pack_into("<H", record_data, 16, 1)
    struct.pack_into("<H", record_data, 18, 1)
    struct.pack_into("<H", record_data, 20, 56)
    struct.pack_into("<H", record_data, 22, 0x01)
    struct.pack_into("<I", record_data, 24, 1024)
    struct.pack_into("<I", record_data, 28, 1024)
    struct.pack_into("<I", record_data, 44, 1)

    # Non-resident attribute: flags bit 0 set, run list follows the header.
    struct.pack_into("<I", record_data, 56, 0x10)
    struct.pack_into("<I", record_data, 60, 64)
    struct.pack_into("<H", record_data, 66, 0x0001)  # non-resident
    struct.pack_into("<H", record_data, 68, 1)
    # A plausible-looking "run list" that would decode as bogus timestamps.
    for i in range(8):
        struct.pack_into("<Q", record_data, 72 + i * 8, _ft(2024, 3, 1))

    record = parse_mft_record(bytes(record_data), record_number=1)
    assert record.is_valid
    assert record.standard_info is None, "non-resident SI must not yield timestamps"


def test_detect_mft_record_size_from_allocated_size():
    """Record size must come from the volume, not a hardcoded 1024."""
    small = _make_record_with_resident_si(record_size=1024)
    large = _make_record_with_resident_si(record_size=4096)
    assert detect_mft_record_size(small) == 1024
    assert detect_mft_record_size(large) == 4096
    # Unreadable probe falls back rather than guessing wildly.
    assert detect_mft_record_size(b"\x00" * 8) == 1024


def test_parse_mft_file_handles_4096_byte_records(tmp_path):
    """A 4096-byte-record volume must parse, not fail every signature check."""
    mft = tmp_path / "MFT4096"
    for i in range(3):
        mft.write_bytes(mft.read_bytes() if mft.exists() else b"")
        with open(mft, "ab") as f:
            f.write(_make_record_with_resident_si(record_number=i, record_size=4096))

    records = parse_mft_file(mft)
    assert len(records) == 3
    for i, record in enumerate(records):
        assert record.is_valid, f"record {i}: {record.error}"
        assert record.record_number == i


def test_parse_mft_file_reports_truncated_final_record(tmp_path):
    """A truncated tail must be reported, never silently dropped."""
    mft = tmp_path / "MFT_trunc"
    good = _make_record_with_resident_si(record_number=0)
    with open(mft, "wb") as f:
        f.write(good)
        f.write(good[:400])  # half a record

    records = parse_mft_file(mft)
    assert len(records) == 2
    assert records[0].is_valid
    assert records[1].is_valid is False
    assert "Truncated" in (records[1].error or "")


def test_record_to_dict_is_json_serializable():
    """Regression: MftRecord had no to_dict, so `import-mft --output` raised
    AttributeError and exited 2 instead of writing JSON."""
    import json

    record = parse_mft_record(_make_record_with_resident_si(), record_number=42)
    payload = json.dumps([record.to_dict()])
    restored = json.loads(payload)[0]
    assert restored["record_number"] == 42
    assert restored["fixups_applied"] is True
    assert restored["standard_info"]["modification_time"].startswith("2024-03-02")


def test_timestamp_conversion_is_exact_and_deterministic():
    """FILETIME conversion must not route through float arithmetic."""
    # 1 FILETIME unit = 100ns; 10 units = 1 microsecond exactly.
    base = _ft(2024, 1, 1)
    a = _ntfs_timestamp_to_datetime(base)
    b = _ntfs_timestamp_to_datetime(base)
    assert a == b
    # A value with sub-microsecond remainder must truncate deterministically.
    assert _ntfs_timestamp_to_datetime(10) == _EPOCH + _dt.timedelta(microseconds=1)
    assert _ntfs_timestamp_to_datetime(9) == _EPOCH


def test_negative_and_huge_timestamps_rejected():
    """Nonsense FILETIMEs must return None, not raise or invent a date."""
    assert _ntfs_timestamp_to_datetime(-1) is None
    assert _ntfs_timestamp_to_datetime(2**64 - 1) is None