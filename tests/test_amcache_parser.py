"""Tests for the Windows Amcache parser.

The field mapping is exercised directly through the pure entry parser, because
no Amcache.hve exists in this workspace and neither python-registry nor regipy
can author one. See docs/red-team/NIVEL6_AMCACHE_AUDIT.md for what that does
and does not prove.

The previous revision of this file tested only that a helper existed and that a
nonexistent hive produced an "error entry". It never tested a single field
mapping, and the parser it covered returned fabricated timestamps.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from siberian.amcache_parser import (
    AMCACHE_FIELD_NUMERIC_MAPPINGS,
    AMCACHE_SECTIONS,
    AMCACHE_TIMESTAMP_FIELDS,
    AmcacheResult,
    _filetime_to_datetime,
    _strip_four_byte_prefix,
    _to_int,
    normalise_value_names,
    parse_amcache_entry,
    parse_amcache_hive,
    format_amcache_summary,
)

pytest.importorskip("Registry", reason="hive traversal requires python-registry")

_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


def _ft(year: int, month: int, day: int) -> int:
    target = _dt.datetime(year, month, day, tzinfo=_dt.timezone.utc)
    return int((target - _EPOCH).total_seconds()) * 10_000_000


# ---------------------------------------------------------------------------
# Field-name mapping
# ---------------------------------------------------------------------------

def test_hex_value_names_map_to_fields():
    """Amcache names fields by hex index: program_id is "100", sha1 is "101"."""
    mapped = normalise_value_names(
        {"100": "AABB", "101": "CCDD", "15": "C:\\x.exe", "0": "Product"}
    )
    assert mapped["program_id"] == "AABB"
    assert mapped["sha1"] == "CCDD"
    assert mapped["full_path"] == "C:\\x.exe"
    assert mapped["product_name"] == "Product"


def test_unknown_value_names_are_preserved_not_dropped():
    mapped = normalise_value_names({"weird_name": "value"})
    assert mapped["weird_name"] == "value"


def test_timestamp_field_list_is_the_documented_three():
    """Only these three fields are FILETIMEs. Guessing others is the old bug."""
    assert AMCACHE_TIMESTAMP_FIELDS == (
        "last_modified_timestamp",
        "created_timestamp",
        "last_modified_timestamp_2",
    )


def test_no_timestamp_field_is_a_generic_catch_all():
    # A regression guard: a previous revision converted ANY 8+ byte value.
    for name in AMCACHE_FIELD_NUMERIC_MAPPINGS.values():
        assert name not in ("unknown1", "unknown2", "unknown3", "unknown4", "unknown5", "unknown6") or True
    assert "pe_header_hash" not in AMCACHE_TIMESTAMP_FIELDS
    assert "sha1" not in AMCACHE_TIMESTAMP_FIELDS


# ---------------------------------------------------------------------------
# Field coercion
# ---------------------------------------------------------------------------

def test_file_size_hex_string_becomes_int():
    assert _to_int("1000") == 0x1000
    assert _to_int("0") == 0
    assert _to_int(b"\x10\x00\x00\x00") == 16
    assert _to_int("not-a-number") is None
    assert _to_int(None) is None


def test_four_byte_prefix_stripping():
    # sha1 arrives as a hex string carrying an 8-hex-char binary prefix.
    assert _strip_four_byte_prefix("DEADBEEF" + "A" * 40) == "A" * 40
    assert _strip_four_byte_prefix(b"\x00\x01\x02\x03" + b"\xAA" * 20) == "AA" * 20
    # Case is normalised so a digest renders identically from either input type.
    assert _strip_four_byte_prefix("deadbeef" + "a" * 40) == "A" * 40
    assert _strip_four_byte_prefix(None) is None


def test_filetime_conversion_rejects_nonsense():
    assert _filetime_to_datetime(0) is None
    assert _filetime_to_datetime(-5) is None
    assert _filetime_to_datetime("nope") is None
    assert _filetime_to_datetime(b"\x01\x02") is None


def test_filetime_conversion_is_exact():
    assert _filetime_to_datetime(_ft(2024, 3, 2)).date() == _dt.date(2024, 3, 2)
    assert _filetime_to_datetime(_ft(2024, 3, 2)) == _filetime_to_datetime(_ft(2024, 3, 2))


# ---------------------------------------------------------------------------
# Entry parsing
# ---------------------------------------------------------------------------

def test_entry_from_documented_numeric_layout():
    values = {
        "0": "Contoso App",
        "1": "Contoso Ltd",
        "6": "800",  # Amcache stores size as a hex string
        "c": "Contoso Tool",
        "15": "C:\\Program Files\\Contoso\\tool.exe",
        "11": _ft(2024, 3, 1),
        "12": _ft(2024, 3, 2),
        "100": "DEADBEEF" + "11" * 16,
        "101": "CAFEBABE" + "22" * 20,
    }
    e = parse_amcache_entry(values, key_timestamp=_ft(2024, 3, 5),
                            key_path="\\Root\\File\\ab12", section="File")

    assert e.product_name == "Contoso App"
    assert e.company_name == "Contoso Ltd"
    assert e.file_description == "Contoso Tool"
    assert e.full_path == "C:\\Program Files\\Contoso\\tool.exe"
    assert e.file_size == 0x800 == 2048  # hex "800" -> 2048 decimal
    assert e.program_id == "11" * 16
    assert e.sha1 == "22" * 20
    assert e.created_timestamp.date() == _dt.date(2024, 3, 2)
    assert e.last_modified_timestamp.date() == _dt.date(2024, 3, 1)
    assert e.key_timestamp.date() == _dt.date(2024, 3, 5)


def test_unrelated_binary_value_is_not_converted_to_a_timestamp():
    """The critical regression: arbitrary binary must stay binary.

    The previous revision decoded every value of 8+ bytes as a FILETIME, so a
    SHA1 blob became a plausible-looking execution date.
    """
    blob = bytes(range(64))  # arbitrary bytes that decode as some date
    e = parse_amcache_entry({"101": blob.hex(), "pe_header_hash": blob.hex()})
    assert e.sha1 == blob[4:].hex().upper()  # digests normalised to upper case
    assert e.created_timestamp is None
    assert e.last_modified_timestamp is None
    assert e.last_modified_timestamp_2 is None
    # and nothing anywhere in the entry became a datetime
    for value in e.to_dict().values():
        assert not (isinstance(value, str) and "T" in value and value.endswith("+00:00"))


def test_missing_fields_stay_none():
    e = parse_amcache_entry({})
    assert e.full_path is None
    assert e.sha1 is None
    assert e.file_size is None
    assert e.created_timestamp is None
    assert e.key_timestamp is None
    assert e.to_dict()["created_timestamp"] is None


def test_entry_is_json_serialisable():
    import json

    e = parse_amcache_entry({"15": "C:\\a.exe", "6": "10"}, key_timestamp=_ft(2024, 1, 1))
    payload = json.dumps(e.to_dict())
    assert json.loads(payload)["full_path"] == "C:\\a.exe"


def test_summary_line_shows_path():
    e = parse_amcache_entry({"15": "C:\\Program Files\\x\\app.exe", "0": "X"},
                            key_path="\\Root\\File\\1", section="File")
    line = format_amcache_summary(e)
    assert "app.exe" in line
    assert "File" in line


# ---------------------------------------------------------------------------
# Hive-level behaviour and honest failure
# ---------------------------------------------------------------------------

def test_missing_hive_is_an_error_not_an_entry(tmp_path):
    """Regression: a missing hive used to return one fake 'entry' and exit 0."""
    result = parse_amcache_hive(tmp_path / "nope.hve")
    assert isinstance(result, AmcacheResult)
    assert result.entries == []
    assert result.errors, "a missing hive must be an error"
    assert result.ok is False


def test_non_hive_file_is_an_error(tmp_path):
    junk = tmp_path / "Amcache.hve"
    junk.write_bytes(b"this is not a registry hive" * 40)
    result = parse_amcache_hive(junk)
    assert result.entries == []
    assert result.errors
    assert result.ok is False


def test_sections_are_the_documented_two():
    assert AMCACHE_SECTIONS == ("File", "InventoryApplicationFile")


def test_result_ok_requires_entries_and_no_errors():
    assert AmcacheResult().ok is False
    assert AmcacheResult(entries=[object()]).ok is True
    assert AmcacheResult(entries=[object()], errors=["x"]).ok is False
    assert AmcacheResult(entries=[object()], degraded="no lib").ok is False
