"""Tests for Windows Amcache.hve parser."""
from __future__ import annotations

from pathlib import Path

from siberian.amcache_parser import (
    parse_amcache_hive,
    format_amcache_summary,
    AmcacheEntry,
    _filetime,
    _parse_filetime_bytes,
)


def test_filetime_conversion():
    """Test FILETIME to datetime conversion."""
    ts = 133635840000000000  # known approximate value
    dt = _filetime(ts)
    assert dt is not None


def test_zero_timestamp():
    """Test that zero timestamp returns None."""
    assert _filetime(0) is None


def test_parse_filetime_bytes():
    """Test parsing 8-byte FILETIME from bytes."""
    import struct
    ts = 133635840000000000
    data = struct.pack("<Q", ts)
    dt = _parse_filetime_bytes(data)
    assert dt is not None


def test_parse_filetime_bytes_too_short():
    """Test parsing FILETIME from too-short bytes."""
    assert _parse_filetime_bytes(b"\x00\x00\x00") is None


def test_amcache_entry_to_dict():
    """Test AmcacheEntry serialization."""
    entry = AmcacheEntry(
        key_name="FakeApp",
        name="Fake Application",
        publisher="Fake Publisher",
        path="C:\\Apps\\FakeApp.exe",
        sha1="abc123",
        entry_type="Program",
        raw_values={"Name": "Fake Application"},
    )
    d = entry.to_dict()
    assert d["key_name"] == "FakeApp"
    assert d["name"] == "Fake Application"
    assert d["publisher"] == "Fake Publisher"
    assert d["path"] == "C:\\Apps\\FakeApp.exe"
    assert d["sha1"] == "abc123"
    assert d["entry_type"] == "Program"


def test_format_amcache_summary():
    """Test summary formatting."""
    entry = AmcacheEntry(
        key_name="FakeApp",
        name="Fake Application",
        publisher="Publisher",
        path="C:\\Apps\\FakeApp.exe",
        entry_type="Program",
    )
    line = format_amcache_summary(entry)
    assert "Fake Application" in line
    assert "FakeApp.exe" in line
    assert "Publisher" in line


def test_format_error_entry():
    """Test formatting an error entry."""
    entry = AmcacheEntry(
        key_name="<error>",
        entry_type="Error",
        raw_values={"error": "File not found"},
    )
    line = format_amcache_summary(entry)
    assert "ERROR" in line
    assert "File not found" in line


def test_parse_nonexistent_file():
    """Test parsing a nonexistent file returns error entry."""
    entries = parse_amcache_hive(Path("/nonexistent/path/Amcache.hve"))
    assert len(entries) == 1
    assert entries[0].entry_type == "Error"