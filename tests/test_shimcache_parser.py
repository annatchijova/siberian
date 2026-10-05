"""Tests for Windows AppCompatCache (Shimcache) parser."""
from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from siberian.shimcache_parser import (
    parse_shimcache_binary,
    format_shimcache_summary,
    ShimcacheEntry,
    _filetime,
)


def test_filetime_conversion():
    """Test FILETIME to datetime conversion."""
    ts = 133635840000000000
    dt = _filetime(ts)
    assert dt is not None


def test_zero_filetime():
    """Test that zero FILETIME returns None."""
    assert _filetime(0) is None


def test_shimcache_entry_to_dict():
    """Test ShimcacheEntry serialization."""
    entry = ShimcacheEntry(
        path="C:\\Windows\\System32\\cmd.exe",
        last_modified=None,
        flags=0,
        entry_size=128,
        raw_offset=0,
    )
    d = entry.to_dict()
    assert d["path"] == "C:\\Windows\\System32\\cmd.exe"
    assert d["last_modified"] is None
    assert d["entry_size"] == 128


def test_format_shimcache_summary():
    """Test summary formatting."""
    entry = ShimcacheEntry(
        path="C:\\Windows\\notepad.exe",
        entry_size=64,
    )
    line = format_shimcache_summary(entry)
    assert "notepad.exe" in line
    assert "unknown" in line


def test_format_error_entry():
    """Test formatting an error entry."""
    entry = ShimcacheEntry(path="", error="Hive not found")
    line = format_shimcache_summary(entry)
    assert "ERROR" in line
    assert "Hive not found" in line


def test_parse_empty_data():
    """Test parsing empty/short data."""
    entries = parse_shimcache_binary(b"\x00\x00\x00\x00")
    assert len(entries) == 1
    assert entries[0].error is not None


def test_parse_synthetic_data():
    """Test parsing synthetic AppCompatCache-like data."""
    path_str = "C:\\Windows\\System32\\cmd.exe"
    path_bytes = path_str.encode("utf-16-le") + b"\x00\x00"
    entry_size = len(path_bytes) + 16
    data = struct.pack("<I", entry_size) + b"\x00" * 12 + path_bytes + b"\x00" * 64
    entries = parse_shimcache_binary(data)
    paths = [e.path for e in entries if e.path]
    assert len(paths) > 0
    assert any("cmd.exe" in p for p in paths)