"""Tests for Windows Shellbags parser."""
from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from siberian.shellbags_parser import (
    parse_shellbags_from_registry,
    format_shellbag_summary,
    ShellbagEntry,
    _filetime,
    _extract_path_from_binary,
)


def test_filetime_conversion():
    """Test FILETIME to datetime conversion."""
    ts = 133635840000000000
    dt = _filetime(ts)
    assert dt is not None


def test_zero_filetime():
    """Test that zero FILETIME returns None."""
    assert _filetime(0) is None


def test_extract_path_from_binary():
    """Test extraction of file path from binary data."""
    path_str = "C:\\Users\\Test\\Desktop"
    data = path_str.encode("utf-16-le") + b"\x00\x00"
    path = _extract_path_from_binary(data)
    assert path is not None
    assert "Desktop" in path or "Deskto" in path or "C:\\Users\\Test" in path


def test_extract_path_no_path():
    """Test extraction when no valid path exists."""
    path = _extract_path_from_binary(b"\x00\x01\x02\x03")
    assert path is None


def test_shellbag_entry_to_dict():
    """Test ShellbagEntry serialization."""
    entry = ShellbagEntry(
        bag_type="BagMRU",
        key_path="Software\\Microsoft\\Windows\\Shell\\BagMRU",
        folder_path="C:\\Users\\Test\\Documents",
        view_mode="Details",
        sort_mode="DateModified",
        timestamp=None,
        raw_value_name="0",
        raw_value_size=128,
    )
    d = entry.to_dict()
    assert d["bag_type"] == "BagMRU"
    assert d["folder_path"] == "C:\\Users\\Test\\Documents"
    assert d["view_mode"] == "Details"
    assert d["timestamp"] is None


def test_format_shellbag_summary():
    """Test summary formatting."""
    entry = ShellbagEntry(
        bag_type="BagMRU",
        key_path="Software\\Microsoft\\Windows\\Shell\\BagMRU",
        folder_path="C:\\Users\\Test\\Documents",
        view_mode="Details",
        sort_mode="DateModified",
    )
    line = format_shellbag_summary(entry)
    assert "Documents" in line
    assert "Details" in line
    assert "DateModified" in line


def test_format_error_entry():
    """Test formatting an error entry."""
    entry = ShellbagEntry(
        bag_type="BagMRU",
        key_path="",
        error="Hive not found",
    )
    line = format_shellbag_summary(entry)
    assert "ERROR" in line
    assert "Hive not found" in line


def test_parse_nonexistent_hive():
    """Test parsing a nonexistent hive returns error entry."""
    entries = parse_shellbags_from_registry(Path("/nonexistent/NTUSER.DAT"))
    assert len(entries) == 1
    assert entries[0].error is not None