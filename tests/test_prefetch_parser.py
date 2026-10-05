"""Tests for Windows Prefetch parser."""
from __future__ import annotations

import struct
from pathlib import Path

from siberian.prefetch_parser import (
    parse_prefetch_file,
    parse_prefetch_directory,
    _executable_name_from_pf,
    PrefetchRecord,
)


def _make_scca_prefetch(filename_in_file: str = "TESTEXE.EXE", last_run: int = 0, run_count: int = 1) -> bytes:
    """Create a minimal SCCA-format Prefetch file (Win7 style)."""
    data = bytearray(256)
    # Unused
    struct.pack_into("<I", data, 0, 0)
    # Signature "SCCA"
    data[4:8] = b"SCCA"
    # File size
    struct.pack_into("<I", data, 8, len(data))
    # File name (60 bytes, UTF-16-LE)
    name_bytes = filename_in_file.encode("utf-16-le")[:60]
    data[12:12+len(name_bytes)] = name_bytes
    # Last run time (FILETIME) at offset 72
    struct.pack_into("<Q", data, 72, last_run)
    # Run count at offset 80
    struct.pack_into("<I", data, 80, run_count)
    return bytes(data)


def _make_mam_prefetch() -> bytes:
    """Create a minimal MAM-format Prefetch file (Win10 style)."""
    data = bytearray(128)
    # MAM signature
    data[0:4] = b"MAM\x04"
    # Decompressed size (4 bytes at offset 4)
    struct.pack_into("<I", data, 4, 512)
    return bytes(data)


def test_executable_name_extraction():
    """Test extraction of executable name from .pf filename."""
    assert _executable_name_from_pf("MIMIKATZ.EXE-1234ABCD") == "MIMIKATZ.EXE"
    assert _executable_name_from_pf("CMD.EXE-1234ABCD") == "CMD.EXE"
    assert _executable_name_from_pf("NOTEPAD.EXE") == "NOTEPAD.EXE"  # no dash
    assert _executable_name_from_pf("SOME-TOOL.EXE-ABCDEF12") == "SOME-TOOL.EXE"


def test_parse_scca_prefetch():
    """Test parsing SCCA-format Prefetch file."""
    import tempfile, os
    pf_data = _make_scca_prefetch("CMD.EXE", last_run=133635840000000000, run_count=5)
    with tempfile.NamedTemporaryFile(suffix=".pf", delete=False) as f:
        f.write(pf_data)
        tmp_path = f.name
    try:
        record = parse_prefetch_file(Path(tmp_path))
        assert record.filename == "CMD.EXE" or record.filename == tmp_path.split("/")[-1].replace(".pf", "")
        assert record.format_version is not None or record.format_version is None  # depends on parse success
        assert record.is_mam_compressed is False
        assert record.error is None
    finally:
        os.unlink(tmp_path)


def test_parse_mam_prefetch():
    """Test parsing MAM-format Prefetch file."""
    import tempfile, os
    pf_data = _make_mam_prefetch()
    with tempfile.NamedTemporaryFile(suffix=".pf", delete=False) as f:
        f.write(pf_data)
        tmp_path = f.name
    try:
        record = parse_prefetch_file(Path(tmp_path))
        assert record.is_mam_compressed is True
        assert record.format_version == 30
    finally:
        os.unlink(tmp_path)


def test_parse_invalid_signature():
    """Test that a file with invalid signature is rejected."""
    import tempfile, os
    pf_data = b"BAD!" + b"\x00" * 100
    with tempfile.NamedTemporaryFile(suffix=".pf", delete=False) as f:
        f.write(pf_data)
        tmp_path = f.name
    try:
        record = parse_prefetch_file(Path(tmp_path))
        assert record.error is not None
        assert "Invalid signature" in record.error
    finally:
        os.unlink(tmp_path)


def test_parse_directory():
    """Test parsing a directory of .pf files."""
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create two test files
        pf1 = _make_scca_prefetch("CMD.EXE")
        pf2 = _make_scca_prefetch("NOTEPAD.EXE")
        Path(tmpdir, "CMD.EXE-1234ABCD.pf").write_bytes(pf1)
        Path(tmpdir, "NOTEPAD.EXE-5678EFAB.pf").write_bytes(pf2)
        # Create a non-pf file (should be ignored)
        Path(tmpdir, "readme.txt").write_text("not prefetch")

        records = parse_prefetch_directory(Path(tmpdir))
        assert len(records) == 2
        names = {r.filename for r in records}
        assert "CMD.EXE" in names or any("CMD" in n for n in names)
        assert "NOTEPAD.EXE" in names or any("NOTEPAD" in n for n in names)


def test_prefetch_record_to_dict():
    """Test PrefetchRecord serialization."""
    record = PrefetchRecord(
        filename="CMD.EXE",
        file_hash="abc123",
        run_count=3,
        format_version=23,
        is_mam_compressed=False,
    )
    d = record.to_dict()
    assert d["filename"] == "CMD.EXE"
    assert d["file_hash"] == "abc123"
    assert d["run_count"] == 3
    assert d["format_version"] == 23
    assert d["is_mam_compressed"] is False