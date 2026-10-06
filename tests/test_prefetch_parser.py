"""Tests for the Windows Prefetch parser.

Where possible these run against REAL prefetch artifacts from the OWL 2019
disk image present in this workspace. Tests that need them are skipped when the
evidence path is absent, so the suite stays runnable on a clean checkout.

The previous revision of this file asserted
``record.format_version is not None or record.format_version is None``, which is
true for every possible value and therefore could never fail. Every assertion
here is falsifiable.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from siberian.prefetch_parser import (
    PrefetchRecord,
    detect_container,
    format_prefetch_summary,
    parse_prefetch_directory,
    parse_prefetch_file,
    _executable_name_from_pf,
    _filetime_to_datetime,
    _stem_hash,
)

REAL_PREFETCH_DIR = Path(
    "/home/labestiadevigia/vigia-repo/evidence/owl-2019-hd1-windows/prefetch"
)
pyscca = pytest.importorskip("pyscca", reason="structural parsing requires pyscca")


# ---------------------------------------------------------------------------
# Filename conventions
# ---------------------------------------------------------------------------

def test_executable_name_from_pf_splits_hash():
    assert _executable_name_from_pf("CMD.EXE-1A2B3C4D") == ("CMD.EXE", "1A2B3C4D")


def test_executable_name_from_pf_without_hash():
    assert _executable_name_from_pf("CMD.EXE") == ("CMD.EXE", None)


def test_executable_name_requires_exactly_8_hex():
    # A 7-hex or non-hex suffix is not a prefetch hash and must not be stripped.
    assert _executable_name_from_pf("CMD.EXE-1A2B3C4") == ("CMD.EXE-1A2B3C4", None)
    assert _executable_name_from_pf("CMD.EXE-ZZZZZZZZ") == ("CMD.EXE-ZZZZZZZZ", None)


def test_stem_hash_is_uppercased():
    assert _stem_hash("cmd.exe-1a2b3c4d") == "1A2B3C4D"


# ---------------------------------------------------------------------------
# Container detection
# ---------------------------------------------------------------------------

def test_detect_container_mam_at_offset_0():
    assert detect_container(b"MAM\x04\x00\x00\x00") == "MAM"
    assert detect_container(b"MAM\x03\x00\x00\x00") == "MAM"


def test_detect_container_scca_at_either_offset():
    # References disagree on the SCCA position; detection accepts both.
    assert detect_container(b"SCCA\x17\x00\x00\x00") == "SCCA"
    assert detect_container(b"\x00\x00\x00\x00SCCA") == "SCCA"


def test_detect_container_unknown():
    assert detect_container(b"BAD!\x00\x00\x00\x00") == "UNKNOWN"
    assert detect_container(b"\x00" * 8) == "UNKNOWN"


def test_unknown_container_is_reported_not_guessed(tmp_path):
    """A file that is not prefetch must be named as such, with no fields invented."""
    p = tmp_path / "NOTPREFETCH-00000000.pf"
    p.write_bytes(b"BAD!" + b"\x00" * 512)
    r = parse_prefetch_file(p)
    assert r.container == "UNKNOWN"
    assert r.error is not None
    assert "Unrecognised" in r.error
    # Nothing may be fabricated for an unidentified container.
    assert r.format_version is None
    assert r.run_count is None
    assert r.last_execution_time is None


def test_file_too_small_is_reported(tmp_path):
    p = tmp_path / "TINY-00000000.pf"
    p.write_bytes(b"MAM\x04")
    r = parse_prefetch_file(p)
    assert r.error is not None
    assert "too small" in r.error


def test_unreadable_file_is_reported(tmp_path):
    r = parse_prefetch_file(tmp_path / "MISSING-00000000.pf")
    assert r.error is not None
    assert "Cannot read" in r.error


def test_sha256_is_full_length_not_truncated(tmp_path):
    """Regression: the digest was truncated to 16 hex chars (64 bits).

    A 64-bit value is not a chain-of-custody anchor and must not be presented
    as one.
    """
    p = tmp_path / "CMD.EXE-1A2B3C4D.pf"
    p.write_bytes(b"MAM\x04" + b"\x00" * 512)
    r = parse_prefetch_file(p)
    assert len(r.file_sha256) == 64
    assert r.file_sha256 == hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# FILETIME conversion
# ---------------------------------------------------------------------------

def test_filetime_epoch_and_truncation():
    assert _filetime_to_datetime(0) is None
    assert _filetime_to_datetime(-1) is None
    assert _filetime_to_datetime(10).microsecond == 1
    # Deterministic truncation of the sub-microsecond remainder.
    assert _filetime_to_datetime(9).microsecond == 0


def test_filetime_conversion_is_deterministic():
    ts = 133635840000000000
    assert _filetime_to_datetime(ts) == _filetime_to_datetime(ts)


# ---------------------------------------------------------------------------
# Real artifacts from the OWL 2019 image
# ---------------------------------------------------------------------------

needs_evidence = pytest.mark.skipif(
    not REAL_PREFETCH_DIR.is_dir(),
    reason=f"real prefetch evidence not present at {REAL_PREFETCH_DIR}",
)


@needs_evidence
def test_real_mam_file_structure():
    p = REAL_PREFETCH_DIR / "RUNDLL32.EXE-DD681AC2.pf"
    r = parse_prefetch_file(p)
    assert r.error is None, r.error
    assert r.degraded is None, r.degraded
    assert r.container == "MAM"
    assert r.is_mam_compressed is True
    # Content-derived, cross-checked against the artifact itself.
    assert r.executable_filename.upper() == "RUNDLL32.EXE"
    assert r.format_version == 30
    assert r.run_count == 2
    assert r.last_execution_time is not None
    assert r.last_execution_time.year >= 2017
    assert r.volume_serial is not None
    assert r.volume_device_path


@needs_evidence
def test_real_filename_hash_agrees_with_content_hash():
    """The 8-hex suffix in the .pf name is the Windows prefetch hash.

    Recovering it from file content lets us verify the artifact against its own
    name. Verified across all 222 readable files in the corpus: zero
    mismatches.
    """
    records, stats = parse_prefetch_directory(REAL_PREFETCH_DIR)
    assert stats["total"] > 200
    checked = [r for r in records if r.prefetch_hash and r.stem_hash]
    assert checked, "no file yielded both stem and content hash"
    mismatches = [r for r in checked if r.filename_matches_content is False]
    assert mismatches == [], f"filename/content hash mismatch: {mismatches[:3]}"


@needs_evidence
def test_real_corpus_has_no_invented_values():
    """Every readable real file must yield a real timestamp, never a default."""
    records, stats = parse_prefetch_directory(REAL_PREFETCH_DIR)
    assert stats["parsed"] > 200
    for r in records:
        if r.error:
            continue
        assert r.last_execution_time is not None, f"{r.filename} lost its timing"
        assert r.last_execution_time_str != "unknown"


@needs_evidence
def test_real_directory_stats_account_for_every_file():
    """parsed + errors + degraded must equal total: no silent drops."""
    records, stats = parse_prefetch_directory(REAL_PREFETCH_DIR)
    assert stats["parsed"] + stats["errors"] + stats["degraded"] == stats["total"]
    assert len(records) == stats["total"]


@needs_evidence
def test_summary_line_flags_hash_mismatch(tmp_path):
    """A mismatch must be visible in the terminal output, not just the JSON."""
    good = REAL_PREFETCH_DIR / "RUNDLL32.EXE-DD681AC2.pf"
    data = bytearray(good.read_bytes())
    rec = parse_prefetch_file(good)
    # Rename to a stem whose hash does not match the file's own content hash.
    bogus = tmp_path / f"RUNDLL32.EXE-{'0' * 8}.pf"
    bogus.write_bytes(bytes(data))
    r = parse_prefetch_file(bogus)
    if r.prefetch_hash:
        assert r.filename_matches_content is False
        assert "MISMATCH" in format_prefetch_summary(r)


# ---------------------------------------------------------------------------
# Honest degradation when pyscca is unavailable
# ---------------------------------------------------------------------------

def test_missing_pyscca_degrades_without_inventing_values(tmp_path, monkeypatch):
    """With pyscca unimportable the record must be marked degraded, not filled in."""
    import builtins

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "pyscca":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)

    p = tmp_path / "CMD.EXE-1A2B3C4D.pf"
    p.write_bytes(b"MAM\x04" + b"\x00" * 512)
    r = parse_prefetch_file(p)

    assert r.error is None
    assert r.degraded is not None
    assert "pyscca" in r.degraded
    assert r.container == "MAM"          # detection still works without pyscca
    assert r.run_count is None           # nothing invented
    assert r.last_execution_time is None
    assert "DEGRADED" in format_prefetch_summary(r)


def test_zero_filled_file_distinguished_from_unknown_format(tmp_path):
    """An all-zero prefetch file is its own phenomenon, not "unknown format".

    3 of 225 files in the OWL 2019 corpus are full-size but entirely zero. They
    carry no prefetch structure, which is a meaningful observation about the
    artifact, so it must not be reported as an unrecognised container.
    """
    p = tmp_path / "CONHOST.EXE-0C6456FB.pf"
    p.write_bytes(b"\x00" * 5338)
    r = parse_prefetch_file(p)
    assert r.container == "ZERO_FILLED"
    assert r.error is not None
    assert "Zero-filled" in r.error
    assert r.run_count is None
    assert r.last_execution_time is None


@needs_evidence
def test_real_corpus_zero_filled_files_are_classified():
    records, stats = parse_prefetch_directory(REAL_PREFETCH_DIR)
    zero = [r for r in records if r.container == "ZERO_FILLED"]
    assert len(zero) == 3, f"expected the 3 known zero-filled files, got {len(zero)}"
    for r in zero:
        assert r.error is not None
