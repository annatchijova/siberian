"""
siberian/prefetch_parser.py
===========================
Windows Prefetch (.pf) parser.

Container formats:
  - MAM (Windows 10+): signature b"MAM\\x04"/b"MAM\\x03" at offset 0,
    XPRESS-compressed payload.
  - SCCA (Windows XP..8.1): uncompressed. Historical parsers disagree on
    whether the "SCCA" signature sits at offset 0 or offset 4.

Design constraints and honesty notes
------------------------------------
* Structure parsing is delegated to pyscca (libyal libscca) for BOTH
  containers. This parser does NOT hand-decode SCCA field offsets.

  Rationale (red-team, see docs/red-team/NIVEL6_PREFETCH_AUDIT.md): a previous
  revision decoded SCCA fields at invented offsets, reading the format version
  from a field its own comment called "file size" and decoding filename
  characters as a FILETIME execution timestamp. No SCCA fixture exists in this
  workspace, so those offsets could not be validated. A value that cannot be
  verified is reported as absent, not estimated.

* pyscca is a hard requirement for structural fields. When it is missing the
  record is explicitly marked ``degraded`` and no timing value is invented.

* Windows Prefetch "MAM" is Windows 10 and later. XP..8.1 files are
  uncompressed SCCA/PFSF. Both are accepted; which one was seen is always
  reported in ``container``.

* The SHA-256 of the .pf file is the full 64-hex digest. A truncated digest is
  not a chain-of-custody anchor and is never presented as one.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

# FILETIME epoch (1601-01-01)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# libyal libscca exposes at most 8 run-time slots.
_MAX_RUN_SLOTS = 8


@dataclass
class PrefetchRecord:
    """Parsed Prefetch file metadata.

    Every optional field is None when it could not be recovered from the
    artifact. Absence is never replaced by a default that looks like data.
    """

    # Identity of the artifact itself
    filename: str
    file_sha256: str

    # Container detection
    container: str = "UNKNOWN"  # "MAM" | "SCCA" | "UNKNOWN"
    is_mam_compressed: bool = False

    # Content-derived fields (require pyscca)
    executable_filename: Optional[str] = None
    format_version: Optional[int] = None
    prefetch_hash: Optional[str] = None
    run_count: Optional[int] = None
    last_execution_time: Optional[datetime] = None
    last_execution_time_str: str = "unknown"
    volume_serial: Optional[int] = None
    volume_device_path: Optional[str] = None
    volume_creation_time: Optional[datetime] = None
    filenames_loaded: Optional[int] = None

    # Cross-checks between the file's name and its content
    stem_hash: Optional[str] = None
    filename_matches_content: Optional[bool] = None

    # Honest-degradation markers
    degraded: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "file_sha256": self.file_sha256,
            "container": self.container,
            "is_mam_compressed": self.is_mam_compressed,
            "executable_filename": self.executable_filename,
            "format_version": self.format_version,
            "prefetch_hash": self.prefetch_hash,
            "run_count": self.run_count,
            "last_execution_time": (
                self.last_execution_time.isoformat() if self.last_execution_time else None
            ),
            "last_execution_time_str": self.last_execution_time_str,
            "volume_serial": self.volume_serial,
            "volume_device_path": self.volume_device_path,
            "volume_creation_time": (
                self.volume_creation_time.isoformat() if self.volume_creation_time else None
            ),
            "filenames_loaded": self.filenames_loaded,
            "stem_hash": self.stem_hash,
            "filename_matches_content": self.filename_matches_content,
            "degraded": self.degraded,
            "error": self.error,
        }


def _executable_name_from_pf(stem: str) -> str:
    """Extract the executable name from a .pf filename stem.

    Windows Prefetch convention: ``EXECUTABLE.EXE-HHHHHHHH.pf`` where HHHHHHHH
    is the 8-hex Windows prefetch hash. The name is everything before the last
    '-'. Returns (name, hash_or_None).
    """
    base, sep, suffix = stem.rpartition("-")
    if sep and len(suffix) == 8 and all(c in "0123456789ABCDEFabcdef" for c in suffix):
        return base, suffix.upper()
    return stem, None


def _stem_hash(stem: str) -> Optional[str]:
    """Return the 8-hex prefetch hash embedded in the .pf filename, if any."""
    return _executable_name_from_pf(stem)[1]


def _filetime_to_datetime(ts: int) -> Optional[datetime]:
    """Convert a FILETIME (100ns since 1601-01-01) to datetime.

    Integer division keeps this exact and reproducible; the sub-microsecond
    remainder is discarded deterministically.
    """
    if not ts or ts < 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ts // 10)
    except (OverflowError, OSError, ValueError):
        return None


def detect_container(head: bytes) -> str:
    """Identify the prefetch container from the first bytes.

    Accepts the MAM signature at offset 0 and the SCCA signature at either
    offset 0 or offset 4, because published references disagree on the SCCA
    position and this parser does not decode SCCA fields itself. Detection is
    deliberately tolerant; field extraction is not speculative.
    """
    if head[0:4] in (b"MAM\x04", b"MAM\x03"):
        return "MAM"
    if head[0:4] == b"SCCA" or head[4:8] == b"SCCA":
        return "SCCA"
    return "UNKNOWN"


def parse_prefetch_file(path: Path) -> PrefetchRecord:
    """Parse one Windows Prefetch (.pf) file.

    Structural fields come from pyscca. If pyscca is unavailable or cannot read
    the file, the record is marked degraded or erroneous and the affected
    fields stay None.
    """
    path = Path(path)
    filename, stem_hash = _executable_name_from_pf(path.stem)

    try:
        data = path.read_bytes()
    except (IOError, OSError) as exc:
        return PrefetchRecord(
            filename=filename,
            file_sha256="",
            stem_hash=stem_hash,
            error=f"Cannot read file: {exc}",
        )

    file_sha256 = hashlib.sha256(data).hexdigest()

    if len(data) < 8:
        return PrefetchRecord(
            filename=filename,
            file_sha256=file_sha256,
            container="UNKNOWN",
            stem_hash=stem_hash,
            error=f"File too small to identify ({len(data)} bytes)",
        )

    container = detect_container(data[0:8])

    # A full-size prefetch file whose entire content is zero is a distinct
    # phenomenon, not an unknown format: the allocation exists but was never
    # populated, or was zeroed. Observed in 3 of 225 files in the OWL 2019
    # corpus. Labelling this "unrecognised container" would bury a real signal,
    # so it is reported separately.
    if container == "UNKNOWN" and not any(data):
        return PrefetchRecord(
            filename=filename,
            file_sha256=file_sha256,
            container="ZERO_FILLED",
            stem_hash=stem_hash,
            error=(
                f"Zero-filled prefetch artifact ({len(data)} bytes, no content). "
                f"No execution data recoverable from this file; the allocation "
                f"exists but holds no prefetch structure."
            ),
        )

    if container == "UNKNOWN":
        return PrefetchRecord(
            filename=filename,
            file_sha256=file_sha256,
            container="UNKNOWN",
            stem_hash=stem_hash,
            error=(
                f"Unrecognised prefetch container: first 8 bytes "
                f"{data[0:8]!r} (expected MAM at offset 0 or SCCA)"
            ),
        )

    record = PrefetchRecord(
        filename=filename,
        file_sha256=file_sha256,
        container=container,
        is_mam_compressed=(container == "MAM"),
        stem_hash=stem_hash,
    )

    try:
        import pyscca
    except ImportError:
        record.degraded = (
            "pyscca (libyal libscca) not installed: container detected but "
            "no structural field could be read. No timing value is reported "
            "rather than estimated."
        )
        return record

    scca_file = pyscca.file()
    try:
        scca_file.open(str(path))
    except Exception as exc:
        record.error = f"libscca could not open the file: {exc}"
        return record

    try:
        record.executable_filename = _safe_call(scca_file.get_executable_filename)
        version = _safe_call(scca_file.get_format_version)
        record.format_version = version if isinstance(version, int) else None

        run_count = _safe_call(scca_file.get_run_count)
        record.run_count = run_count if isinstance(run_count, int) else None

        prefetch_hash = _safe_call(scca_file.get_prefetch_hash)
        if isinstance(prefetch_hash, int):
            record.prefetch_hash = f"{prefetch_hash:08X}"
            if stem_hash:
                record.filename_matches_content = (
                    stem_hash.upper() == record.prefetch_hash.upper()
                )

        latest = 0
        for slot in range(_MAX_RUN_SLOTS):
            ticks = _safe_call(scca_file.get_last_run_time_as_integer, slot)
            if isinstance(ticks, int) and ticks > latest:
                latest = ticks
        if latest > 0:
            record.last_execution_time = _filetime_to_datetime(latest)
            if record.last_execution_time:
                record.last_execution_time_str = record.last_execution_time.isoformat()

        try:
            record.filenames_loaded = scca_file.get_number_of_filenames()
        except Exception:
            record.filenames_loaded = None

        try:
            if scca_file.get_number_of_volumes() > 0:
                volume = scca_file.get_volume_information(0)
                serial = _safe_call(volume.get_serial_number)
                record.volume_serial = serial if isinstance(serial, int) else None
                record.volume_device_path = _safe_call(volume.get_device_path)
                record.volume_creation_time = _safe_call(volume.get_creation_time)
        except Exception:
            # Volume metadata is supplementary; its absence does not
            # invalidate the record, but it must not be faked.
            pass

    except Exception as exc:
        record.error = f"libscca read failed: {exc}"
    finally:
        try:
            scca_file.close()
        except Exception:
            pass

    return record


def _safe_call(fn, *args):
    """Call a pyscca accessor, returning None instead of raising.

    libscca raises OSError for fields a given container does not expose (for
    example prefetch_hash on MAM). That is an absent field, not a failure.
    """
    try:
        return fn(*args)
    except Exception:
        return None


def parse_prefetch_directory(
    directory: Path, max_files: int = 0
) -> tuple[List[PrefetchRecord], Dict[str, int]]:
    """Parse every .pf file in a directory.

    Returns (records, stats). Per-file failures are kept as records with an
    explicit error, and the stats make the failure counts visible so a caller
    cannot mistake a partial parse for a complete one.

    ``stats`` distinguishes:
      available   how many .pf files the directory holds
      processed   how many were actually parsed
      truncated   available - processed, non-zero only when max_files bit

    ``total`` is retained as an alias of ``processed`` for compatibility.
    """
    directory = Path(directory)
    available = sorted(directory.glob("*.pf"))

    # Respecting a limit is not the same as silently dropping the remainder:
    # a truncated run must be distinguishable from a complete one, so the
    # available count is recorded alongside the processed count.
    paths = available[:max_files] if max_files > 0 else available
    truncated = len(available) - len(paths)

    records: List[PrefetchRecord] = []
    stats = {
        "available": len(available),
        "processed": len(paths),
        "truncated": truncated,
        "max_files": max_files,
        "parsed": 0,
        "errors": 0,
        "degraded": 0,
    }

    for path in paths:
        record = parse_prefetch_file(path)
        records.append(record)
        if record.error:
            stats["errors"] += 1
        elif record.degraded:
            stats["degraded"] += 1
        else:
            stats["parsed"] += 1

    # Backwards-compatible alias. `available` is the honest denominator.
    stats["total"] = stats["processed"]
    return records, stats


def format_prefetch_summary(record: PrefetchRecord) -> str:
    """Format one record as a single terminal line."""
    if record.error:
        return f"ERROR  {record.filename}: {record.error}"
    version = record.format_version if record.format_version is not None else "?"
    runs = record.run_count if record.run_count is not None else "?"
    flag = ""
    if record.filename_matches_content is False:
        flag = "  [FILENAME/CONTENT HASH MISMATCH]"
    elif record.degraded:
        flag = "  [DEGRADED]"
    return (
        f"{record.filename:28s} v{str(version):4s} runs={str(runs):4s} "
        f"container={record.container:4s} last_run={record.last_execution_time_str}{flag}"
    )
