"""
siberian/prefetch_parser.py
===========================
Windows Prefetch (.pf) binary parser.

Supports both formats:
  - SCCA (WinXP..Win8, versions 17/23/26/30): signature "SCCA" at offset 4
  - MAM (Win10+, version 30): signature "MAM\\x03"/"MAM\\x04" at offset 0,
    XPRESS Huffman compressed

Design constraints:
- No external dependencies (stdlib only)
- Terminal-only output
- Each .pf file is an independent evidence item
- Derives executable name from filename stem (works for both formats)
- For MAM-compressed files, timing fields require decompression (pyscca);
  without it, fields are reported as \\"unknown\\" (honest degradation)
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


# FILETIME epoch (1601-01-01)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass
class PrefetchRecord:
    """Parsed Prefetch file metadata."""
    filename: str
    file_hash: str
    last_execution_time: Optional[datetime] = None
    last_execution_time_str: str = "unknown"
    run_count: int = 0
    format_version: Optional[int] = None
    is_mam_compressed: bool = False
    volume_info: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "file_hash": self.file_hash,
            "last_execution_time": self.last_execution_time.isoformat() if self.last_execution_time else None,
            "last_execution_time_str": self.last_execution_time_str,
            "run_count": self.run_count,
            "format_version": self.format_version,
            "is_mam_compressed": self.is_mam_compressed,
            "volume_info": self.volume_info,
            "error": self.error,
        }


def _executable_name_from_pf(stem: str) -> str:
    """Extract executable name from .pf filename stem.
    
    Windows Prefetch convention: `EXECUTABLE.EXE-HHHHHHHH.pf`
    where HHHHHHHH is an 8-hex hash. The real name is everything before the last '-'.
    """
    base, sep, suffix = stem.rpartition("-")
    if sep and len(suffix) == 8 and all(c in "0123456789ABCDEFabcdef" for c in suffix):
        return base
    return stem


def _filetime_to_datetime(ts: int) -> Optional[datetime]:
    """Convert NTFS FILETIME (100ns since 1601-01-01) to datetime."""
    if ts == 0:
        return None
    try:
        microseconds = ts // 10
        return _FILETIME_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, OSError, ValueError):
        return None


def parse_prefetch_file(path: Path) -> PrefetchRecord:
    """Parse one Windows Prefetch (.pf) file.
    
    Returns PrefetchRecord with available metadata.
    """
    try:
        data = path.read_bytes()
    except (IOError, OSError) as e:
        return PrefetchRecord(
            filename=_executable_name_from_pf(path.stem),
            file_hash="",
            error=f"Cannot read file: {e}",
        )

    if len(data) < 8:
        return PrefetchRecord(
            filename=_executable_name_from_pf(path.stem),
            file_hash=hashlib.sha256(data).hexdigest()[:16],
            error=f"File too small ({len(data)} bytes)",
        )

    filename = _executable_name_from_pf(path.stem)
    file_hash = hashlib.sha256(data).hexdigest()[:16]

    head = data[0:4]
    sig_at_4 = data[4:8]

    is_mam = head in (b"MAM\x04", b"MAM\x03")
    is_scca = sig_at_4 == b"SCCA"

    if not (is_mam or is_scca):
        return PrefetchRecord(
            filename=filename,
            file_hash=file_hash,
            error=f"Invalid signature: head={head!r}, sig_at_4={sig_at_4!r} (expected SCCA or MAM)",
        )

    version = None
    last_execution_time: Optional[datetime] = None
    last_execution_time_str = "unknown"
    run_count = 0

    if is_scca:
        # SCCA format: basic header at offset 4
        try:
            # SCCA header layout (simplified):
            # Offset 0: Unused (4 bytes)
            # Offset 4: "SCCA" signature
            # Offset 8: File size (4 bytes)
            # Offset 12: File name (60 bytes, UTF-16-LE)
            # Offset 72: Last run time (8 bytes, FILETIME)
            # Offset 80: Run count (4 bytes)
            version = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else None
            if len(data) >= 80:
                last_run_raw = struct.unpack_from("<Q", data, 72)[0]
                last_execution_time = _filetime_to_datetime(last_run_raw)
                last_execution_time_str = last_execution_time.isoformat() if last_execution_time else "unknown"
            if len(data) >= 84:
                run_count = struct.unpack_from("<I", data, 80)[0]
        except (struct.error, IndexError, ValueError) as e:
            return PrefetchRecord(
                filename=filename,
                file_hash=file_hash,
                format_version=version,
                is_mam_compressed=False,
                error=f"SCCA parse error: {e}",
            )
    elif is_mam:
        # MAM format (Win10+): XPRESS compressed, requires pyscca for real values
        try:
            # MAM header:
            # Offset 0: "MAM\x04" or "MAM\x03"
            # Offset 4: Decompressed size (4 bytes)
            # Offset 8: Compressed data starts
            version = 30  # MAM implies version 30
            is_compressed = True

            # Try to get pyscca if available (optional)
            try:
                import pyscca
                scca_file = pyscca.file()
                try:
                    scca_file.open(str(path))
                    run_count = scca_file.run_count
                    latest_ticks = 0
                    for slot in range(8):
                        ticks = scca_file.get_last_run_time_as_integer(slot)
                        if ticks and ticks > latest_ticks:
                            latest_ticks = ticks
                    if latest_ticks > 0:
                        last_execution_time = _filetime_to_datetime(latest_ticks)
                        last_execution_time_str = last_execution_time.isoformat() if last_execution_time else "unknown"
                finally:
                    scca_file.close()
            except ImportError:
                pass  # pyscca not installed - report unknown
        except Exception as e:
            return PrefetchRecord(
                filename=filename,
                file_hash=file_hash,
                format_version=version,
                is_mam_compressed=True,
                error=f"MAM parse error: {e}",
            )

    return PrefetchRecord(
        filename=filename,
        file_hash=file_hash,
        last_execution_time=last_execution_time,
        last_execution_time_str=last_execution_time_str,
        run_count=run_count,
        format_version=version,
        is_mam_compressed=is_mam,
    )


def parse_prefetch_directory(dir_path: Path, max_files: int = 0) -> List[PrefetchRecord]:
    """Parse all .pf files in a directory."""
    records: List[PrefetchRecord] = []
    try:
        pf_files = sorted(dir_path.glob("*.pf"))
    except (IOError, OSError):
        return records

    for pf in pf_files:
        record = parse_prefetch_file(pf)
        records.append(record)
        if max_files > 0 and len(records) >= max_files:
            break

    return records


def format_prefetch_summary(record: PrefetchRecord) -> str:
    """Format one record as a human-readable summary line."""
    status = "MAM" if record.is_mam_compressed else "SCCA"
    time_str = record.last_execution_time_str if record.last_execution_time_str != "unknown" else "unknown"
    runs = str(record.run_count) if record.run_count > 0 else "?"
    if record.error:
        return f"{record.filename:40s} | {status} | ERROR: {record.error}"
    return f"{record.filename:40s} | {status:4s} | last exec: {time_str:20s} | runs: {runs}"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m siberian.prefetch_parser <prefetch_dir_or_file> [max_files]")
        sys.exit(1)
    target = Path(sys.argv[1])
    max_files = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    if target.is_file():
        record = parse_prefetch_file(target)
        print(format_prefetch_summary(record))
    elif target.is_dir():
        records = parse_prefetch_directory(target, max_files=max_files)
        print(f"Parsed {len(records)} Prefetch records")
        for r in records[:100]:
            print(format_prefetch_summary(r))
        if len(records) > 100:
            print(f"... and {len(records) - 100} more")
    else:
        print(f"Error: {target} is not a file or directory")
        sys.exit(1)