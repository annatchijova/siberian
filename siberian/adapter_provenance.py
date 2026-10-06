"""
siberian/adapter_provenance.py
==============================
Shared provenance record for the Nivel 6 artifact adapters.

Level 6 completion requires that every adapter preserve the original source,
the parser version, and the transformations it applied. None of the adapters
recorded a parser version or a transform list, so a JSON export could not be
interpreted later without knowing which code produced it.

This module provides one canonical shape for that record, used by every
``import-*`` command. It is deliberately stdlib-only and deterministic: the same
input always yields the same provenance, and nothing here reaches the network or
depends on the evidence directory's contents beyond hashing the named source.

Design notes
------------
* ``source_sha256`` is the digest of the source **as acquired**. It is the
  chain-of-custody anchor; the adapters' own internal hashes are separate and do
  not replace it.
* ``transformations`` lists what the adapter actually did, in order, in plain
  language. It must not claim work the adapter does not perform -- an empty
  tuple is the correct value for "decoded and copied".
* ``limitations`` states what the adapter cannot do. This is where the audits'
  findings belong permanently, so a consumer of the JSON sees them without
  reading the audit.
* ``determinism_level`` names the guarantee honestly: ``"deterministic"`` for a
  pure decode, ``"best_effort"`` when a dependency or heuristic is involved.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Bump when the shape of the provenance record changes.
PROVENANCE_VERSION = "1"


@dataclass(frozen=True)
class ParserSpec:
    """Static description of one adapter, recorded in every export."""

    name: str
    version: str
    #: Artifact classes this adapter claims to read.
    supports: Tuple[str, ...]
    #: Ordered, plain-language description of what the adapter does.
    transformations: Tuple[str, ...]
    #: What the adapter cannot do. Stated here so it travels with the data.
    limitations: Tuple[str, ...]
    #: Optional dependency required for full function, if any.
    requires: Optional[str] = None
    #: "deterministic" for a pure decode; "best_effort" when a heuristic or an
    #: external library is involved.
    determinism_level: str = "deterministic"


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> Optional[str]:
    """Return the SHA-256 of a file, or None if it cannot be read.

    Streams the file so a multi-gigabyte $MFT is not loaded into memory.
    """
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, IOError):
        return None


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_tree(root: Path, pattern: str = "*") -> Optional[str]:
    """Return a deterministic digest over a directory of artifacts.

    A directory has no single byte stream to hash, so without this an adapter
    pointed at a directory of 225 prefetch files would emit no
    chain-of-custody anchor at all. This hashes a manifest instead: for each
    matching file, in sorted relative-path order, the path, size and content
    digest are folded in.

    Sorting makes the result independent of readdir order, so the same directory
    yields the same digest on any machine and in any process.
    """
    root = Path(root)
    if not root.is_dir():
        return None
    try:
        files = sorted(
            (p for p in root.rglob(pattern) if p.is_file()),
            key=lambda p: str(p.relative_to(root)),
        )
    except OSError:
        return None

    manifest = hashlib.sha256()
    for file_path in files:
        rel = str(file_path.relative_to(root))
        digest = sha256_file(file_path)
        try:
            size = file_path.stat().st_size
        except OSError:
            size = -1
        manifest.update(rel.encode("utf-8"))
        manifest.update(b"\x00")
        manifest.update(str(size).encode("ascii"))
        manifest.update(b"\x00")
        manifest.update((digest or "").encode("ascii"))
        manifest.update(b"\n")
    return manifest.hexdigest()


def count_files(root: Path, pattern: str = "*") -> Optional[int]:
    """Count the artifacts a directory source contains, or None if unreadable."""
    root = Path(root)
    if not root.is_dir():
        return None
    try:
        return sum(1 for p in root.rglob(pattern) if p.is_file())
    except OSError:
        return None


def source_descriptor(path: Path, *, label: str = "primary") -> Dict[str, Any]:
    """Describe one source artifact without reading more than necessary."""
    p = Path(path)
    descriptor: Dict[str, Any] = {
        "label": label,
        "path": str(p),
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
        "size_bytes": None,
        "sha256": None,
        # For a directory: a digest over a sorted manifest of its files, so a
        # directory source still carries a reproducible anchor.
        "tree_sha256": None,
        "file_count": None,
        "hash_error": None,
    }
    if p.is_file():
        try:
            descriptor["size_bytes"] = p.stat().st_size
        except OSError as exc:
            descriptor["hash_error"] = f"cannot stat: {exc}"
        descriptor["sha256"] = sha256_file(p)
        if descriptor["sha256"] is None and descriptor["hash_error"] is None:
            descriptor["hash_error"] = "cannot read file for hashing"
    elif p.is_dir():
        descriptor["file_count"] = count_files(p)
        descriptor["tree_sha256"] = sha256_tree(p)
        if descriptor["tree_sha256"] is None and descriptor["hash_error"] is None:
            descriptor["hash_error"] = "cannot read directory for hashing"
    return descriptor


def build_provenance(
    spec: ParserSpec,
    sources: List[Path],
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical provenance record for one adapter run.

    Args:
        spec: the adapter's static description
        sources: the artifact(s) the adapter was pointed at
        extra: additional run-specific facts (counts, flags, degradation)

    Returns:
        A JSON-serialisable dict carrying the provenance version, the parser
        name and version, the sources with their digests, the ordered
        transformation list, the declared limitations, and the determinism level.
    """
    record: Dict[str, Any] = {
        "provenance_version": PROVENANCE_VERSION,
        "parser": {
            "name": spec.name,
            "version": spec.version,
            "supports": list(spec.supports),
            "determinism_level": spec.determinism_level,
            "requires": spec.requires,
        },
        "transformations": list(spec.transformations),
        "limitations": list(spec.limitations),
        "sources": [source_descriptor(p) for p in sources],
    }
    if extra:
        record["run"] = extra
    return record


# ---------------------------------------------------------------------------
# Adapter specifications
#
# `limitations` entries here are the standing, permanent record of each audit's
# residual risk. They are deliberately specific.
# ---------------------------------------------------------------------------

MFT_SPEC = ParserSpec(
    name="siberian.mft_parser",
    version="2",
    supports=("NTFS $MFT (FILE records)",),
    transformations=(
        "applied the update sequence array (fixups) to each record",
        "detected the record size from the volume rather than assuming 1024",
        "decoded resident attribute headers and read content at the resident "
        "content offset",
        "converted $STANDARD_INFORMATION and $FILE_NAME FILETIMEs to UTC using "
        "integer arithmetic",
        "recorded invalid and truncated records explicitly instead of dropping them",
    ),
    limitations=(
        "validated only against synthetic records; no real $MFT has been parsed",
        "non-resident attribute content is not read, so large-file sizes come "
        "from $FILE_NAME only",
        "header field 0x18 is the record's used size, not the size of the file "
        "the record describes (reported as real_size)",
    ),
)

PREFETCH_SPEC = ParserSpec(
    name="siberian.prefetch_parser",
    version="2",
    supports=("Windows Prefetch MAM (Windows 10+)", "Windows Prefetch SCCA (XP-8.1, delegated)"),
    transformations=(
        "detected the container signature",
        "delegated all structural decoding to libyal libscca via pyscca",
        "selected the most recent run time across the available slots",
        "computed the full SHA-256 of each artifact",
        "cross-checked the filename hash against the content prefetch hash",
    ),
    limitations=(
        "SCCA handling is delegated to libscca and is unvalidated: no SCCA "
        "sample exists in this workspace and references disagree on the "
        "signature offset",
        "timing and run counts come from libscca's interpretation and are not "
        "cross-checked against a second independent implementation",
        "zero-filled artifacts are reported as ZERO_FILLED; their cause is not "
        "determined here",
    ),
    requires="pyscca (libyal libscca)",
    determinism_level="best_effort",
)

AMCACHE_SPEC = ParserSpec(
    name="siberian.amcache_parser",
    version="2",
    supports=("Amcache.hve \\Root\\File", "Amcache.hve \\Root\\InventoryApplicationFile"),
    transformations=(
        "read only the two documented sections",
        "mapped hexadecimal value names onto field names",
        "stripped the 4-byte binary prefix from sha1, program_id and file_id",
        "coerced file_size from its hex string form",
        "converted only the three documented timestamp fields from FILETIME",
    ),
    limitations=(
        "no Amcache.hve exists in this workspace, so the field mapping has "
        "never run on real evidence",
        "\\Root\\Device and \\Root\\Driver sections are not read",
        "requires python-registry; without it nothing is reported",
    ),
    requires="python-registry",
)

SHIMCACHE_SPEC = ParserSpec(
    name="siberian.shimcache_parser",
    version="2",
    supports=("AppCompatCache REG_BINARY (SYSTEM hive)",),
    transformations=(
        "located the cache value by name under each ControlSet",
        "scanned the value for a length prefix, then for a UTF-16-LE path",
        "recorded parse_method per entry so a heuristic recovery is not "
        "presented as a decoded record",
    ),
    limitations=(
        "the shimcache record layout is NOT decoded; entries are recovered "
        "path strings, not decoded records",
        "no SYSTEM hive exists in this workspace, so neither the record layout "
        "nor the registry value name is confirmed against real evidence",
        "flags are absent because the parser does not read them",
        "last_modified is attributed by falling in a date range, not by a known "
        "offset",
    ),
    requires="python-registry",
    determinism_level="best_effort",
)

SHELLBAGS_SPEC = ParserSpec(
    name="siberian.shellbags_parser",
    version="2",
    supports=("Shellbags BagMRU (NTUSER.DAT / UsrClass.dat)", "Shellbags Bags"),
    transformations=(
        "resolved both Shell locations under Software\\Microsoft\\Windows\\Shell "
        "and Software\\Classes\\Local Settings",
        "read values at the bag key and at its numbered child slots",
        "decoded UTF-16-LE path strings at both byte alignments",
        "skipped the MRUList and NodeSlotCapacity bookkeeping values",
    ),
    limitations=(
        "the shellbag record layout is NOT decoded; only path strings are "
        "recovered",
        "no user hive exists in this workspace, so traversal is covered only by "
        "a stub of the python-registry interface",
        "view mode, sort mode and an accessed timestamp are NOT reported: they "
        "were previously invented from arbitrary bytes and have been removed",
        "a recovered path is a record that Explorer stored the path, not proof "
        "the folder existed",
    ),
    requires="python-registry",
    determinism_level="best_effort",
)

PLASO_SPEC = ParserSpec(
    name="siberian.plaso_import",
    version="2",
    supports=("Plaso l2tcsv export",),
    transformations=(
        "validated the case template is siberian-case-v1",
        "mapped l2tcsv columns to catalog expectations via an explicit mapping",
        "created UNKNOWN observations for unmatched rows with a recorded reason",
        "recorded input digest, row counts and the mappings used",
    ),
    limitations=(
        "unmatched rows become UNKNOWN observations, never PRESENT ones",
    ),
)
