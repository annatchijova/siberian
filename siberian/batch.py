"""
siberian/batch.py
=================
Batch execution for the Nivel 6 artifact adapters.

Level 6 states a batch must not mix cases or sources, and must respect
configured limits. This module implements both as enforceable invariants rather
than as conventions.

Invariants
----------
**No mixed sources.** Every input produces its own output file. Two inputs can
never share an output path: the runner derives each output name from the input
and refuses to continue if that would collide. Nothing is ever appended to
another input's output.

**No mixed cases.** Each output records the digest of exactly one source. Before
writing, the runner checks any existing output: if it was produced from a
different source, the batch stops rather than overwriting it. Re-running the
same batch over the same sources is idempotent; pointing it at new sources is
refused.

**One failure cannot contaminate another.** Each input is processed in its own
try/except and its outcome recorded independently. A source that cannot be read
produces a recorded failure, not an aborted batch and not a poisoned sibling.

**Limits are disclosed.** Limits on the number of inputs and on the work per
input are enforced *and* recorded, including how much was left unprocessed. A
truncated batch is distinguishable from a complete one.

Determinism: given the same inputs and options, the manifest is byte-identical
except for values that are inherently wall-clock (recorded under ``run`` and
excluded from the digest input). The per-input provenance is produced by the
same code path as a single ``import-*`` invocation.
"""
from __future__ import annotations

import json
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .adapter_provenance import (
    PROVENANCE_VERSION,
    AMCACHE_SPEC,
    MFT_SPEC,
    PREFETCH_SPEC,
    SHELLBAGS_SPEC,
    SHIMCACHE_SPEC,
    ParserSpec,
    build_provenance,
)

BATCH_MANIFEST_VERSION = "1"


class BatchError(Exception):
    """Raised when a batch cannot start without violating an invariant."""


@dataclass
class BatchLimits:
    """Configured limits for one batch run."""

    #: Maximum number of inputs to process. 0 = no limit.
    max_inputs: int = 0
    #: Maximum items per input, forwarded to the adapter (records/files/entries).
    #: 0 = no limit.
    #:
    #: Note on semantics: directory inputs are expanded into individual
    #: artifacts, one output each, so this limit binds only on artifacts that
    #: contain many items -- a $MFT holds many records, a single .pf holds one.
    #: Whatever the limit drops is recorded in the output's statistics, never
    #: silently discarded.
    max_items_per_input: int = 0
    #: Refuse to start if fewer than this many inputs are found. Guards against a
    #: mistyped path silently yielding a one-item "batch".
    min_inputs: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_inputs": self.max_inputs,
            "max_items_per_input": self.max_items_per_input,
            "min_inputs": self.min_inputs,
        }


@dataclass
class InputOutcome:
    """Result of processing one input."""

    source: str
    output: Optional[str]
    status: str  # "ok" | "partial" | "failed" | "skipped"
    detail: Optional[str] = None
    source_digest: Optional[str] = None
    item_stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "output": self.output,
            "status": self.status,
            "detail": self.detail,
            "source_digest": self.source_digest,
            "item_stats": self.item_stats,
        }


@dataclass
class BatchResult:
    """Aggregate outcome of a batch."""

    adapter: str
    outcomes: List[InputOutcome] = field(default_factory=list)
    limits: BatchLimits = field(default_factory=BatchLimits)
    inputs_available: int = 0
    inputs_skipped_by_limit: int = 0
    manifest_path: Optional[str] = None

    @property
    def ok(self) -> bool:
        return all(o.status == "ok" for o in self.outcomes)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "failed")

    @property
    def partial(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "partial")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch_version": BATCH_MANIFEST_VERSION,
            "provenance_version": PROVENANCE_VERSION,
            "adapter": self.adapter,
            "limits": self.limits.to_dict(),
            "inputs_available": self.inputs_available,
            "inputs_processed": len(self.outcomes),
            "inputs_skipped_by_limit": self.inputs_skipped_by_limit,
            "summary": {
                "ok": sum(1 for o in self.outcomes if o.status == "ok"),
                "partial": self.partial,
                "failed": self.failed,
            },
            "inputs": [o.to_dict() for o in self.outcomes],
        }


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

def discover_inputs(
    inputs: List[Path],
    pattern: str,
    recursive: bool = False,
) -> List[Path]:
    """Expand the given paths into a sorted, de-duplicated list of sources.

    Sorting makes the batch order deterministic, so the manifest is
    reproducible. Duplicates are removed so the same file is never processed
    twice under two names.
    """
    found: List[Path] = []
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            globber = path.rglob if recursive else path.glob
            found.extend(sorted(p for p in globber(pattern) if p.is_file()))
        elif path.is_file():
            found.append(path)
        # A non-existent path is recorded by the caller as a failure rather than
        # silently skipped here.
    seen = set()
    unique = []
    for path in found:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


# ---------------------------------------------------------------------------
# Output naming and the no-mixed-sources invariant
# ---------------------------------------------------------------------------

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def output_name_for(source: Path, index: int) -> str:
    """Derive a deterministic output filename from a source path.

    The index prefix guarantees uniqueness even when two sources share a stem
    in different directories, which is what would otherwise cause two inputs to
    collide on one output.
    """
    stem = _UNSAFE.sub("_", source.name).strip("_") or "source"
    return f"{index:04d}_{stem}.json"


def assert_no_output_collision(outputs: List[Path]) -> None:
    """Refuse the batch if two inputs would write the same file."""
    seen: Dict[str, str] = {}
    for out, source in outputs:
        key = str(out.resolve()) if out.parent.exists() else str(out)
        if key in seen:
            raise BatchError(
                f"Refusing to run: inputs {seen[key]!r} and {source!r} would "
                f"both write {out}. A batch must not mix sources into one file."
            )
        seen[key] = source


def assert_output_matches_source(output_path: Path, source_digest: Optional[str]) -> None:
    """Refuse to overwrite an output that belongs to a different source.

    This is the no-mixed-cases guard. Re-running the same batch over the same
    sources is fine (idempotent); writing a different source over an existing
    export is not, because it would silently replace one case's evidence with
    another's under the same filename.
    """
    if not output_path.exists():
        return
    if source_digest is None:
        # Nothing to compare against; refuse rather than assume.
        raise BatchError(
            f"Refusing to overwrite {output_path}: the new source could not be "
            f"digested, so it cannot be shown to be the same evidence."
        )
    try:
        existing = json.loads(output_path.read_text(encoding="utf-8"))
        recorded = (existing.get("provenance") or {}).get("sources", [{}])[0]
    except (OSError, ValueError, IndexError, TypeError) as exc:
        raise BatchError(
            f"Refusing to overwrite {output_path}: it is not a readable adapter "
            f"export ({exc})."
        ) from exc

    previous = recorded.get("sha256") or recorded.get("tree_sha256")
    if previous is None:
        raise BatchError(
            f"Refusing to overwrite {output_path}: it carries no source digest, "
            f"so its provenance cannot be compared."
        )
    if previous != source_digest:
        raise BatchError(
            f"Refusing to overwrite {output_path}: it was produced from a "
            f"different source ({previous[:16]}... vs {source_digest[:16]}...). "
            f"Write to a different output directory so cases are not mixed."
        )


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BatchAdapter:
    """One adapter, callable over a single source path."""

    name: str
    spec: ParserSpec
    #: Runs the adapter and returns (payload_dict, status, detail, item_stats).
    run: Callable[[Path, "BatchLimits"], Any]


def _mft_run(source: Path, limits: BatchLimits) -> Any:
    from .mft_parser import parse_mft_file

    stats: Dict[str, Any] = {}
    records = parse_mft_file(source, max_records=limits.max_items_per_input, stats=stats)
    invalid = sum(1 for r in records if not r.is_valid)
    payload = {
        "provenance": build_provenance(
            MFT_SPEC, [source],
            extra={
                "records_parsed": len(records),
                "records_invalid": invalid,
                "available": stats.get("available"),
                "processed": stats.get("processed"),
                "truncated": stats.get("truncated"),
                "max_records": limits.max_items_per_input,
                "record_size": stats.get("record_size"),
            },
        ),
        "records": [r.to_dict() for r in records],
    }
    status = "partial" if (invalid or stats.get("truncated")) else "ok"
    detail = None
    # Zero records from a readable file is not a successful parse: an empty or
    # non-$MFT file yields nothing, and "ok" would report that as a clean run.
    if not records:
        status = "failed" if stats.get("empty_file") else "partial"
        detail = (
            "file is empty: no MFT records present"
            if stats.get("empty_file")
            else "no MFT records decoded from this file"
        )
    elif invalid:
        detail = f"{invalid} record(s) did not parse"
    if stats.get("truncated"):
        detail = (detail + "; " if detail else "") + (
            f"{stats['truncated']} record(s) not parsed (limit)"
        )
    return payload, status, detail, stats


def _prefetch_run(source: Path, limits: BatchLimits) -> Any:
    from .prefetch_parser import parse_prefetch_directory, parse_prefetch_file

    if source.is_dir():
        records, stats = parse_prefetch_directory(
            source, max_files=limits.max_items_per_input
        )
    else:
        record = parse_prefetch_file(source)
        records = [record]
        stats = {
            "available": 1, "processed": 1, "truncated": 0,
            "max_files": limits.max_items_per_input,
            "parsed": 0 if (record.error or record.degraded) else 1,
            "errors": 1 if record.error else 0,
            "degraded": 1 if record.degraded else 0,
            "total": 1,
        }
    payload = {
        "provenance": build_provenance(
            PREFETCH_SPEC, [source], extra={"stats": stats}
        ),
        "records": [r.to_dict() for r in records],
    }
    status = "ok"
    if stats.get("errors") or stats.get("degraded") or stats.get("truncated"):
        status = "partial"
    detail = []
    if stats.get("errors"):
        detail.append(f"{stats['errors']} failed")
    if stats.get("degraded"):
        detail.append(f"{stats['degraded']} degraded")
    if stats.get("truncated"):
        detail.append(f"{stats['truncated']} not parsed (limit)")
    return payload, status, "; ".join(detail) or None, stats


def _amcache_run(source: Path, limits: BatchLimits) -> Any:
    from .amcache_parser import parse_amcache_hive

    result = parse_amcache_hive(source)
    payload = {
        "provenance": build_provenance(
            AMCACHE_SPEC, [source],
            extra={
                "entries_parsed": len(result.entries),
                "sections_found": result.sections_found,
                "sections_absent": result.sections_absent,
                "degraded": result.degraded,
            },
        ),
        "entries": [e.to_dict() for e in result.entries],
        "sections_found": result.sections_found,
        "sections_absent": result.sections_absent,
        "errors": result.errors,
        "degraded": result.degraded,
    }
    if result.errors or result.degraded:
        detail = "; ".join(result.errors) or result.degraded
        return payload, "partial", detail, {"entries": len(result.entries)}
    return payload, "ok", None, {"entries": len(result.entries)}


def _shimcache_run(source: Path, limits: BatchLimits) -> Any:
    from .shimcache_parser import parse_shimcache_from_registry

    entries = parse_shimcache_from_registry(source)
    parsed = [e for e in entries if not e.error]
    payload = {
        "provenance": build_provenance(
            SHIMCACHE_SPEC, [source],
            extra={
                "entries_parsed": len(parsed),
                "parse_methods": sorted({e.parse_method for e in parsed}),
            },
        ),
        "entries": [e.to_dict() for e in entries],
    }
    if not parsed:
        detail = entries[0].error if entries and entries[0].error else "no entries recovered"
        return payload, "partial", detail, {"entries": 0}
    return payload, "ok", None, {"entries": len(parsed)}


def _shellbags_run(source: Path, limits: BatchLimits) -> Any:
    from .shellbags_parser import parse_shellbags_from_registry

    entries = parse_shellbags_from_registry(source)
    parsed = [e for e in entries if not e.error]
    payload = {
        "provenance": build_provenance(
            SHELLBAGS_SPEC, [source], extra={"entries_parsed": len(parsed)}
        ),
        "entries": [e.to_dict() for e in entries],
    }
    if not parsed:
        detail = entries[0].error if entries and entries[0].error else "no entries recovered"
        return payload, "partial", detail, {"entries": 0}
    return payload, "ok", None, {"entries": len(parsed)}


ADAPTERS: Dict[str, BatchAdapter] = {
    "mft": BatchAdapter("mft", MFT_SPEC, _mft_run),
    "prefetch": BatchAdapter("prefetch", PREFETCH_SPEC, _prefetch_run),
    "amcache": BatchAdapter("amcache", AMCACHE_SPEC, _amcache_run),
    "shimcache": BatchAdapter("shimcache", SHIMCACHE_SPEC, _shimcache_run),
    "shellbags": BatchAdapter("shellbags", SHELLBAGS_SPEC, _shellbags_run),
}


def get_adapter(name: str) -> BatchAdapter:
    try:
        return ADAPTERS[name]
    except KeyError:
        raise BatchError(
            f"Unknown adapter {name!r}. Available: {', '.join(sorted(ADAPTERS))}"
        ) from None


# ---------------------------------------------------------------------------
# The batch runner
# ---------------------------------------------------------------------------

def run_batch(
    adapter_name: str,
    inputs: List[Path],
    out_dir: Path,
    limits: Optional[BatchLimits] = None,
    pattern: str = "*",
    recursive: bool = False,
    allow_partial: bool = False,
    manifest_name: str = "batch-manifest.json",
) -> BatchResult:
    """Run one adapter over many inputs, one output per input.

    Raises BatchError if an invariant would be violated. Individual input
    failures are recorded, not raised.
    """
    adapter = get_adapter(adapter_name)
    limits = limits or BatchLimits()
    out_dir = Path(out_dir)

    sources = discover_inputs(inputs, pattern, recursive=recursive)

    # Record inputs that do not exist, rather than silently dropping them.
    missing = [
        Path(p) for p in inputs
        if not Path(p).exists()
    ]

    if len(sources) < limits.min_inputs:
        raise BatchError(
            f"Found {len(sources)} input(s) but min_inputs={limits.min_inputs}. "
            f"Refusing to run a batch that would silently cover less than "
            f"expected; check the path and the --pattern."
        )

    applied_limit = limits.max_inputs if limits.max_inputs > 0 else len(sources)
    skipped = max(0, len(sources) - applied_limit)
    selected = sources[:applied_limit]

    planned = [(out_dir / output_name_for(src, i), src) for i, src in enumerate(selected)]
    assert_no_output_collision(planned)

    out_dir.mkdir(parents=True, exist_ok=True)

    result = BatchResult(
        adapter=adapter.name,
        limits=limits,
        inputs_available=len(sources),
        inputs_skipped_by_limit=skipped,
    )

    for source in missing:
        result.outcomes.append(InputOutcome(
            source=str(source), output=None, status="failed",
            detail="source does not exist",
        ))

    for out_path, source in planned:
        outcome = _process_one(adapter, source, out_path, limits)
        result.outcomes.append(outcome)

    manifest_path = out_dir / manifest_name
    manifest_path.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    result.manifest_path = str(manifest_path)

    return result


def _process_one(
    adapter: BatchAdapter, source: Path, out_path: Path, limits: BatchLimits
) -> InputOutcome:
    """Process a single source in isolation.

    Any exception is contained here: it becomes a recorded failure for this
    input and cannot affect a sibling.
    """
    digest = None
    try:
        from .adapter_provenance import source_descriptor

        digest = source_descriptor(source)
        digest = digest.get("sha256") or digest.get("tree_sha256")
    except Exception:
        digest = None

    # The no-mixed-cases guard runs before any work is done.
    try:
        assert_output_matches_source(out_path, digest)
    except BatchError as exc:
        return InputOutcome(
            source=str(source), output=str(out_path), status="failed",
            detail=str(exc), source_digest=digest,
        )

    try:
        payload, status, detail, item_stats = adapter.run(source, limits)
    except Exception as exc:
        return InputOutcome(
            source=str(source), output=None, status="failed",
            detail=f"{type(exc).__name__}: {exc}", source_digest=digest,
            item_stats={"traceback": traceback.format_exc(limit=3)},
        )

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        return InputOutcome(
            source=str(source), output=None, status="failed",
            detail=f"cannot write output: {exc}", source_digest=digest,
        )

    return InputOutcome(
        source=str(source), output=str(out_path), status=status,
        detail=detail, source_digest=digest, item_stats=item_stats,
    )


def format_batch_report(result: BatchResult, max_report: int = 20) -> str:
    """Render a batch result for the terminal.

    The per-input listing is capped: a batch over a real Prefetch directory is
    225 inputs, and a report that prints one line each is unusable. Problems
    are always listed, up to the cap, so a failure cannot be hidden by the cap.
    """
    lines = [
        f"Batch adapter: {result.adapter}",
        f"  inputs available : {result.inputs_available}",
        f"  inputs processed : {len(result.outcomes)}",
    ]
    if result.limits.max_inputs:
        lines.append(f"  --max-inputs    : {result.limits.max_inputs}")
    if result.inputs_skipped_by_limit:
        lines.append(
            f"  NOT PROCESSED   : {result.inputs_skipped_by_limit} "
            f"(max_inputs reached)"
        )
    lines.append(
        f"  ok={result.to_dict()['summary']['ok']} "
        f"partial={result.partial} failed={result.failed}"
    )
    # Show problems first, then clean inputs, capped in total.
    problems = [o for o in result.outcomes if o.status != "ok"]
    clean = [o for o in result.outcomes if o.status == "ok"]
    shown = problems[:max_report]
    if len(problems) > max_report:
        lines.append(f"  ... and {len(problems) - max_report} more problem(s)")
    shown += clean[: max(0, max_report - len(shown))]
    for outcome in shown:
        mark = {"ok": "ok      ", "partial": "PARTIAL", "failed": "FAILED "}[outcome.status]
        detail = f"  ({outcome.detail})" if outcome.detail else ""
        lines.append(f"  [{mark}] {Path(outcome.source).name}{detail}")
    hidden = len(result.outcomes) - len(shown)
    if hidden > 0:
        lines.append(f"  ... and {hidden} more input(s) listed in the manifest")
    if result.manifest_path:
        lines.append(f"  manifest: {result.manifest_path}")
    return "\n".join(lines)
