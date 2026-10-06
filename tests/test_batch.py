"""Tests for the Nivel 6 batch runner.

Level 6 requires that a batch does not mix cases or sources and respects
configured limits. These tests treat those as invariants to be enforced, not as
conventions to be documented.

The tests use synthetic artifacts. No real SYSTEM/NTUSER/Amcache hive exists in
this workspace, so the registry adapters are exercised only on failure paths; the
MFT and Prefetch adapters are exercised end to end because those artifacts can
be constructed faithfully.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from siberian.batch import (
    ADAPTERS,
    BatchError,
    BatchLimits,
    assert_no_output_collision,
    assert_output_matches_source,
    discover_inputs,
    format_batch_report,
    get_adapter,
    output_name_for,
    run_batch,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mft_record(record_number: int = 0) -> bytes:
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 16, 1)
    struct.pack_into("<H", rec, 18, 1)
    struct.pack_into("<H", rec, 20, 56)
    struct.pack_into("<I", rec, 24, 1024)
    struct.pack_into("<I", rec, 28, 1024)
    struct.pack_into("<I", rec, 44, record_number)
    return bytes(rec)


def _good_mft(path: Path, n: int = 3, tag: bytes = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_mft_record() * n + tag)
    return path


def _pf(path: Path, seed: int = 0) -> Path:
    """A synthetic MAM container.

    Note: libscca cannot decode a synthetic payload, so these parse as
    `partial`. That is the correct outcome and tests assert on record counts
    rather than on a clean status. Real prefetch artifacts are used separately
    where a genuine parse matters.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MAM\x04" + bytes([seed % 256]) * 300)
    return path


# ---------------------------------------------------------------------------
# Invariant: no mixed sources
# ---------------------------------------------------------------------------

def test_each_input_gets_its_own_output(tmp_path):
    a = _good_mft(tmp_path / "a" / "SYSTEM")
    b = _good_mft(tmp_path / "b" / "SYSTEM")
    out = tmp_path / "out"
    result = run_batch("mft", [a, b], out, limits=BatchLimits(min_inputs=1))

    outputs = {o.output for o in result.outcomes if o.output}
    assert len(outputs) == 2, "two inputs must not share one output"
    for path in outputs:
        assert Path(path).exists()


def test_same_filename_in_different_directories_does_not_collide(tmp_path):
    """The index prefix is what prevents this; the stem alone would collide."""
    a = _good_mft(tmp_path / "a" / "SYSTEM")
    b = _good_mft(tmp_path / "b" / "SYSTEM")
    out = tmp_path / "out"
    result = run_batch("mft", [a, b], out)
    names = sorted(Path(o.output).name for o in result.outcomes if o.output)
    assert names[0] != names[1]


def test_output_names_are_unique_and_ordered(tmp_path):
    names = [output_name_for(Path(f"/x/dir{i}/SAME.pf"), i) for i in range(5)]
    assert len(set(names)) == 5


def test_output_name_is_filesystem_safe(tmp_path):
    name = output_name_for(Path("/x/weird name<>|*.pf"), 3)
    assert not set(name) & set('<>|*?"/\\')
    assert name.endswith(".json")


def test_collision_guard_raises():
    same = Path("/out/0000_SYSTEM.json")
    with pytest.raises(BatchError, match="would both write"):
        assert_no_output_collision([(same, "source-a"), (same, "source-b")])


def test_collision_guard_allows_distinct_outputs(tmp_path):
    assert_no_output_collision([
        (tmp_path / "a.json", "s1"),
        (tmp_path / "b.json", "s2"),
    ])


# ---------------------------------------------------------------------------
# Invariant: no mixed cases
# ---------------------------------------------------------------------------

def test_refuses_to_overwrite_an_output_from_a_different_source(tmp_path):
    src = _good_mft(tmp_path / "SYSTEM")
    out = tmp_path / "out"
    run_batch("mft", [src], out)

    # Same path, different content: a different piece of evidence.
    _good_mft(src, n=5, tag=b"different")
    result = run_batch("mft", [src], out)

    assert len(result.outcomes) == 1
    outcome = result.outcomes[0]
    assert outcome.status == "failed"
    assert "different source" in outcome.detail


def test_refusal_names_both_digests(tmp_path):
    src = _good_mft(tmp_path / "SYSTEM")
    out = tmp_path / "out"
    run_batch("mft", [src], out)
    _good_mft(src, n=5, tag=b"different")
    outcome = run_batch("mft", [src], out).outcomes[0]
    assert "..." in outcome.detail
    # Two distinct digests are quoted.
    assert outcome.detail.count("...") >= 2


def test_rerunning_the_same_sources_is_idempotent(tmp_path):
    """The same batch over the same evidence must be safe to repeat."""
    src = _good_mft(tmp_path / "SYSTEM")
    out = tmp_path / "out"
    first = run_batch("mft", [src], out)
    digest_first = json.loads(Path(first.outcomes[0].output).read_text())

    second = run_batch("mft", [src], out)
    digest_second = json.loads(Path(second.outcomes[0].output).read_text())

    assert first.outcomes[0].status == "ok"
    assert second.outcomes[0].status == "ok"
    assert digest_first == digest_second


def test_refuses_to_overwrite_a_non_export_file(tmp_path):
    out_file = tmp_path / "0000_SYSTEM.json"
    out_file.write_text("not json at all")
    src = _good_mft(tmp_path / "SYSTEM")
    outcome = run_batch("mft", [src], tmp_path).outcomes[0]
    assert outcome.status == "failed"
    assert "not a readable adapter export" in outcome.detail


def test_refuses_to_overwrite_an_export_without_a_digest(tmp_path):
    out_file = tmp_path / "0000_SYSTEM.json"
    out_file.write_text(json.dumps({"records": []}))
    src = _good_mft(tmp_path / "SYSTEM")
    outcome = run_batch("mft", [src], tmp_path).outcomes[0]
    assert outcome.status == "failed"
    assert "no source digest" in outcome.detail


def test_guard_helper_allows_a_matching_digest(tmp_path):
    target = tmp_path / "x.json"
    target.write_text(json.dumps({
        "provenance": {"sources": [{"sha256": "abc"}]}
    }))
    assert_output_matches_source(target, "abc")  # no raise
    with pytest.raises(BatchError):
        assert_output_matches_source(target, "def")


def test_guard_refuses_when_new_source_cannot_be_digested(tmp_path):
    target = tmp_path / "x.json"
    target.write_text(json.dumps({"provenance": {"sources": [{"sha256": "abc"}]}}))
    with pytest.raises(BatchError, match="could not be digested"):
        assert_output_matches_source(target, None)


# ---------------------------------------------------------------------------
# Invariant: one failure cannot contaminate another
# ---------------------------------------------------------------------------

def test_corrupt_input_does_not_stop_the_batch(tmp_path):
    good = [_good_mft(tmp_path / f"good{i}.mft") for i in range(3)]
    bad = tmp_path / "corrupt.mft"
    bad.write_bytes(b"GARBAGE" * 300)

    result = run_batch("mft", [*good, bad], tmp_path / "out")
    statuses = {Path(o.source).name: o.status for o in result.outcomes}
    assert statuses["corrupt.mft"] == "partial"
    for i in range(3):
        assert statuses[f"good{i}.mft"] == "ok"


def test_empty_input_is_not_reported_as_success(tmp_path):
    """Regression: an empty file yielded zero records and status 'ok'."""
    empty = tmp_path / "empty.mft"
    empty.write_bytes(b"")
    good = _good_mft(tmp_path / "good.mft")

    result = run_batch("mft", [empty, good], tmp_path / "out")
    statuses = {Path(o.source).name: o.status for o in result.outcomes}
    assert statuses["empty.mft"] == "failed"
    assert "empty" in next(o.detail for o in result.outcomes
                           if Path(o.source).name == "empty.mft")
    assert statuses["good.mft"] == "ok"


def test_missing_input_is_recorded_not_dropped(tmp_path):
    good = _good_mft(tmp_path / "good.mft")
    result = run_batch("mft", [good, tmp_path / "does-not-exist"], tmp_path / "out")
    statuses = {Path(o.source).name: o.status for o in result.outcomes}
    assert statuses["does-not-exist"] == "failed"


def test_an_adapter_exception_is_contained(tmp_path):
    """A raising adapter must fail only its own input."""
    from siberian.batch import BatchAdapter

    calls = []

    def exploding(source, limits):
        calls.append(source)
        if Path(source).name == "boom":
            raise RuntimeError("adapter exploded")
        payload, status, detail, stats = _mft_run_ok(Path(source))
        return payload, status, detail, stats

    from siberian.batch import _mft_run

    def _mft_run_ok(source):
        return _mft_run(source, BatchLimits())

    original = ADAPTERS["mft"]
    ADAPTERS["mft"] = BatchAdapter("mft", original.spec, exploding)
    try:
        boom = _good_mft(tmp_path / "boom")
        fine = _good_mft(tmp_path / "fine")
        result = run_batch("mft", [boom, fine], tmp_path / "out")
        statuses = {Path(o.source).name: o.status for o in result.outcomes}
        assert statuses["boom"] == "failed"
        assert "adapter exploded" in next(
            o.detail for o in result.outcomes if Path(o.source).name == "boom"
        )
        assert statuses["fine"] == "ok"
    finally:
        ADAPTERS["mft"] = original


def test_unknown_adapter_is_rejected():
    with pytest.raises(BatchError, match="Unknown adapter"):
        get_adapter("nope")


def test_all_registered_adapters_are_documented():
    assert set(ADAPTERS) == {"mft", "prefetch", "amcache", "shimcache", "shellbags"}
    for name, adapter in ADAPTERS.items():
        assert adapter.spec.name.startswith("siberian."), name
        assert adapter.spec.transformations, name
        assert adapter.spec.limitations, name


# ---------------------------------------------------------------------------
# Invariant: limits are respected AND disclosed
# ---------------------------------------------------------------------------

def test_max_inputs_is_enforced_and_the_remainder_reported(tmp_path):
    sources = [_pf(tmp_path / f"E{i}.EXE-{i:08X}.pf", i) for i in range(10)]
    result = run_batch(
        "prefetch", sources, tmp_path / "out",
        limits=BatchLimits(max_inputs=4),
    )
    assert result.inputs_available == 10
    assert len(result.outcomes) == 4
    assert result.inputs_skipped_by_limit == 6
    assert len(list((tmp_path / "out").glob("0*.json"))) == 4


def test_max_items_per_input_is_forwarded(tmp_path):
    sources = [_pf(tmp_path / f"E{i}.EXE-{i:08X}.pf", i) for i in range(3)]
    result = run_batch(
        "prefetch", sources, tmp_path / "out",
        limits=BatchLimits(max_items_per_input=1),
    )
    for outcome in result.outcomes:
        # The limit is per input and these inputs are single files, so one whole
        # artifact is processed either way. What matters is that the limit was
        # forwarded and the accounting reflects it.
        assert outcome.output is not None
        payload = json.loads(Path(outcome.output).read_text())
        assert len(payload["records"]) == 1
        stats = payload["provenance"]["run"]["stats"]
        assert stats["max_files"] == 1


def test_max_items_per_input_truncates_a_multi_item_artifact(tmp_path):
    """The per-input limit binds on artifacts holding many items, e.g. a $MFT.

    Directory inputs are expanded into one artifact per output, so for Prefetch
    (one artifact == one record) the limit never binds. For MFT it does, and the
    remainder must be disclosed rather than silently dropped.
    """
    from siberian.mft_parser import parse_mft_file

    src = _good_mft(tmp_path / "MFT", n=20)
    result = run_batch(
        "mft", [src], tmp_path / "out",
        limits=BatchLimits(max_items_per_input=5),
    )
    outcome = result.outcomes[0]
    payload = json.loads(Path(outcome.output).read_text())
    run = payload["provenance"]["run"]
    assert len(payload["records"]) == 5
    assert run["available"] == 20
    assert run["processed"] == 5
    assert run["truncated"] == 15
    assert run["max_records"] == 5
    # Truncation makes the input partial, not a clean success.
    assert outcome.status == "partial"
    assert "not parsed (limit)" in outcome.detail


def test_limits_are_recorded_in_the_manifest(tmp_path):
    source = _pf(tmp_path / "A.EXE-00000000.pf")
    result = run_batch(
        "prefetch", [source], tmp_path / "out",
        limits=BatchLimits(max_inputs=5, max_items_per_input=2, min_inputs=1),
    )
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["limits"] == {
        "max_inputs": 5, "max_items_per_input": 2, "min_inputs": 1
    }


def test_min_inputs_refuses_a_suspiciously_small_batch(tmp_path):
    """Guards a mistyped path silently producing a one-item 'batch'."""
    one = _pf(tmp_path / "A.EXE-00000000.pf")
    with pytest.raises(BatchError, match="min_inputs"):
        run_batch("prefetch", [one], tmp_path / "out", limits=BatchLimits(min_inputs=5))


def test_min_inputs_refusal_creates_nothing(tmp_path):
    one = _pf(tmp_path / "A.EXE-00000000.pf")
    out = tmp_path / "out"
    with pytest.raises(BatchError):
        run_batch("prefetch", [one], out, limits=BatchLimits(min_inputs=5))
    assert not out.exists() or not list(out.glob("*.json"))


def test_zero_max_inputs_means_no_limit(tmp_path):
    sources = [_pf(tmp_path / f"E{i}.EXE-{i:08X}.pf", i) for i in range(4)]
    result = run_batch(
        "prefetch", sources, tmp_path / "out", limits=BatchLimits(max_inputs=0)
    )
    assert len(result.outcomes) == 4
    assert result.inputs_skipped_by_limit == 0


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def test_discovery_is_sorted_and_deduplicated(tmp_path):
    for name in ("c.pf", "a.pf", "b.pf"):
        _pf(tmp_path / name)
    found = discover_inputs([tmp_path], "*.pf")
    assert [p.name for p in found] == ["a.pf", "b.pf", "c.pf"]
    # Passing the same directory twice must not double the work.
    assert len(discover_inputs([tmp_path, tmp_path], "*.pf")) == 3


def test_discovery_honours_the_pattern(tmp_path):
    _pf(tmp_path / "a.pf")
    _pf(tmp_path / "b.txt")
    assert len(discover_inputs([tmp_path], "*.pf")) == 1


def test_discovery_recursion_is_opt_in(tmp_path):
    nested = tmp_path / "sub" / "deep"
    nested.mkdir(parents=True)
    _pf(nested / "x.pf")
    _pf(tmp_path / "y.pf")
    assert len(discover_inputs([tmp_path], "*.pf")) == 1
    assert len(discover_inputs([tmp_path], "*.pf", recursive=True)) == 2


def test_discovery_accepts_explicit_files(tmp_path):
    f = _pf(tmp_path / "a.pf")
    assert discover_inputs([f], "*.pf") == [f]


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def test_manifest_accounts_for_every_input(tmp_path):
    sources = [_good_mft(tmp_path / f"m{i}.mft") for i in range(3)]
    result = run_batch("mft", sources, tmp_path / "out")
    manifest = json.loads(Path(result.manifest_path).read_text())
    assert manifest["inputs_processed"] == 3
    assert manifest["inputs_available"] == 3
    assert manifest["summary"]["ok"] == 3
    assert len(manifest["inputs"]) == 3
    assert manifest["batch_version"]
    assert manifest["provenance_version"]


def test_manifest_records_each_source_digest(tmp_path):
    sources = [_good_mft(tmp_path / f"m{i}.mft") for i in range(2)]
    result = run_batch("mft", sources, tmp_path / "out")
    manifest = json.loads(Path(result.manifest_path).read_text())
    digests = {i["source_digest"] for i in manifest["inputs"]}
    assert all(d and len(d) == 64 for d in digests)


def test_each_output_carries_its_own_provenance(tmp_path):
    sources = [_good_mft(tmp_path / f"m{i}.mft", n=i + 1) for i in range(3)]
    result = run_batch("mft", sources, tmp_path / "out")
    for outcome in result.outcomes:
        payload = json.loads(Path(outcome.output).read_text())
        prov = payload["provenance"]
        assert prov["parser"]["name"] == "siberian.mft_parser"
        assert prov["sources"][0]["sha256"] == outcome.source_digest


def test_manifest_is_deterministic(tmp_path):
    sources = [_good_mft(tmp_path / f"m{i}.mft") for i in range(3)]
    first = run_batch("mft", sources, tmp_path / "o1").to_dict()
    second = run_batch("mft", sources, tmp_path / "o2").to_dict()
    # Only the output paths differ, because the directories differ.
    for payload in (first, second):
        for entry in payload["inputs"]:
            entry.pop("output")
    assert first == second


# ---------------------------------------------------------------------------
# Result accounting and reporting
# ---------------------------------------------------------------------------

def test_ok_property_requires_every_input_clean(tmp_path):
    good = [_good_mft(tmp_path / f"m{i}.mft") for i in range(2)]
    assert run_batch("mft", good, tmp_path / "o1").ok is True

    bad = tmp_path / "bad.mft"
    bad.write_bytes(b"NOPE" * 400)
    result = run_batch("mft", [*good, bad], tmp_path / "o2")
    assert result.ok is False
    assert result.partial >= 1


def test_counts_add_up(tmp_path):
    good = _good_mft(tmp_path / "good.mft")
    bad = tmp_path / "bad.mft"
    bad.write_bytes(b"NOPE" * 400)
    empty = tmp_path / "empty.mft"
    empty.write_bytes(b"")
    result = run_batch("mft", [good, bad, empty], tmp_path / "out")
    summary = result.to_dict()["summary"]
    assert summary["ok"] + summary["partial"] + summary["failed"] == len(result.outcomes)


def test_report_lists_problems_before_clean_inputs(tmp_path):
    good = [_good_mft(tmp_path / f"m{i}.mft") for i in range(5)]
    bad = tmp_path / "bad.mft"
    bad.write_bytes(b"NOPE" * 400)
    report = format_batch_report(run_batch("mft", [*good, bad], tmp_path / "out"))
    lines = [l.strip() for l in report.splitlines() if l.strip().startswith("[")]
    assert lines[0].startswith("[PARTIAL") or lines[0].startswith("[FAILED")


def test_report_is_capped_and_says_so(tmp_path):
    sources = [_good_mft(tmp_path / f"m{i}.mft") for i in range(30)]
    report = format_batch_report(run_batch("mft", sources, tmp_path / "out"), max_report=5)
    listed = [l.strip() for l in report.splitlines() if l.strip().startswith("[")]
    assert len(listed) == 5
    assert "more input(s) listed in the manifest" in report


def test_report_cap_cannot_hide_problems(tmp_path):
    """Failures are shown first, so a small cap cannot bury them."""
    bad = []
    for i in range(6):
        p = tmp_path / f"bad{i}.mft"
        p.write_bytes(b"NOPE" * 400)
        bad.append(p)
    good = [_good_mft(tmp_path / f"m{i}.mft") for i in range(6)]
    report = format_batch_report(
        run_batch("mft", [*bad, *good], tmp_path / "out"), max_report=3
    )
    listed = [l.strip() for l in report.splitlines() if l.strip().startswith("[")]
    problems = [l for l in listed if "PARTIAL" in l or "FAILED" in l]
    assert len(problems) == 3, "the cap must be spent on problems first"
