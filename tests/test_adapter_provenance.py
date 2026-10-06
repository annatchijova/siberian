"""Tests for the shared adapter provenance record.

Level 6 completion requires that every adapter preserve the original source,
the parser version, and the transformations applied. Before this module no
adapter recorded a parser version or a transform list, so a JSON export could
not be interpreted later without knowing which code produced it.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from siberian.adapter_provenance import (
    AMCACHE_SPEC,
    MFT_SPEC,
    PLASO_SPEC,
    PREFETCH_SPEC,
    PROVENANCE_VERSION,
    SHELLBAGS_SPEC,
    SHIMCACHE_SPEC,
    build_provenance,
    count_files,
    sha256_bytes,
    sha256_file,
    sha256_tree,
    source_descriptor,
)

ALL_SPECS = (MFT_SPEC, PREFETCH_SPEC, AMCACHE_SPEC, SHIMCACHE_SPEC,
             SHELLBAGS_SPEC, PLASO_SPEC)


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec", ALL_SPECS, ids=lambda s: s.name)
def test_every_adapter_records_the_required_fields(spec, tmp_path):
    """source + parser version + transformations, per the Level 6 criteria."""
    src = tmp_path / "artifact.bin"
    src.write_bytes(b"evidence")
    record = build_provenance(spec, [src])

    assert record["provenance_version"] == PROVENANCE_VERSION
    assert record["parser"]["name"] == spec.name
    assert record["parser"]["version"], "a parser version is mandatory"
    assert record["parser"]["determinism_level"] in ("deterministic", "best_effort")
    assert record["transformations"], "transformations must be stated"
    assert record["limitations"], "limitations must travel with the data"
    assert record["sources"][0]["sha256"] == sha256_bytes(b"evidence")


@pytest.mark.parametrize("spec", ALL_SPECS, ids=lambda s: s.name)
def test_provenance_is_json_serialisable(spec, tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    assert json.loads(json.dumps(build_provenance(spec, [src])))


@pytest.mark.parametrize("spec", ALL_SPECS, ids=lambda s: s.name)
def test_parser_identity_is_unique(spec):
    """(name, version) identifies exactly one adapter.

    Versions are per-parser, so two adapters may both be at version 2; what
    must not happen is the same name appearing twice, which would make
    provenance ambiguous.
    """
    names = [s.name for s in ALL_SPECS]
    assert names.count(spec.name) == 1
    assert spec.version
    identities = [(s.name, s.version) for s in ALL_SPECS]
    assert len(set(identities)) == len(ALL_SPECS)


def test_spec_transformations_do_not_overlap():
    seen = set()
    for spec in ALL_SPECS:
        for t in spec.transformations:
            assert t not in seen, f"duplicate transformation text: {t}"
            seen.add(t)


# ---------------------------------------------------------------------------
# Honesty of the recorded claims
# ---------------------------------------------------------------------------

def test_heuristic_adapters_declare_best_effort():
    """An adapter that guesses or delegates must not claim determinism."""
    for spec in (PREFETCH_SPEC, SHIMCACHE_SPEC, SHELLBAGS_SPEC):
        assert spec.determinism_level == "best_effort", spec.name


def test_pure_decoders_claim_determinism():
    assert MFT_SPEC.determinism_level == "deterministic"
    assert AMCACHE_SPEC.determinism_level == "deterministic"


def test_unvalidated_adapters_say_so_in_their_limitations():
    """The audits' central finding is unvalidated evidence; it must persist."""
    for spec in (AMCACHE_SPEC, SHIMCACHE_SPEC, SHELLBAGS_SPEC, PREFETCH_SPEC):
        text = " ".join(spec.limitations).lower()
        assert any(
            phrase in text
            for phrase in ("no ", "unvalidated", "never run", "not decoded")
        ), f"{spec.name} limitations do not disclose the validation gap"


def test_adapters_that_drop_fields_say_so():
    """Fields removed during red-team must not quietly reappear as claims."""
    assert "not reported" in " ".join(SHELLBAGS_SPEC.limitations).lower()
    assert "not decoded" in " ".join(SHIMCACHE_SPEC.limitations).lower()


def test_optional_dependency_is_declared_where_required():
    assert MFT_SPEC.requires is None
    assert "python-registry" in AMCACHE_SPEC.requires
    assert "python-registry" in SHIMCACHE_SPEC.requires
    assert "python-registry" in SHELLBAGS_SPEC.requires
    assert "pyscca" in PREFETCH_SPEC.requires


# ---------------------------------------------------------------------------
# Source digests
# ---------------------------------------------------------------------------

def test_file_digest_matches_hashlib(tmp_path):
    import hashlib

    f = tmp_path / "x.bin"
    f.write_bytes(b"abc" * 1000)
    assert sha256_file(f) == hashlib.sha256(b"abc" * 1000).hexdigest()


def test_missing_file_digest_is_none_not_raised(tmp_path):
    assert sha256_file(tmp_path / "nope") is None


def test_source_descriptor_of_missing_path(tmp_path):
    d = source_descriptor(tmp_path / "nope")
    assert d["is_file"] is False and d["is_dir"] is False
    assert d["sha256"] is None


def test_directory_source_gets_a_tree_digest(tmp_path):
    """A directory of evidence must still carry a reproducible anchor."""
    (tmp_path / "a.pf").write_bytes(b"one")
    (tmp_path / "b.pf").write_bytes(b"two")
    d = source_descriptor(tmp_path)
    assert d["is_dir"] is True
    assert d["file_count"] == 2
    assert d["tree_sha256"]
    assert d["sha256"] is None


def test_tree_digest_is_deterministic(tmp_path):
    for name in ("c", "a", "b"):
        (tmp_path / f"{name}.pf").write_bytes(name.encode())
    assert sha256_tree(tmp_path) == sha256_tree(tmp_path)


def test_tree_digest_is_independent_of_creation_order(tmp_path):
    """Sorted manifest: the same content must digest the same regardless of order."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    for name in ("x", "y", "z"):
        (a / name).write_bytes(name.encode())
    for name in reversed(("x", "y", "z")):
        (b / name).write_bytes(name.encode())
    assert sha256_tree(a) == sha256_tree(b)


def test_tree_digest_changes_when_content_changes(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "one.pf").write_bytes(b"original")
    before = sha256_tree(d)
    (d / "one.pf").write_bytes(b"modified")
    assert sha256_tree(d) != before


def test_tree_digest_changes_when_a_file_is_added(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "one.pf").write_bytes(b"same")
    before = sha256_tree(d)
    (d / "two.pf").write_bytes(b"same")
    assert sha256_tree(d) != before


def test_tree_digest_of_empty_directory_is_stable(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    assert sha256_tree(d) == sha256_tree(d)
    assert count_files(d) == 0


def test_copy_of_a_directory_has_the_same_digest(tmp_path):
    """Paths in the manifest are relative, so a copy is the same evidence set."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "one.pf").write_bytes(b"alpha")
    (src / "two.pf").write_bytes(b"beta")
    dst = tmp_path / "dst"
    shutil.copytree(src, dst)
    assert sha256_tree(src) == sha256_tree(dst)


# ---------------------------------------------------------------------------
# Run facts
# ---------------------------------------------------------------------------

def test_extra_run_facts_are_carried(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    record = build_provenance(MFT_SPEC, [src], extra={"records_invalid": 3})
    assert record["run"]["records_invalid"] == 3


def test_run_absent_when_no_extra(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    assert "run" not in build_provenance(MFT_SPEC, [src])


def test_multiple_sources_are_all_described(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"a")
    b.write_bytes(b"b")
    record = build_provenance(PLASO_SPEC, [a, b])
    assert len(record["sources"]) == 2
    assert record["sources"][0]["sha256"] != record["sources"][1]["sha256"]


def test_provenance_is_reproducible_across_calls(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"stable")
    assert build_provenance(MFT_SPEC, [src]) == build_provenance(MFT_SPEC, [src])
