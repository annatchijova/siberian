"""Tests for the artifact validation harness.

This is the handoff to whoever brings up the Windows VM. It is the one piece of
infrastructure whose correctness is checked only once, at the end, when a real
artifact exists -- so it has to be tested against artifacts that CAN be produced
here, and its failure modes have to be exercised deliberately.

The harness silently produced a report claiming verification had failed on its
first run, because a non-recursive glob found no documents and the verifier was
then invoked with no arguments. These tests cover that class of bug.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "lab"))

import validate_artifacts as va  # noqa: E402


def _mft(path: Path, n: int = 2) -> Path:
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 16, 1)
    struct.pack_into("<H", rec, 18, 1)
    struct.pack_into("<H", rec, 20, 56)
    struct.pack_into("<I", rec, 24, 1024)
    struct.pack_into("<I", rec, 28, 1024)
    path.write_bytes(bytes(rec) * n)
    return path


def _pf(path: Path, seed: int = 0) -> Path:
    path.write_bytes(b"MAM\x04" + bytes([seed % 256]) * 300)
    return path


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def test_discovers_named_artifacts(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(b"x")
    (tmp_path / "SYSTEM").write_bytes(b"x")
    (tmp_path / "NTUSER.DAT").write_bytes(b"x")
    found = va.discover(tmp_path)
    assert [p.name for p in found["amcache"]] == ["Amcache.hve"]
    assert [p.name for p in found["shimcache"]] == ["SYSTEM"]
    assert [p.name for p in found["shellbags"]] == ["NTUSER.DAT"]


def test_discovers_mft_by_name_and_suffix(tmp_path):
    (tmp_path / "$MFT").write_bytes(b"x")
    (tmp_path / "other.mft").write_bytes(b"x")
    found = va.discover(tmp_path)
    assert sorted(p.name for p in found["mft"]) == ["$MFT", "other.mft"]


def test_discovers_prefetch_directory(tmp_path):
    d = tmp_path / "Prefetch"
    d.mkdir()
    _pf(d / "A.EXE-00000000.pf")
    _pf(d / "B.EXE-00000000.pf")
    found = va.discover(tmp_path)
    assert len(found["prefetch"]) == 2


def test_discovery_is_case_insensitive(tmp_path):
    (tmp_path / "system").write_bytes(b"x")
    assert len(va.discover(tmp_path)["shimcache"]) == 1


def test_discovery_of_missing_directory_is_empty(tmp_path):
    found = va.discover(tmp_path / "absent")
    assert all(v == [] for v in found.values())


# ---------------------------------------------------------------------------
# Running and independent verification
# ---------------------------------------------------------------------------

def test_run_export_produces_a_sealed_output(tmp_path):
    from siberian.export_seal import is_sealed

    src = _mft(tmp_path / "MFT")
    run = va.run_export("mft", src, tmp_path / "out")
    assert run["status"] == "ok"
    outputs = [o for o in run["outcomes"] if o["output"]]
    assert outputs
    for outcome in outputs:
        assert is_sealed(json.loads(Path(outcome["output"]).read_text()))
        assert outcome["source_digest"]


def test_independent_verify_walks_subdirectories(tmp_path):
    """Regression: a non-recursive glob found nothing, the verifier was invoked
    with no arguments, produced no JSON, and the report claimed verification had
    failed. Exports live in per-adapter subdirectories."""
    mft = _mft(tmp_path / "MFT")
    pf = _pf(tmp_path / "A.EXE-00000000.pf")
    # Two adapters, so the exports land in two different subdirectories.
    va.run_export("mft", mft, tmp_path / "out" / "mft")
    va.run_export("prefetch", pf, tmp_path / "out" / "prefetch")

    nested = sorted((tmp_path / "out").rglob("*.json"))
    assert len({p.parent.name for p in nested}) == 2, (
        "the fixtures must span two subdirectories or this proves nothing"
    )

    result = va.independent_verify(tmp_path / "out")
    assert "error" not in result, result
    assert result["siberian_importable"] is False, (
        "the verification workspace must not be able to import siberian"
    )
    verified = [d for d in result["documents"] if d["verified"]]
    assert len(verified) == len(nested), (
        f"only {len(verified)}/{len(nested)} nested exports were verified"
    )


def test_non_export_json_in_the_tree_is_reported_not_hidden(tmp_path):
    """A stray JSON in the output tree must surface as unverified.

    The harness must never quietly drop a document it could not verify.
    """
    mft = _mft(tmp_path / "MFT")
    va.run_export("mft", mft, tmp_path / "out" / "mft")
    (tmp_path / "out" / "notes").mkdir(parents=True, exist_ok=True)
    (tmp_path / "out" / "notes" / "scratch.json").write_text("{}")

    result = va.independent_verify(tmp_path / "out")
    unverified = [d for d in result["documents"] if not d["verified"]]
    assert len(unverified) == 1
    assert "scratch.json" in unverified[0]["path"]
    assert "V1" in unverified[0]["failed_checks"]


def test_independent_verify_reports_an_empty_run_clearly(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    result = va.independent_verify(out)
    assert "no sealed documents" in result.get("error", "")


def test_independent_verify_detects_tampering(tmp_path):
    """A modified export must be reported as unverified, not silently passed."""
    src = _pf(tmp_path / "A.EXE-00000000.pf")
    va.run_export("prefetch", src, tmp_path / "out" / "prefetch")

    # Tamper with one sealed export.
    exports = sorted((tmp_path / "out" / "prefetch").glob("0*.json"))
    assert exports
    payload = json.loads(exports[0].read_text())
    payload["records"][0]["run_count"] = 4242
    exports[0].write_text(json.dumps(payload, indent=2))

    result = va.independent_verify(tmp_path / "out")
    assert "error" not in result
    assert any(not d["verified"] for d in result["documents"]), (
        "tampering with an export must fail independent verification"
    )


def test_tampered_manifest_is_detected(tmp_path):
    src = _mft(tmp_path / "MFT")
    va.run_export("mft", src, tmp_path / "out" / "mft")
    manifest = next((tmp_path / "out" / "mft").glob("batch-manifest.json"))
    payload = json.loads(manifest.read_text())
    payload["inputs_available"] = 999
    manifest.write_text(json.dumps(payload, indent=2))

    result = va.independent_verify(tmp_path / "out")
    assert any(not d["verified"] for d in result["documents"])


# ---------------------------------------------------------------------------
# The report must not overstate
# ---------------------------------------------------------------------------

def test_report_states_it_does_not_establish_correctness(tmp_path):
    report = va.build_report(tmp_path, [], {"error": "not run"})
    assert "does not establish that any parse is correct" in report
    assert "verified export is not a correct export" in report


def test_report_lists_what_remains_open(tmp_path):
    report = va.build_report(tmp_path, [], {"error": "not run"})
    for topic in ("Correctness of each parse", "Prefetch SCCA",
                  "Level 1 catalog applicability", "Level 4 calibration"):
        assert topic in report, topic


def test_report_records_the_independence_result(tmp_path):
    report = va.build_report(tmp_path, [], {
        "siberian_importable": False, "exit_code": 0, "documents": [],
    })
    assert "independence confirmed" in report

    report_bad = va.build_report(tmp_path, [], {
        "siberian_importable": True, "exit_code": 0, "documents": [],
    })
    assert "invalidates the independence claim" in report_bad


def test_report_includes_source_digests(tmp_path):
    src = _mft(tmp_path / "MFT")
    run = va.run_export("mft", src, tmp_path / "out")
    report = va.build_report(tmp_path, [run], {"error": "not run"})
    assert "sha256:" in report


def test_report_records_adapter_outcomes_and_detail(tmp_path):
    bad = tmp_path / "empty.mft"
    bad.write_bytes(b"")
    run = va.run_export("mft", bad, tmp_path / "out")
    report = va.build_report(tmp_path, [run], {"error": "not run"})
    assert "failed" in report or "partial" in report
    assert "empty" in report


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------

def test_end_to_end_run(tmp_path, capsys):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _mft(artifacts / "$MFT")
    _pf(artifacts / "A.EXE-00000000.pf")
    out = tmp_path / "out"

    code = va.main(["--artifacts", str(artifacts), "--out", str(out),
                    "--only", "mft", "--only", "prefetch"])
    assert code == 0

    report = (out / "VALIDATION_REPORT.md").read_text()
    assert "does not establish that any parse is correct" in report
    assert "independence confirmed" in report
    # A per-input export and a manifest must both exist.
    assert list(out.rglob("*.json"))


def test_end_to_end_with_no_artifacts_is_honest(tmp_path):
    artifacts = tmp_path / "empty"
    artifacts.mkdir()
    out = tmp_path / "out"
    code = va.main(["--artifacts", str(artifacts), "--out", str(out)])
    assert code == 0
    report = (out / "VALIDATION_REPORT.md").read_text()
    assert "No recognised artifact was found" in report
    assert "Nothing was validated" in report


def test_harness_documents_what_it_needs(tmp_path):
    """The harness must say which artifacts it looks for, for the VM operator."""
    text = (REPO_ROOT / "lab" / "validate_artifacts.py").read_text()
    for artifact in ("Amcache.hve", "SYSTEM", "NTUSER.DAT", "$MFT", "Prefetch"):
        assert artifact in text, artifact
