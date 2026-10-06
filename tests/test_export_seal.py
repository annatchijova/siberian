"""Tests for export sealing and the independent verifier.

Level 6 requires that "an analyst can compare and verify the exported bundle
without using SIBERIAN". Two things are tested here:

1. Sealing produces digests that a third party can re-derive.
2. The shipped verifier genuinely does not depend on SIBERIAN. That is proven by
   running it in a subprocess whose environment cannot import the package, not
   by reading its imports and believing them.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from siberian.export_seal import (
    EXPORT_KIND,
    EXPORT_SEAL_VERSION,
    MANIFEST_KIND,
    is_sealed,
    seal_export,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "forensics" / "verify_siberian.py"


def _payload(n: int = 3) -> dict:
    return {
        "provenance": {
            "provenance_version": "1",
            "parser": {
                "name": "siberian.mft_parser",
                "version": "2",
                "determinism_level": "deterministic",
            },
            "transformations": ["applied fixups"],
            "limitations": ["validated only against synthetic records"],
            "sources": [{"path": "/tmp/x", "sha256": "a" * 64}],
        },
        "records": [{"record_number": i, "is_valid": True} for i in range(n)],
    }


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------

def test_seal_adds_envelope_and_integrity():
    sealed = seal_export(_payload())
    assert sealed["kind"] == EXPORT_KIND
    assert sealed["export_version"] == EXPORT_SEAL_VERSION
    assert sealed["canonicalize_version"] == "2"
    assert is_sealed(sealed)


def test_seal_does_not_mutate_the_input():
    original = _payload()
    before = json.dumps(original, sort_keys=True)
    seal_export(original)
    assert json.dumps(original, sort_keys=True) == before


def test_seal_is_deterministic():
    assert seal_export(_payload()) == seal_export(_payload())


def test_sealing_twice_is_idempotent():
    once = seal_export(_payload())
    assert seal_export(once) == once


def test_seal_replaces_a_stale_integrity_block():
    payload = _payload()
    payload["integrity"] = {"provenance_hash": "stale", "payload_hash": "stale",
                            "export_hash": "stale"}
    sealed = seal_export(payload)
    assert sealed["integrity"]["export_hash"] != "stale"
    assert is_sealed(sealed)


def test_manifest_kind_is_sealable():
    sealed = seal_export({"inputs": [], "summary": {"ok": 0}}, kind=MANIFEST_KIND)
    assert sealed["kind"] == MANIFEST_KIND
    assert is_sealed(sealed)


def test_unsealed_document_is_not_reported_as_sealed():
    assert is_sealed({"records": []}) is False
    assert is_sealed({"integrity": {}}) is False
    assert is_sealed({"integrity": {"provenance_hash": "x"}}) is False


# ---------------------------------------------------------------------------
# Independence of the verifier
# ---------------------------------------------------------------------------

def test_verifier_exists_and_is_a_single_file():
    assert VERIFIER.is_file()
    assert VERIFIER.stat().st_size > 0


def test_verifier_imports_nothing_from_siberian():
    """Static check. The subprocess tests below are the real proof."""
    text = VERIFIER.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            assert "siberian" not in stripped, f"verifier imports siberian: {line}"


def _run_verifier(workspace: Path, *args: str) -> subprocess.CompletedProcess:
    """Run the verifier with the siberian package provably unimportable.

    The subprocess runs in `workspace`, which contains only the verifier and the
    documents under test. `PYTHONPATH` is emptied so the repo cannot leak in,
    and the package's own location is not on sys.path.
    """
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(workspace),
        # Empty PYTHONPATH: nothing from the repo is reachable.
        "PYTHONPATH": "",
        "PYTHONNOUSERSITE": "1",
    }
    return subprocess.run(
        [sys.executable, str(VERIFIER), *args],
        cwd=workspace,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_siberian_is_not_importable_in_the_verifier_workspace(tmp_path):
    """Precondition for the independence tests. If this fails they prove nothing."""
    workspace = tmp_path / "elsewhere"
    workspace.mkdir()
    result = subprocess.run(
        [sys.executable, "-c", "import siberian"],
        cwd=workspace, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(workspace), "PYTHONPATH": ""},
    )
    assert result.returncode != 0, "siberian must NOT be importable here"


def test_verifier_runs_with_siberian_absent(tmp_path):
    workspace = tmp_path / "elsewhere"
    workspace.mkdir()
    doc = workspace / "export.json"
    doc.write_text(json.dumps(seal_export(_payload())), encoding="utf-8")

    result = _run_verifier(workspace, "export.json", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout[result.stdout.index("{"):])
    assert payload["documents"][0]["verified"] is True


def test_verifier_only_needs_the_one_file(tmp_path):
    """Copy the verifier alone into an empty directory and use it there."""
    workspace = tmp_path / "standalone"
    workspace.mkdir()
    copied = workspace / "verify_siberian.py"
    shutil.copy2(VERIFIER, copied)
    doc = workspace / "export.json"
    doc.write_text(json.dumps(seal_export(_payload())), encoding="utf-8")

    env = {"PATH": "/usr/bin:/bin", "HOME": str(workspace), "PYTHONPATH": ""}
    result = subprocess.run(
        [sys.executable, "verify_siberian.py", "export.json"],
        cwd=workspace, capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "VERIFIED" in result.stdout


# ---------------------------------------------------------------------------
# Tamper detection, exercised through the standalone verifier
# ---------------------------------------------------------------------------

def _verify(workspace: Path, document: dict, *extra: str):
    path = workspace / "doc.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return _run_verifier(workspace, "doc.json", "--json", *extra)


def _failed_codes(result: subprocess.CompletedProcess) -> list:
    payload = json.loads(result.stdout[result.stdout.index("{"):])
    return [c["code"] for c in payload["documents"][0]["checks"] if not c["passed"]]


def test_untampered_export_verifies(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    assert _verify(workspace, seal_export(_payload())).returncode == 0


def test_modified_record_is_detected(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["records"][0]["record_number"] = 999
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V4" in _failed_codes(result)


def test_modified_provenance_is_detected(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["provenance"]["parser"]["version"] = "99"
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V3" in _failed_codes(result)


def test_modified_parser_name_is_detected(tmp_path):
    """The provenance claim itself is bound, not just the records."""
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["provenance"]["parser"]["name"] = "some.other.parser"
    assert "V3" in _failed_codes(_verify(workspace, doc))


def test_modified_integrity_block_is_detected(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["integrity"]["export_hash"] = "0" * 64
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V5" in _failed_codes(result)


def test_removed_limitations_are_detected(tmp_path):
    """Dropping the caveats changes the provenance, so it breaks the seal."""
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["provenance"]["limitations"] = []
    assert "V3" in _failed_codes(_verify(workspace, doc))


def test_unsealed_document_is_rejected_and_explained(tmp_path):
    """An unsealed export must be named as such, not sent to another verifier.

    A raw export carries no envelope, so the kind check is what rejects it. The
    message has to say "unsealed", because telling an analyst to use a different
    verifier for their own unsealed file would send them down the wrong path.
    """
    workspace = tmp_path / "w"
    workspace.mkdir()
    result = _verify(workspace, _payload())
    assert result.returncode == 1
    assert "UNSEALED" in result.stdout
    assert "never sealed" in result.stdout or "UNSEALED" in result.stdout


def test_integrity_stripped_from_a_sealed_export_fails_v2(tmp_path):
    """Removing only the integrity block leaves the envelope, so V2 is reached."""
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    del doc["integrity"]
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V2" in _failed_codes(result)
    assert "never sealed" in result.stdout


def test_incomplete_integrity_block_is_rejected(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    del doc["integrity"]["payload_hash"]
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V2" in _failed_codes(result)


def test_wrong_document_kind_points_to_the_right_verifier(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    bundle = {
        "bundle_id": "x", "schema_version": "siberian-evidence-matrix-v1",
        "records": [], "context": {}, "catalog_version": "v3",
    }
    result = _verify(workspace, bundle)
    assert result.returncode == 1
    assert "siberian/verify.py" in result.stdout


def test_unknown_export_version_is_rejected(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["export_version"] = "99"
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V1" in _failed_codes(result)


def test_unsupported_canonicalize_version_is_rejected(tmp_path):
    """A verifier must refuse a hash protocol it does not implement."""
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    doc["canonicalize_version"] = "99"
    result = _verify(workspace, doc)
    assert result.returncode == 1
    assert "V1" in _failed_codes(result)


def test_malformed_json_exits_two(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    (workspace / "broken.json").write_text("not json", encoding="utf-8")
    result = _run_verifier(workspace, "broken.json")
    assert result.returncode == 2


def test_missing_file_exits_two(tmp_path):
    workspace = tmp_path / "w"
    workspace.mkdir()
    assert _run_verifier(workspace, "absent.json").returncode == 2


# ---------------------------------------------------------------------------
# Canonicalization agreement between producer and verifier
# ---------------------------------------------------------------------------

def test_key_order_does_not_affect_verification(tmp_path):
    """Order-independence is the point of a canonical form, not a miss.

    Reordering keys produces semantically identical JSON. It must still verify,
    otherwise the digest would depend on an incidental serialization detail.
    """
    workspace = tmp_path / "w"
    workspace.mkdir()
    doc = seal_export(_payload())
    record = doc["records"][0]
    doc["records"][0] = {k: record[k] for k in reversed(list(record))}
    assert _verify(workspace, doc).returncode == 0


def test_verifier_agrees_with_producer_on_a_real_export(tmp_path):
    """A genuine export produced by the CLI verifies without siberian present."""
    workspace = tmp_path / "w"
    workspace.mkdir()
    from siberian.batch import run_batch

    src = tmp_path / "A.EXE-00000000.pf"
    src.write_bytes(b"MAM\x04" + b"\x00" * 300)
    result = run_batch("prefetch", [src], workspace / "out")
    for produced in list((workspace / "out").glob("*.json")):
        shutil.copy2(produced, workspace / produced.name)

    outcome = _run_verifier(workspace, *[p.name for p in workspace.glob("*.json")],
                            "--json")
    assert outcome.returncode in (0, 1)  # a synthetic MAM is partial, not invalid
    payload = json.loads(outcome.stdout[outcome.stdout.index("{"):])
    for doc in payload["documents"]:
        failed = [c["code"] for c in doc["checks"] if not c["passed"]]
        assert not any(code.startswith(("V2", "V3", "V4", "V5")) for code in failed), (
            f"{doc['path']} failed an integrity check: {failed}"
        )
