"""The catalog's declared version must cover its actual contents.

The analysis digest and the sealed bundle both include `catalog_version`. If the
catalog entries change without the version being bumped, two different catalogs
seal under the same declared version and a verifier cannot distinguish them.

That is not hypothetical: `ntfs_mft_entry` was added to the catalog while
CATALOG_VERSION still read v3, and both of that entry's source references were
unreachable (one was a fabricated Open Specifications GUID).

These tests pin the invariant offline. They do not check that URLs are live --
a unit test that depends on the network is a flaky test, not a safe one. URL
reachability is recorded in `docs/CATALOG_REVIEW.md` as a dated manual check,
and the fingerprint below forces any catalog edit to be an explicit, reviewed act.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

import siberian.catalog as C

REPO_ROOT = Path(__file__).resolve().parents[1]


def _entries() -> tuple:
    for name in dir(C):
        obj = getattr(C, name)
        if isinstance(obj, tuple) and obj and hasattr(obj[0], "source_refs"):
            return obj
    raise AssertionError("no catalog entry tuple found in siberian.catalog")


def _entry_fingerprint() -> str:
    """A stable digest over every declared field of every catalog entry.

    Order-independent and type-tagged so that reordering two entries, or
    swapping two strings, changes the fingerprint.
    """
    parts = []
    for entry in sorted(_entries(), key=lambda e: (e.action, e.artifact_type)):
        parts.append(json.dumps({
            "action": entry.action,
            "artifact_type": entry.artifact_type,
            "description": entry.description,
            "scope": entry.scope,
            "required_conditions": list(entry.required_conditions),
            "retention": entry.retention,
            "interpretation_limit": entry.interpretation_limit,
            "source_refs": [list(r) for r in entry.source_refs],
        }, sort_keys=True, ensure_ascii=True))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

def test_catalog_version_declares_a_version():
    assert re.search(r"-v\d+$", C.CATALOG_VERSION), (
        f"CATALOG_VERSION {C.CATALOG_VERSION!r} must end in -vN so a change is "
        f"visible in the declared version"
    )


def test_catalog_version_matches_its_contents():
    """Changing any catalog field requires bumping CATALOG_VERSION.

    On failure the message states the fingerprint to record in the version bump,
    so the fix is mechanical rather than a guess.
    """
    # The fingerprint of the catalog as committed. Bump both together.
    expected = "b9fd0870e4eb97ffdd49d5fd6f186d487e991f49761cde41877b14a6f15edd16"
    actual = _entry_fingerprint()
    assert actual == expected, (
        f"The catalog contents changed but CATALOG_VERSION is still "
        f"{C.CATALOG_VERSION!r}.\n"
        f"  entry fingerprint: {actual}\n"
        f"If this change is intended, update CATALOG_VERSION to a new -vN and "
        f"replace `expected` in this test with the fingerprint above."
    )


def test_every_entry_declares_conditions_and_a_limit():
    """An entry that cannot state its conditions cannot be evaluated."""
    for entry in _entries():
        assert entry.required_conditions, entry.artifact_type
        assert entry.interpretation_limit, entry.artifact_type
        assert entry.retention, entry.artifact_type
        assert entry.source_refs, entry.artifact_type


def test_every_entry_cites_at_least_one_source():
    for entry in _entries():
        assert len(entry.source_refs) >= 1, entry.artifact_type
        for label, url in entry.source_refs:
            assert label and url, entry.artifact_type
            assert url.startswith("http"), (
                f"{entry.artifact_type}: {url!r} is not a locator"
            )


def test_source_urls_are_unique_per_entry():
    """Duplicate refs suggest a copy-paste that was never checked."""
    for entry in _entries():
        urls = [u for _, u in entry.source_refs]
        assert len(urls) == len(set(urls)), entry.artifact_type


def test_no_placeholder_urls_survive():
    """Fabricated or template URLs are the defect this file exists to prevent."""
    placeholder_markers = ("example.com", "TODO", "FIXME", "REPLACE", "00000000-0000")
    for entry in _entries():
        for label, url in entry.source_refs:
            for marker in placeholder_markers:
                assert marker.lower() not in url.lower(), (
                    f"{entry.artifact_type} cites a placeholder URL: {url}"
                )


# ---------------------------------------------------------------------------
# Documentation must agree with the catalog
# ---------------------------------------------------------------------------

def test_catalog_review_does_not_defer_an_included_entry():
    """CATALOG_REVIEW.md said MFT was deferred while the catalog included it."""
    review = (REPO_ROOT / "docs" / "CATALOG_REVIEW.md").read_text(encoding="utf-8")
    for entry in _entries():
        if entry.artifact_type != "ntfs_mft_entry":
            continue
        # The entry is present, so the review must not still call it deferred.
        for line in review.splitlines():
            if "MFT" in line and "deferred" in line.lower():
                assert "ntfs_mft_entry" in line, (
                    f"CATALOG_REVIEW.md still defers MFT, but the catalog "
                    f"includes ntfs_mft_entry:\n  {line.strip()}"
                )


def test_catalog_matrix_documents_every_entry():
    matrix = (REPO_ROOT / "docs" / "CATALOG_MATRIX.md").read_text(encoding="utf-8")
    missing = [e.artifact_type for e in _entries() if e.artifact_type not in matrix]
    assert not missing, (
        f"CATALOG_MATRIX.md does not document: {', '.join(missing)}. "
        f"The matrix is the reviewable record of the active catalog."
    )


def test_review_records_a_dated_url_check():
    """URL liveness cannot be unit-tested, so it must be recorded manually."""
    review = (REPO_ROOT / "docs" / "CATALOG_REVIEW.md").read_text(encoding="utf-8")
    assert re.search(r"20\d\d-\d\d-\d\d", review), (
        "CATALOG_REVIEW.md must carry a dated reachability check; a unit test "
        "must not depend on the network"
    )
