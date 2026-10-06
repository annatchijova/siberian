"""Consistency checks between the documentation and the code.

Documentation drifts silently: a parser count changes, a test count changes, and
the prose keeps asserting the old numbers. Two documents in this repository
already did -- TECHNICAL_README.md claimed "the CLI has no raw-evidence parser"
and "no rival-hypothesis comparison" after both had shipped, and PENDIENTES.md
still listed Levels 3, 5 and 6 as unimplemented.

These tests are deliberately narrow. They check claims that are cheap to state
and easy to falsify: counts, command lists, and the presence of capabilities the
documentation must not deny.

They do NOT check that prose is well written. A test cannot do that, and a test
that pretended to would be worse than no test.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
README_ES = REPO_ROOT / "README_ES.md"
TECHNICAL = REPO_ROOT / "TECHNICAL_README.md"
PENDING = REPO_ROOT / "PENDIENTES.md"

DOCS = (README, README_ES, TECHNICAL, PENDING)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _real_test_count() -> int:
    """Collect test count without running the suite.

    Counting collected items keeps this check cheap enough to run on every edit.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=180,
    )
    match = re.search(r"(\d+) tests? collected", result.stdout)
    if match:
        return int(match.group(1))
    match = re.search(r"(\d+) tests? collected", result.stderr)
    assert match, f"could not count tests:\n{result.stdout[-500:]}"
    return int(match.group(1))


def _subcommands() -> set:
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from siberian.cli import _build_parser

        return set(
            _build_parser()._subparsers._group_actions[0].choices.keys()
        )
    finally:
        sys.path.pop(0)


# ---------------------------------------------------------------------------
# Test counts
# ---------------------------------------------------------------------------

def test_readme_test_count_is_accurate():
    """A wrong test count is the most common way docs go stale."""
    real = _real_test_count()
    cited = {int(n) for n in re.findall(r"(\d+) (?:passing|unit tests pass)", _read(README))}
    assert cited, "README cites no test count at all"
    for number in cited:
        assert number == real, (
            f"README cites {number} tests but the suite collects {real}. "
            f"Update README.md."
        )


# ---------------------------------------------------------------------------
# Command coverage
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("doc", [README, README_ES], ids=lambda p: p.name)
def test_every_command_is_documented(doc):
    """Both entry points must list every subcommand.

    A command that exists but is undocumented is effectively absent.
    """
    text = _read(doc)
    missing = sorted(c for c in _subcommands() if c not in text)
    assert not missing, f"{doc.name} does not document: {', '.join(missing)}"


def test_standalone_verifier_is_documented():
    for doc in DOCS:
        if doc is PENDING:
            continue
        text = _read(doc)
        assert "verify_siberian.py" in text, (
            f"{doc.name} does not mention the standalone verifier"
        )


# ---------------------------------------------------------------------------
# The documentation must not deny shipped capabilities
#
# This is the check that would have caught the two false claims.
# ---------------------------------------------------------------------------

_DENIALS = [
    (r"CLI has no raw-evidence parser", "five artifact parsers ship"),
    (r"no raw-evidence parser", "five artifact parsers ship"),
    (r"no rival-hypothesis comparison", "rivals is implemented"),
    (r"dependency-free analysis library", "adapters need optional extras"),
]


@pytest.mark.parametrize("doc", [README, README_ES, TECHNICAL], ids=lambda p: p.name)
@pytest.mark.parametrize("pattern,capability", _DENIALS)
def test_docs_do_not_deny_shipped_capabilities(doc, pattern, capability):
    text = _read(doc)
    assert not re.search(pattern, text, re.IGNORECASE), (
        f"{doc.name} denies {capability}. Either the code is wrong or the "
        f"document is; re-check before editing either."
    )


def test_technical_readme_does_not_describe_a_prototype_state():
    """A technical document asserting the absence of a shipped feature is a
    false claim, not a conservative one."""
    text = _read(TECHNICAL)
    assert "import-mft" in text or "artifact adapters" in text.lower(), (
        "TECHNICAL_README.md must describe the artifact adapters it ships with"
    )


# ---------------------------------------------------------------------------
# Pending-work accuracy
# ---------------------------------------------------------------------------

def test_pending_does_not_list_completed_levels_as_pending():
    """Levels 3, 5 and the Level 6 deliverables are implemented."""
    text = _read(PENDING)
    for line in text.splitlines():
        if not re.match(r"^- \[ \] Nivel [356]", line):
            continue
        # A pending line is legitimate only if it names remaining scope, not the
        # capability itself.
        assert "Falta validar" not in line, (
            f"PENDIENTES.md marks as pending what is already built: {line}"
        )


def test_pending_separates_windows_system_from_artifact_samples():
    """The two blockers are different and were previously conflated.

    A parser needs a real artifact FILE, which can be copied off a volume. Only
    catalog validation, the calibration corpus and the PowerShell collector
    genuinely require a running Windows system.
    """
    text = _read(PENDING)
    assert "Requiere solo el archivo" in text, (
        "PENDIENTES.md must distinguish 'needs a live Windows' from 'needs the file'"
    )


def test_pending_links_every_red_team_audit():
    text = _read(PENDING)
    for audit in sorted((REPO_ROOT / "docs" / "red-team").glob("*.md")):
        assert audit.name in text, (
            f"PENDIENTES.md does not reference {audit.name}; the audit table "
            f"should be complete"
        )


# ---------------------------------------------------------------------------
# Cross-references resolve
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_in_docs_resolve(doc):
    """Every relative markdown link must point at something that exists."""
    text = _read(doc)
    broken = []
    for match in re.finditer(r"\]\((?!https?://|#)([^)]+)\)", text):
        target = match.group(1).split("#")[0]
        if not target:
            continue
        resolved = (doc.parent / target).resolve()
        if not resolved.exists():
            broken.append(target)
    assert not broken, f"{doc.name} links to missing files: {sorted(set(broken))}"


def test_readme_links_every_audit_and_verification_doc():
    text = _read(README)
    for name in ("NIVEL3_AUDIT.md", "NIVEL6_MFT_AUDIT.md", "NIVEL6_PREFETCH_AUDIT.md",
                 "NIVEL6_AMCACHE_AUDIT.md", "NIVEL6_SHIMCACHE_AUDIT.md",
                 "NIVEL6_SHELLBAGS_AUDIT.md", "NIVEL6_INFRA_AUDIT.md",
                 "EXPORT_VERIFICATION.md"):
        assert name in text, f"README does not link {name}"


def test_no_stray_backup_files_are_tracked():
    """Backups taken before patching must never enter the repository."""
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True,
    ).stdout.splitlines()
    strays = [f for f in tracked if f.endswith((".bak", ".orig", ".rej"))]
    assert not strays, f"backup files are tracked: {strays}"
