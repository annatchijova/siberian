"""CLI-level tests for the Level 6 artifact parsers.

These exercise the command handlers, not just the parser functions.

Motivation: during the Amcache fix a handler was rewritten and shipped with a
typo (`args.amcache_hive` instead of `args.amcache_hve`). Every parser unit test
passed, because none of them invoked the handler. These tests call the handlers
with real argument namespaces so a handler that crashes on its own arguments
fails the suite instead of reaching an operator.

Exit-code contract under test:
  0  the requested artifact was read
  1  the artifact was read but the result is partial / degraded
  2  the command could not run at all
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from siberian import cli


def _ns(**kwargs):
    base = {
        "output": None,
        "summary": False,
        "max_entries": 0,
        "max_files": 0,
        "max_records": 0,
        "allow_partial": False,
        "bag_type": "BagMRU",
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# import-amcache
# ---------------------------------------------------------------------------

def test_amcache_missing_hive_exits_nonzero(tmp_path, capsys):
    """A hive that cannot be read must not exit 0."""
    rc = cli._cmd_import_amcache(
        _ns(amcache_hve=tmp_path / "missing.hve")
    )
    assert rc == 1
    assert "missing.hve" in capsys.readouterr().err


def test_amcache_missing_hive_allow_partial_exits_zero(tmp_path):
    rc = cli._cmd_import_amcache(
        _ns(amcache_hve=tmp_path / "missing.hve", allow_partial=True)
    )
    assert rc == 0


def test_amcache_non_hive_file_exits_nonzero(tmp_path, capsys):
    junk = tmp_path / "Amcache.hve"
    junk.write_bytes(b"definitely not a registry hive" * 50)
    rc = cli._cmd_import_amcache(_ns(amcache_hve=junk))
    assert rc == 1
    assert capsys.readouterr().err


def test_amcache_json_output_carries_errors(tmp_path):
    """The JSON must not present an empty result as a clean parse."""
    out = tmp_path / "out.json"
    rc = cli._cmd_import_amcache(
        _ns(amcache_hve=tmp_path / "missing.hve", output=out, allow_partial=True)
    )
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["entries"] == []
    assert payload["errors"], "errors must survive into the JSON output"
    assert "degraded" in payload


# ---------------------------------------------------------------------------
# import-prefetch
# ---------------------------------------------------------------------------

def test_prefetch_missing_target_exits_two(tmp_path, capsys):
    rc = cli._cmd_import_prefetch(_ns(target=tmp_path / "nope"))
    assert rc == 2


def test_prefetch_all_files_fail_exits_nonzero(tmp_path):
    """Every file failing is a total failure, not a clean run."""
    d = tmp_path / "pf"
    d.mkdir()
    (d / "A.EXE-00000000.pf").write_bytes(b"BAD!" + b"\x00" * 300)
    (d / "B.EXE-00000000.pf").write_bytes(b"NOPE" + b"\x00" * 300)
    rc = cli._cmd_import_prefetch(_ns(target=d))
    assert rc == 1


def test_prefetch_partial_acceptance_flag(tmp_path):
    d = tmp_path / "pf"
    d.mkdir()
    (d / "A.EXE-00000000.pf").write_bytes(b"BAD!" + b"\x00" * 300)
    rc = cli._cmd_import_prefetch(_ns(target=d, allow_partial=True))
    assert rc == 0


def test_prefetch_json_output(tmp_path):
    d = tmp_path / "pf"
    d.mkdir()
    (d / "A.EXE-00000000.pf").write_bytes(b"MAM\x04" + b"\x00" * 300)
    out = tmp_path / "pf.json"
    rc = cli._cmd_import_prefetch(_ns(target=d, output=out, allow_partial=True))
    assert rc == 0
    payload = json.loads(out.read_text())
    assert isinstance(payload, list)
    assert payload[0]["container"] == "MAM"
    assert len(payload[0]["file_sha256"]) == 64


# ---------------------------------------------------------------------------
# import-mft
# ---------------------------------------------------------------------------

def test_mft_missing_file_exits_nonzero(tmp_path, capsys):
    rc = cli._cmd_import_mft(_ns(mft_file=tmp_path / "missing.mft"))
    assert rc != 0
    assert capsys.readouterr().err


def test_mft_json_output(tmp_path):
    """Regression: this path raised AttributeError before MftRecord.to_dict."""
    import struct

    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 16, 1)
    struct.pack_into("<H", rec, 18, 1)
    struct.pack_into("<H", rec, 20, 56)
    struct.pack_into("<I", rec, 24, 1024)
    struct.pack_into("<I", rec, 28, 1024)
    mft = tmp_path / "MFT"
    mft.write_bytes(bytes(rec))

    out = tmp_path / "mft.json"
    rc = cli._cmd_import_mft(_ns(mft_file=mft, output=out))
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload[0]["is_valid"] is True


# ---------------------------------------------------------------------------
# import-shimcache / import-shellbags
# ---------------------------------------------------------------------------

def test_shimcache_missing_hive_exits_nonzero(tmp_path):
    rc = cli._cmd_import_shimcache(_ns(system_hive=tmp_path / "missing"))
    assert rc != 0


def test_shellbags_missing_hive_exits_nonzero(tmp_path):
    rc = cli._cmd_import_shellbags(_ns(hive_path=tmp_path / "missing"))
    assert rc != 0


# ---------------------------------------------------------------------------
# Argument contract
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "command,expect_case_file",
    [
        ("validate", True),
        ("analyze", True),
        ("explain", True),
        ("seal", True),
        ("verify", True),
        ("import-plaso", True),
        ("rivals", True),
        ("import-mft", False),
        ("import-prefetch", False),
        ("import-amcache", False),
        ("import-shimcache", False),
        ("import-shellbags", False),
    ],
)
def test_case_file_positional_only_where_consumed(command, expect_case_file):
    """Regression: every subcommand used to demand an unused `case_file`.

    The five artifact parsers each forced the operator to supply a meaningless
    extra positional argument.
    """
    parser = cli._build_parser()
    sub = parser._subparsers._group_actions[0].choices[command]
    positionals = [
        a.dest for a in sub._actions if not a.option_strings and a.dest != "help"
    ]
    assert ("case_file" in positionals) is expect_case_file, (
        f"{command}: positionals={positionals}"
    )
