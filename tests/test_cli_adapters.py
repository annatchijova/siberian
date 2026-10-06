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
    # A failed run still states which parser produced the file and what it can
    # and cannot do.
    prov = payload["provenance"]
    assert prov["parser"]["name"] == "siberian.amcache_parser"
    assert prov["parser"]["version"]
    assert prov["parser"]["requires"] == "python-registry"
    assert prov["limitations"]
    assert prov["sources"][0]["path"].endswith("missing.hve")


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
    assert isinstance(payload, dict)
    assert payload["records"][0]["container"] == "MAM"
    assert len(payload["records"][0]["file_sha256"]) == 64
    prov = payload["provenance"]
    assert prov["parser"]["name"] == "siberian.prefetch_parser"
    assert prov["parser"]["determinism_level"] == "best_effort"
    assert "SCCA" in " ".join(prov["parser"]["supports"])
    assert prov["run"]["stats"]["total"] == 1


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
    assert payload["records"][0]["is_valid"] is True
    prov = payload["provenance"]
    assert prov["parser"]["name"] == "siberian.mft_parser"
    # The source digest is the chain-of-custody anchor and must be correct.
    import hashlib

    assert prov["sources"][0]["sha256"] == hashlib.sha256(mft.read_bytes()).hexdigest()
    assert prov["sources"][0]["size_bytes"] == mft.stat().st_size
    assert prov["run"]["records_invalid"] == 0
    assert any("fixup" in t for t in prov["transformations"])


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


def test_shimcache_failure_is_not_counted_as_a_parsed_entry(tmp_path, capsys):
    """Regression: the count line reported 'Parsed 1 entries' for a missing hive.

    The synthetic error entry was included in the tally, so a total failure
    looked like a one-entry success.
    """
    rc = cli._cmd_import_shimcache(_ns(system_hive=tmp_path / "SYSTEM"))
    out = capsys.readouterr().out
    assert rc == 1
    assert "Parsed 0 Shimcache entries" in out


def test_shellbags_failure_is_not_counted_as_a_parsed_entry(tmp_path, capsys):
    rc = cli._cmd_import_shellbags(_ns(hive_path=tmp_path / "NTUSER.DAT"))
    out = capsys.readouterr().out
    assert rc == 1
    assert "Parsed 0 Shellbag entries" in out


# ---------------------------------------------------------------------------
# Provenance in every export
#
# These exist because a NameError in the Shimcache/Shellbags JSON paths shipped
# unnoticed: the handlers wrapped everything in `except Exception`, reported
# "error importing ...", and returned 2. No test invoked those code paths.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "command,kwargs,parser_name",
    [
        ("_cmd_import_shimcache", {"system_hive": "HIVE"}, "siberian.shimcache_parser"),
        ("_cmd_import_shellbags", {"hive_path": "HIVE"}, "siberian.shellbags_parser"),
        ("_cmd_import_amcache", {"amcache_hve": "HIVE"}, "siberian.amcache_parser"),
    ],
)
def test_registry_adapters_emit_provenance(tmp_path, capsys, command, kwargs, parser_name):
    """A failed parse must still produce a provenance record.

    The record is what tells a later reader which code produced the file and
    what it could not do -- including on a total failure.
    """
    hive = tmp_path / "HIVE"
    hive.write_bytes(b"\x00" * 4096)  # not a real hive: the run fails
    args = _ns(output=tmp_path / "out.json", allow_partial=True,
               **{k: hive for k in kwargs})
    rc = getattr(cli, command)(args)

    payload = json.loads((tmp_path / "out.json").read_text())
    prov = payload["provenance"]
    assert prov["parser"]["name"] == parser_name
    assert prov["parser"]["version"]
    assert prov["transformations"]
    assert prov["limitations"]
    # The source digest is present even though parsing failed: the artifact was
    # still read and hashed, and that is the chain-of-custody anchor.
    src = prov["sources"][0]
    assert src["sha256"] == __import__("hashlib").sha256(hive.read_bytes()).hexdigest()
    assert src["size_bytes"] == 4096
    assert rc in (0, 1)


def test_every_adapter_json_export_has_a_provenance_block(tmp_path):
    """Belt and braces: the top-level key exists for all five artifact adapters."""
    import struct

    mft = tmp_path / "MFT"
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 16, 1)
    struct.pack_into("<H", rec, 18, 1)
    struct.pack_into("<H", rec, 20, 56)
    struct.pack_into("<I", rec, 24, 1024)
    struct.pack_into("<I", rec, 28, 1024)
    mft.write_bytes(bytes(rec))

    pf = tmp_path / "pf"
    pf.mkdir()
    (pf / "A.EXE-00000000.pf").write_bytes(b"MAM\x04" + b"\x00" * 300)

    cases = [
        ("_cmd_import_mft", {"mft_file": mft}, "siberian.mft_parser"),
        ("_cmd_import_prefetch", {"target": pf}, "siberian.prefetch_parser"),
        ("_cmd_import_amcache", {"amcache_hve": tmp_path / "no.hive"}, "siberian.amcache_parser"),
        ("_cmd_import_shimcache", {"system_hive": tmp_path / "no.hive"}, "siberian.shimcache_parser"),
        ("_cmd_import_shellbags", {"hive_path": tmp_path / "no.hive"}, "siberian.shellbags_parser"),
    ]
    for handler, kwargs, parser_name in cases:
        out = tmp_path / f"{parser_name.split('.')[-1]}.json"
        getattr(cli, handler)(_ns(output=out, allow_partial=True, **kwargs))
        payload = json.loads(out.read_text())
        assert "provenance" in payload, f"{parser_name} export lacks provenance"
        assert payload["provenance"]["parser"]["name"] == parser_name
        assert payload["provenance"]["provenance_version"]


def test_mft_invalid_records_exit_nonzero(tmp_path, capsys):
    """A record that failed to parse is a partial result, not a clean run."""
    mft = tmp_path / "MFT"
    mft.write_bytes(b"BAD!" + b"\x00" * 2040)  # wrong signature throughout
    rc = cli._cmd_import_mft(_ns(mft_file=mft))
    assert rc == 1
    assert "did not parse" in capsys.readouterr().err

    rc = cli._cmd_import_mft(_ns(mft_file=mft, allow_partial=True))
    assert rc == 0


# ---------------------------------------------------------------------------
# Configured limits must be disclosed, not silently applied
#
# Regression: parse_prefetch_directory reported total=10 for a directory holding
# 225 files with max_files=10, so a truncated run was indistinguishable from a
# complete one. parse_mft_file returned 5 records for a 50-record file with no
# indication that 45 had been dropped.
# ---------------------------------------------------------------------------

def _pf_dir(tmp_path, n=25):
    d = tmp_path / f"pf{n}"
    d.mkdir()
    for i in range(n):
        (d / f"E{i}.EXE-{i:08X}.pf").write_bytes(b"MAM\x04" + bytes([i]) * 300)
    return d


def test_prefetch_limit_is_disclosed(tmp_path, capsys):
    d = _pf_dir(tmp_path, 25)
    out = tmp_path / "o.json"
    rc = cli._cmd_import_prefetch(
        _ns(target=d, max_files=10, output=out, allow_partial=True)
    )
    payload = json.loads(out.read_text())
    st = payload["provenance"]["run"]["stats"]
    assert st["available"] == 25
    assert st["processed"] == 10
    assert st["truncated"] == 15
    assert len(payload["records"]) == 10
    assert rc == 0  # --allow-partial was given


def test_prefetch_limit_makes_the_run_partial(tmp_path):
    d = _pf_dir(tmp_path, 25)
    rc = cli._cmd_import_prefetch(_ns(target=d, max_files=10))
    assert rc == 1


def test_prefetch_no_limit_reports_zero_truncation(tmp_path):
    d = _pf_dir(tmp_path, 25)
    out = tmp_path / "o.json"
    cli._cmd_import_prefetch(_ns(target=d, output=out))
    st = json.loads(out.read_text())["provenance"]["run"]["stats"]
    assert st["available"] == 25 and st["processed"] == 25 and st["truncated"] == 0


def _mft_with(tmp_path, n):
    import struct

    p = tmp_path / f"MFT{n}"
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 16, 1)
    struct.pack_into("<H", rec, 18, 1)
    struct.pack_into("<H", rec, 20, 56)
    struct.pack_into("<I", rec, 24, 1024)
    struct.pack_into("<I", rec, 28, 1024)
    p.write_bytes(bytes(rec) * n)
    return p


def test_mft_limit_is_disclosed(tmp_path):
    mft = _mft_with(tmp_path, 50)
    out = tmp_path / "mft.json"
    cli._cmd_import_mft(_ns(mft_file=mft, max_records=5, output=out,
                           allow_partial=True))
    run = json.loads(out.read_text())["provenance"]["run"]
    assert run["available"] == 50
    assert run["processed"] == 5
    assert run["truncated"] == 45
    assert run["max_records"] == 5


def test_mft_limit_makes_the_run_partial(tmp_path):
    mft = _mft_with(tmp_path, 50)
    assert cli._cmd_import_mft(_ns(mft_file=mft, max_records=5)) == 1
    assert cli._cmd_import_mft(
        _ns(mft_file=mft, max_records=5, allow_partial=True)
    ) == 0


def test_mft_no_limit_reports_zero_truncation(tmp_path):
    mft = _mft_with(tmp_path, 10)
    out = tmp_path / "mft.json"
    rc = cli._cmd_import_mft(_ns(mft_file=mft, output=out))
    run = json.loads(out.read_text())["provenance"]["run"]
    assert rc == 0
    assert run["available"] == 10 and run["processed"] == 10
    assert run["truncated"] == 0


def test_parse_mft_file_stats_is_optional(tmp_path):
    """Backwards compatibility: the stats argument is optional."""
    from siberian.mft_parser import parse_mft_file

    mft = _mft_with(tmp_path, 3)
    assert len(parse_mft_file(mft)) == 3
    assert len(parse_mft_file(mft, max_records=1)) == 1
