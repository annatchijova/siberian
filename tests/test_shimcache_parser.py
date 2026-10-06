"""Tests for Windows AppCompatCache (Shimcache) parser."""
from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from siberian.shimcache_parser import (
    parse_shimcache_binary,
    format_shimcache_summary,
    ShimcacheEntry,
    _filetime,
)


def test_filetime_conversion():
    """Test FILETIME to datetime conversion."""
    ts = 133635840000000000
    dt = _filetime(ts)
    assert dt is not None


def test_zero_filetime():
    """Test that zero FILETIME returns None."""
    assert _filetime(0) is None


def test_shimcache_entry_to_dict():
    """Test ShimcacheEntry serialization."""
    entry = ShimcacheEntry(
        path="C:\\Windows\\System32\\cmd.exe",
        last_modified=None,
        flags=0,
        entry_size=128,
        raw_offset=0,
    )
    d = entry.to_dict()
    assert d["path"] == "C:\\Windows\\System32\\cmd.exe"
    assert d["last_modified"] is None
    assert d["entry_size"] == 128


def test_format_shimcache_summary():
    """Test summary formatting."""
    entry = ShimcacheEntry(
        path="C:\\Windows\\notepad.exe",
        entry_size=64,
    )
    line = format_shimcache_summary(entry)
    assert "notepad.exe" in line
    # An absent timestamp is stated as an absence, not as a value called "unknown".
    assert "not recovered" in line


def test_format_error_entry():
    """Test formatting an error entry."""
    entry = ShimcacheEntry(path="", error="Hive not found")
    line = format_shimcache_summary(entry)
    assert "ERROR" in line
    assert "Hive not found" in line


def test_parse_empty_data():
    """Test parsing empty/short data."""
    entries = parse_shimcache_binary(b"\x00\x00\x00\x00")
    assert len(entries) == 1
    assert entries[0].error is not None


def test_parse_synthetic_data():
    """Test parsing synthetic AppCompatCache-like data."""
    path_str = "C:\\Windows\\System32\\cmd.exe"
    path_bytes = path_str.encode("utf-16-le") + b"\x00\x00"
    entry_size = len(path_bytes) + 16
    data = struct.pack("<I", entry_size) + b"\x00" * 12 + path_bytes + b"\x00" * 64
    entries = parse_shimcache_binary(data)
    paths = [e.path for e in entries if e.path]
    assert len(paths) > 0
    assert any("cmd.exe" in p for p in paths)

# ---------------------------------------------------------------------------
# Provenance: a heuristic recovery must never look like a decoded record
# ---------------------------------------------------------------------------

def test_flags_is_never_a_defaulted_zero():
    """Regression: `flags` defaulted to 0, indistinguishable from a real zero."""
    entry = ShimcacheEntry(path="C:\\a.exe")
    assert entry.flags is None
    assert entry.to_dict()["flags"] is None


def test_entry_declares_how_it_was_recovered():
    entry = ShimcacheEntry(path="C:\\a.exe")
    assert entry.parse_method in ("length-scan", "path-scan")
    assert entry.to_dict()["parse_method"] == entry.parse_method


def test_summary_shows_recovery_method_and_source():
    line = format_shimcache_summary(
        ShimcacheEntry(path="C:\\a.exe", parse_method="path-scan",
                       control_set="ControlSet001", value_name="AppCompatCache")
    )
    assert "path-scan" in line
    assert "AppCompatCache" in line


def test_summary_does_not_say_unknown_for_an_unrecovered_timestamp():
    """'unknown' reads like a value; 'not recovered' states an absence."""
    line = format_shimcache_summary(ShimcacheEntry(path="C:\\a.exe"))
    assert "not recovered" in line


def test_json_roundtrip_includes_provenance():
    import json

    payload = json.loads(json.dumps(
        ShimcacheEntry(path="C:\\a.exe", parse_method="path-scan").to_dict()
    ))
    assert payload["parse_method"] == "path-scan"
    assert payload["control_set"] is None
    assert payload["value_name"] is None
    assert payload["degraded"] is None


# ---------------------------------------------------------------------------
# Registry lookup, driven by a stub hive
#
# python-registry can only open real hives, and no SYSTEM hive exists in this
# workspace, so the lookup logic is exercised with a stub that mimics the
# python-registry surface (root/subkeys/subkey/values/name/value). This tests
# the SELECTION logic only; it does not validate the on-disk hive format.
# ---------------------------------------------------------------------------

class _V:
    def __init__(self, name, val):
        self._n, self._v = name, val

    def name(self):
        return self._n

    def value(self):
        return self._v


class _K:
    def __init__(self, name, values=(), subkeys=()):
        self._n, self._values, self._subkeys = name, list(values), list(subkeys)

    def name(self):
        return self._n

    def values(self):
        return self._values

    def subkeys(self):
        return self._subkeys

    def subkey(self, path):
        cur = self
        for part in path.split("\\"):
            nxt = [s for s in cur._subkeys if s._n == part]
            if not nxt:
                return None
            cur = nxt[0]
        return cur


def _payload(path="C:\\Windows\\System32\\cmd.exe"):
    import struct

    body = (
        b"\x00" * 12
        + path.encode("utf-16-le")
        + b"\x00\x00"
        + b"\x00" * 40
    )
    return struct.pack("<I", min(len(body) + 4, 4096)) + body


def _install_stub(monkeypatch, session_values, control_set="ControlSet001",
                  cache_subkey_values=None):
    import sys
    import types

    sm = _K("Session Manager", values=session_values)
    if cache_subkey_values is not None:
        sm._subkeys.append(_K("AppCompatCache", values=cache_subkey_values))
    control = _K("Control", subkeys=[sm])
    cs = _K(control_set, subkeys=[control])
    root = _K("root", subkeys=[cs])

    module = types.ModuleType("Registry")
    module.Registry = types.SimpleNamespace(
        Registry=lambda p: types.SimpleNamespace(root=lambda: root)
    )
    monkeypatch.setitem(sys.modules, "Registry", module)


@pytest.mark.parametrize("value_name", ["AppCompatCache", "AppCompatibilityCache"])
def test_both_known_value_names_are_found(monkeypatch, value_name):
    """Windows versions differ on the spelling; both must be located by name."""
    from siberian.shimcache_parser import parse_shimcache_from_registry

    _install_stub(monkeypatch, [_V(value_name, _payload())])
    entries = parse_shimcache_from_registry(Path("/fake/SYSTEM"))
    paths = [e.path for e in entries if e.path]
    assert paths, f"{value_name} was not found"
    assert all("cmd.exe" in p for p in paths)
    # Provenance records which name matched.
    assert all(e.value_name == value_name for e in entries if e.path)
    assert all(e.control_set == "ControlSet001" for e in entries if e.path)


def test_unrelated_binary_value_is_not_taken(monkeypatch):
    """Regression: the lookup accepted ANY binary value in Session Manager."""
    from siberian.shimcache_parser import parse_shimcache_from_registry

    _install_stub(monkeypatch, [
        _V("UnrelatedBinary", b"\xde\xad\xbe\xef" * 64),
        _V("AppCompatCache", _payload("C:\\real.exe")),
    ])
    entries = parse_shimcache_from_registry(Path("/fake/SYSTEM"))
    paths = [e.path for e in entries if e.path]
    assert paths == ["C:\\real.exe"], f"wrong value consumed: {paths}"


def test_failure_message_names_what_was_actually_present(monkeypatch):
    """A failed lookup must be diagnosable, not a bare 'not found'."""
    from siberian.shimcache_parser import parse_shimcache_from_registry

    _install_stub(monkeypatch, [_V("BootExecute", "lsass.exe")])
    entries = parse_shimcache_from_registry(Path("/fake/SYSTEM"))
    assert len(entries) == 1
    err = entries[0].error
    assert err and "not found" in err
    assert "ControlSet001" in err, "must name the control set it inspected"
    assert "BootExecute" in err, "must name the values it actually saw"


def test_no_control_set_present_is_reported(monkeypatch):
    from siberian.shimcache_parser import parse_shimcache_from_registry
    import sys
    import types

    module = types.ModuleType("Registry")
    root = _K("root", subkeys=[_K("Foo", subkeys=[])])
    module.Registry = types.SimpleNamespace(
        Registry=lambda p: types.SimpleNamespace(root=lambda: root)
    )
    monkeypatch.setitem(sys.modules, "Registry", module)

    entries = parse_shimcache_from_registry(Path("/fake/SYSTEM"))
    assert entries[0].error
    assert "control sets seen: none" in entries[0].error


def test_unnamed_binary_in_cache_subkey_is_not_consumed(monkeypatch):
    """Regression: the AppCompatCache subkey branch accepted ANY binary value.

    The previous code's condition was
    `value.name() == "AppCompatCache" or isinstance(value.value(), bytes)`,
    so the first binary value in that subkey was consumed regardless of its
    name. Demonstrated against the old parser: it consumed an unrelated
    'SomeVendorBlob' and then reported "No entries parsed - format may be
    unsupported", blaming the format instead of reporting the wrong value.
    """
    from siberian.shimcache_parser import parse_shimcache_from_registry

    _install_stub(
        monkeypatch,
        session_values=[],
        cache_subkey_values=[
            _V("SomeVendorBlob", b"\xde\xad\xbe\xef" * 64),
            _V("OtherName", _payload("C:\\real.exe")),
        ],
    )
    entries = parse_shimcache_from_registry(Path("/fake/SYSTEM"))
    assert [e.path for e in entries if e.path] == [], (
        "an unrecognised value name must not be parsed as shimcache"
    )
    err = entries[0].error
    assert "SomeVendorBlob" in err, "the failure must name the values it saw"


def test_known_name_inside_cache_subkey_is_found(monkeypatch):
    from siberian.shimcache_parser import parse_shimcache_from_registry

    _install_stub(
        monkeypatch,
        session_values=[],
        cache_subkey_values=[
            _V("SomeVendorBlob", b"\xde\xad\xbe\xef" * 64),
            _V("AppCompatCache", _payload("C:\\real.exe")),
        ],
    )
    entries = parse_shimcache_from_registry(Path("/fake/SYSTEM"))
    paths = [e.path for e in entries if e.path]
    assert paths == ["C:\\real.exe"]
