"""Tests for the Windows Shellbags parser.

No NTUSER.DAT or UsrClass.dat exists in this workspace and python-registry can
only open real hives, so the traversal is exercised with a stub that mimics the
python-registry surface. That covers selection and extraction logic; it does not
validate the on-disk shellbag record layout. See
docs/red-team/NIVEL6_SHELLBAGS_AUDIT.md.

The previous revision of this file asserted only that a path substring appeared,
accepting `"C:\\Users\\Test\\Deskto"` as a match for `Desktop` — which is exactly
the truncation bug it should have caught.
"""
from __future__ import annotations

import random
import sys
import types
from pathlib import Path

import pytest

from siberian.shellbags_parser import (
    ShellbagEntry,
    _extract_path_from_binary,
    _extract_utf16_paths,
    _filetime,
    _is_bag_child,
    _looks_like_path,
    format_shellbag_summary,
    parse_shellbags_from_registry,
)


# ---------------------------------------------------------------------------
# UTF-16 path extraction
# ---------------------------------------------------------------------------

def test_clean_path_is_extracted_exactly():
    """Regression: the last character was always dropped.

    'C:\\Users\\Bob\\Desktop' came back as 'C:\\Users\\Bob\\Deskto' — a wrong
    path that still looks entirely plausible.
    """
    blob = "C:\\Users\\Bob\\Desktop".encode("utf-16-le") + b"\x00\x00"
    assert _extract_path_from_binary(blob) == "C:\\Users\\Bob\\Desktop"


def test_unc_path_is_extracted():
    blob = b"\x11\x22" + "\\\\server\\share\\folder".encode("utf-16-le") + b"\x00\x00"
    assert _extract_path_from_binary(blob) == "\\\\server\\share\\folder"


def test_path_is_found_at_either_byte_alignment():
    """A registry payload may begin at either parity."""
    path = "C:\\Users\\Bob\\Documents\\file.docx"
    for prefix_len in range(0, 8):
        prefix = bytes(range(prefix_len))
        blob = prefix + path.encode("utf-16-le") + b"\x00\x00"
        assert _extract_path_from_binary(blob) == path, f"prefix_len={prefix_len}"


def test_many_random_prefixes_all_yield_the_exact_path():
    rnd = random.Random(11)
    for i in range(200):
        prefix = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 20)))
        path = f"C:\\Users\\Bob\\Documents\\file{i}.docx"
        blob = prefix + path.encode("utf-16-le") + b"\x00\x00"
        assert _extract_path_from_binary(blob) == path, f"iteration {i}"


def test_noise_does_not_yield_a_path():
    """Guessing must not manufacture paths out of arbitrary bytes."""
    rnd = random.Random(5)
    for _ in range(300):
        noise = bytes(rnd.randrange(256) for _ in range(200))
        assert _extract_path_from_binary(noise) is None


def test_empty_and_short_blobs_yield_nothing():
    assert _extract_path_from_binary(b"") is None
    assert _extract_path_from_binary(b"\x00\x01") is None


def test_all_paths_are_reported_not_just_the_first():
    blob = (
        b"\x00\x00"
        + "C:\\Users\\Bob\\One".encode("utf-16-le")
        + b"\x00\x00"
        + b"\x00" * 8
        + "C:\\Users\\Bob\\Two".encode("utf-16-le")
        + b"\x00\x00"
    )
    found = [p for _, p in _extract_utf16_paths(blob)]
    assert "C:\\Users\\Bob\\One" in found
    assert "C:\\Users\\Bob\\Two" in found


def test_path_shaped_validation():
    assert _looks_like_path("C:\\Windows") is True
    assert _looks_like_path("C:/Windows") is True
    assert _looks_like_path("\\\\srv\\share") is True
    assert _looks_like_path("C:") is False
    assert _looks_like_path("hello world") is False
    assert _looks_like_path("") is False


def test_bag_child_detection():
    assert _is_bag_child("0") is True
    assert _is_bag_child("1a") is True
    assert _is_bag_child("2F") is True
    assert _is_bag_child("MRUList") is False
    assert _is_bag_child("") is False


# ---------------------------------------------------------------------------
# Invented fields are gone
# ---------------------------------------------------------------------------

def test_entry_has_no_invented_view_or_sort_fields():
    """Regression: view_mode/sort_mode were matched from arbitrary bytes.

    A random byte matches the view-mode table ~3% of the time and the parser
    took the first hit across 11 offsets, inventing a value for roughly a
    quarter of the entries it read. The fields are removed rather than kept as
    unverified guesses.
    """
    entry = ShellbagEntry(bag_type="BagMRU", key_path="x", folder_path="C:\\a")
    assert not hasattr(entry, "view_mode")
    assert not hasattr(entry, "sort_mode")
    assert not hasattr(entry, "timestamp")
    payload = entry.to_dict()
    assert set(payload) == {
        "bag_type", "key_path", "folder_path",
        "raw_value_name", "raw_value_size", "error",
    }


def test_summary_reports_only_what_was_recovered():
    line = format_shellbag_summary(
        ShellbagEntry(bag_type="BagMRU", key_path="Shell\\BagMRU\\0",
                      folder_path="C:\\Users\\Bob\\Desktop")
    )
    assert "Desktop" in line
    assert "BagMRU" in line
    # No invented settings, and no "unknown" standing in for absent data.
    assert "view" not in line.lower()
    assert "sort" not in line.lower()
    assert "unknown" not in line.lower()


def test_summary_of_error_entry():
    line = format_shellbag_summary(ShellbagEntry(bag_type="BagMRU", key_path="",
                                                 error="Hive not found"))
    assert "ERROR" in line and "Hive not found" in line


def test_filetime_conversion():
    assert _filetime(0) is None
    assert _filetime(-1) is None
    assert _filetime(133635840000000000) is not None


# ---------------------------------------------------------------------------
# Traversal, driven by a stub hive
# ---------------------------------------------------------------------------

class V:
    def __init__(self, name, val):
        self._n, self._v = name, val

    def name(self):
        return self._n

    def value(self):
        return self._v


class K:
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
            if not part:
                continue
            nxt = [s for s in cur._subkeys if s._n == part]
            if not nxt:
                return None
            cur = nxt[0]
        return cur


def _entry_blob(path: str, filler: bytes = b"\x00" * 32) -> bytes:
    return filler + path.encode("utf-16-le") + b"\x00\x00" + b"\x00" * 16


def _install(monkeypatch, root):
    module = types.ModuleType("Registry")
    module.Registry = types.SimpleNamespace(
        Registry=lambda p: types.SimpleNamespace(root=lambda: root)
    )
    monkeypatch.setitem(sys.modules, "Registry", module)


def _shell_tree(bag):
    """Wrap a bag key in the Software\\Microsoft\\Windows\\Shell hierarchy."""
    shell = K("Shell", subkeys=[bag])
    windows = K("Windows", subkeys=[shell])
    microsoft = K("Microsoft", subkeys=[windows])
    return K("root", subkeys=[K("Software", subkeys=[microsoft])])


def _classes_tree(bag):
    """Wrap a bag key in the UsrClass.dat Local Settings hierarchy.

    Real path: Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell
    """
    shell = K("Shell", subkeys=[bag])
    windows = K("Windows", subkeys=[shell])
    microsoft = K("Microsoft", subkeys=[windows])
    inner_software = K("Software", subkeys=[microsoft])
    local = K("Local Settings", subkeys=[inner_software])
    classes = K("Classes", subkeys=[local])
    return K("root", subkeys=[K("Software", subkeys=[classes])])


def _realistic_tree(n=5):
    """BagMRU with numbered subkeys holding the entry data, as in a real hive."""
    subs = [K(f"{i:x}", values=[V("0", _entry_blob(f"C:\\Users\\Bob\\F{i}"))])
            for i in range(n)]
    bag = K("BagMRU",
             values=[V("MRUList", b"0 " * n), V("NodeSlotCapacity", b"\x20\x04\x00\x00")],
             subkeys=subs)
    return _shell_tree(bag)


def test_paths_in_numbered_subkeys_are_found(monkeypatch):
    """Regression: the real layout stores entry data BELOW BagMRU.

    The previous revision read only values on the BagMRU key itself and
    recovered 0 of 200 folders from a realistically shaped hive.
    """
    _install(monkeypatch, _realistic_tree(5))
    entries = parse_shellbags_from_registry(Path("/fake/NTUSER.DAT"))
    paths = sorted(e.folder_path for e in entries if e.folder_path)
    assert paths == [f"C:\\Users\\Bob\\F{i}" for i in range(5)]


def test_bookkeeping_values_are_skipped(monkeypatch):
    _install(monkeypatch, _realistic_tree(3))
    entries = parse_shellbags_from_registry(Path("/fake/NTUSER.DAT"))
    names = {e.raw_value_name for e in entries if e.folder_path}
    assert "MRUList" not in names
    assert "NodeSlotCapacity" not in names


def test_classes_based_shellbags_are_found(monkeypatch):
    bag = K("BagMRU", subkeys=[
        K("0", values=[V("0", _entry_blob("C:\\Users\\Bob\\Classes"))])])
    _install(monkeypatch, _classes_tree(bag))
    entries = parse_shellbags_from_registry(Path("/fake/UsrClass.dat"))
    paths = [e.folder_path for e in entries if e.folder_path]
    assert paths == ["C:\\Users\\Bob\\Classes"]


def test_missing_hive_is_an_explicit_error(tmp_path):
    entries = parse_shellbags_from_registry(tmp_path / "NTUSER.DAT")
    assert len(entries) == 1
    assert entries[0].error is not None
    assert "Cannot open hive" in entries[0].error


def test_hive_without_shellbags_is_an_explicit_error(monkeypatch):
    _install(monkeypatch, K("root", subkeys=[
        K("Software", subkeys=[K("Other", subkeys=[])])]))
    entries = parse_shellbags_from_registry(Path("/fake/NTUSER.DAT"))
    assert len(entries) == 1
    assert entries[0].error is not None
    assert "No Shell" in entries[0].error


def test_present_keys_without_recoverable_paths_is_reported(monkeypatch):
    """Keys exist but nothing decoded: say so, do not return an empty success."""
    _install(monkeypatch, _shell_tree(K("BagMRU", values=[V("MRUList", b"\x00" * 8)])))
    entries = parse_shellbags_from_registry(Path("/fake/NTUSER.DAT"))
    assert len(entries) == 1
    assert "No folder paths recovered" in entries[0].error


def test_deep_nesting_does_not_recurse_without_bound(monkeypatch):
    """A pathological hive must terminate."""
    node = K("BagMRU", values=[V("0", _entry_blob("C:\\Users\\Bob\\Deep"))])
    for i in range(40):
        node = K(f"{i:x}", subkeys=[node])
    shell = K("Shell", subkeys=[node])
    root = K("root", subkeys=[K("Software", subkeys=[
        K("Microsoft", subkeys=[K("Windows", subkeys=[shell])])])])
    _install(monkeypatch, root)
    entries = parse_shellbags_from_registry(Path("/fake/NTUSER.DAT"))
    assert isinstance(entries, list)
