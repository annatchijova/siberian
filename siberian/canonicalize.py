"""
siberian/canonicalize.py
========================
Single source of truth for canonical serialization in SIBERIAN.

INVARIANT: This module defines the canonical encoding for SHA-256 sealing.
All modules that need to canonicalize must import from here — except the
stdlib-only verifier (verify.py) which keeps its own copy BY DESIGN,
verified in lockstep by tests.

Schema v2 (DEFAULT — new seals):
  bool     → "true" / "false"
  int      → "N:int"
  float    → "N.NNNNNNNN" (8 fixed decimals)
  str      → "s:" + NFC(CRLF/CR->LF)   ← escaped + normalized
  None     → "null"
  Fraction → "num/den:frac"
  dict     → sorted keys, recursive values
  list     → recursive elements

Schema v1 (LEGACY — only for verifying historical bundles): identical to v2
except `str → unchanged` and `Fraction → str()`. That root cause produced
type collisions (True/"true", 1/"1:int", None/"null") and instability
(NFC/NFD, CRLF/LF → two hashes). v2 closes this without touching scalar
encoding, so verification tries v2 and FALLS BACK to v1: every bundle
sealed under v1 still verifies identically, and new ones get collision-free
encoding.

CANONICALIZE_VERSION = "2" — default for new seals; v1 preserved for
verifying historical bundles.
"""
from __future__ import annotations

from typing import Any

import unicodedata
from fractions import Fraction

# v2 (DEFAULT for new seals). v1 preserved for verifying historical bundles.
CANONICALIZE_VERSION: str = "2"

# Unique prefix for strings — prevents "true"/"1:int"/"null" from colliding
# with scalar tags (True/1/None). Any prefix works as long as it CANNOT be
# produced by scalar encoding; "s:" is not.
_V2_STR_PREFIX: str = "s:"


def _v2_norm_str(s: str) -> str:
    """Normalize a string for v2 hashing: CRLF/CR -> LF, then NFC.
    Closes the instability "same logical string → two hashes" (NFC/NFD, CRLF/LF)."""
    return unicodedata.normalize("NFC", s.replace("\r\n", "\n").replace("\r", "\n"))


def _canonicalize_v1(obj: Any) -> Any:
    """
    Schema v1 (LEGACY — frozen). Only for verifying historical bundles.

    Rules:
    - bool  → "true" / "false"  (before int — bool is subclass of int)
    - int   → "N:int"
    - float → "N.NNNNNNNN" (8 decimals), "nan", "inf", "-inf"
    - str   → unchanged   ← root cause of R3-2 collisions
    - None  → "null"
    - dict  → sorted keys, recursive values
    - list/tuple → recursive elements
    - other → str() — fallback

    WEAKNESS (R3-2): unescaped strings collide with scalar tags, and
    NFC/NFD + CRLF/LF produce two hashes for one string. Fixed in v2.
    DO NOT use for new seals.
    """
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"  # +0.0 maps -0.0 -> 0.0: signed zero must canonicalize identically
    if isinstance(obj, str):
        return obj
    if obj is None:
        return "null"
    if isinstance(obj, dict):
        return {k: _canonicalize_v1(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize_v1(v) for v in obj]
    return str(obj)


def _canonicalize_v2(obj: Any) -> Any:
    """
    Schema v2 (DEFAULT for new seals). Closes the collisions.

    Differences from v1 (SCALARS IDENTICAL — only strings and Fraction change):
    - str      → "s:" + NFC(CRLF/CR->LF)   [unique prefix + normalization]
    - Fraction → "num/den:frac"            [before fell to str() → "1/2"]
    - fallback → "s:" + NFC(str(obj))      [never raw, avoids collision]
    - bool/int/float/None/dict/list        [identical to v1, bit for bit]

    Why this closes the three collision classes:
    - True→"true" vs "true"→"s:true"       : no longer collide.
    - 1→"1:int"  vs "1:int"→"s:1:int"      : no longer collide.
    - None→"null" vs "null"→"s:null"       : no longer collide.
    - NFC/NFD and CRLF/LF                   : normalized to single form.
    - Fraction(1,2)                         : unique and stable.
    """
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"  # +0.0 maps -0.0 -> 0.0: signed zero must canonicalize identically
    if isinstance(obj, str):
        return _V2_STR_PREFIX + _v2_norm_str(obj)
    if obj is None:
        return "null"
    if isinstance(obj, Fraction):
        return f"{obj.numerator}/{obj.denominator}:frac"
    if isinstance(obj, dict):
        return {k: _canonicalize_v2(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize_v2(v) for v in obj]
    return _V2_STR_PREFIX + _v2_norm_str(str(obj))


# Default for all production code (new seals) = v2.
def _canonicalize(obj: Any) -> Any:
    """Canonical form DEFAULT (v2). See _canonicalize_v2."""
    return _canonicalize_v2(obj)


def canonical_hash(payload: dict, canon=_canonicalize) -> str:
    """
    SHA-256 of a dict in strict canonical form.

    `canon` chooses the scheme: default v2 (new seals); v1 only for
    verifying historical bundles (backward-compat).
    """
    import hashlib
    import json

    canonical = canon(payload)
    serialized = json.dumps(canonical, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def canonicalize_v1(obj: Any) -> Any:
    """Public accessor for v1 (legacy verification only)."""
    return _canonicalize_v1(obj)


def canonicalize_v2(obj: Any) -> Any:
    """Public accessor for v2 (new seals)."""
    return _canonicalize_v2(obj)