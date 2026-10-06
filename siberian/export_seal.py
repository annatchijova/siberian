"""
siberian/export_seal.py
=======================
Tamper-evident sealing for Nivel 6 adapter exports.

An adapter export (the JSON written by ``import-*`` and by ``batch``) is the
thing an analyst actually hands to someone else. Until now it carried provenance
but no integrity block: it said which parser produced it and from which source,
yet nothing tied the *contents* to that claim. Editing a record after the fact
left every provenance field intact and self-consistent.

Sealing closes that. The same reasoning that applies to an evidence-matrix
bundle applies here: a claim that cannot be checked is not evidence.

Hash protocol
-------------
Reuses the project's canonicalization v2 (see ``siberian/canonicalize.py``), so
an independent verifier reproduces these digests from the documented rules alone,
without this package:

    canonical_hash(obj) = SHA256(
        json.dumps(canonicalize_v2(obj), sort_keys=True, ensure_ascii=True)
        .encode("utf-8")
    )

    provenance_hash = canonical_hash({"provenance": <provenance>})
    payload_hash    = canonical_hash(<document without "integrity">)
    export_hash     = canonical_hash(
        <document without "integrity">
        + {"integrity": {"provenance_hash": ..., "payload_hash": ...}}
    )

``export_hash`` therefore covers the provenance, the records, and the two
component hashes. It cannot cover itself, which is the normal arrangement.

What sealing does and does not prove
------------------------------------
It proves the document has not changed since it was produced. It does **not**
prove the parser was correct, and it does not prove the source digest is the
digest of the analyst's original evidence -- that requires re-hashing the source,
which the standalone verifier offers as ``--rehash-source`` when the artifact is
still present. Each adapter's own limitations travel inside the sealed
provenance, so a verifier surfaces them without trusting this package.
"""
from __future__ import annotations

from typing import Any, Dict

from .canonicalize import CANONICALIZE_VERSION, canonical_hash

# Bump when the export envelope or hash protocol changes.
EXPORT_SEAL_VERSION = "1"

#: Marker so a verifier can identify the document kind without guessing.
EXPORT_KIND = "siberian-adapter-export"

MANIFEST_KIND = "siberian-batch-manifest"

INTEGRITY_KEY = "integrity"


def seal_export(payload: Dict[str, Any], kind: str = EXPORT_KIND) -> Dict[str, Any]:
    """Return ``payload`` with an integrity block bound to its contents.

    Any pre-existing ``integrity`` block is replaced, so sealing twice is
    idempotent rather than accumulating nested blocks.

    Args:
        payload: the export document
        kind: document kind marker

    Returns:
        A new dict; the input is not mutated.
    """
    document = {k: v for k, v in payload.items() if k != INTEGRITY_KEY}
    document["export_version"] = EXPORT_SEAL_VERSION
    document["canonicalize_version"] = CANONICALIZE_VERSION
    document["kind"] = kind

    # The version fields are part of the document, so they are set before any
    # digest is computed: they are covered by payload_hash and export_hash.
    provenance_hash = canonical_hash({"provenance": document.get("provenance")})
    payload_hash = canonical_hash(document)

    sealed_for_hash = dict(document)
    sealed_for_hash[INTEGRITY_KEY] = {
        "provenance_hash": provenance_hash,
        "payload_hash": payload_hash,
    }
    export_hash = canonical_hash(sealed_for_hash)

    document[INTEGRITY_KEY] = {
        "provenance_hash": provenance_hash,
        "payload_hash": payload_hash,
        "export_hash": export_hash,
        "algorithm": "sha256",
        "canonicalize_version": CANONICALIZE_VERSION,
        "export_version": EXPORT_SEAL_VERSION,
    }
    return document


def is_sealed(document: Dict[str, Any]) -> bool:
    """True when the document carries a complete integrity block."""
    integrity = document.get(INTEGRITY_KEY)
    if not isinstance(integrity, dict):
        return False
    return all(
        isinstance(integrity.get(field), str) and integrity.get(field)
        for field in ("provenance_hash", "payload_hash", "export_hash")
    )
