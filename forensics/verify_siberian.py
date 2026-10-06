#!/usr/bin/env python3
"""
verify_siberian.py — independent verifier for SIBERIAN artifact exports.

WHAT THIS IS
    A single-file, standard-library-only verifier for the JSON documents written
    by SIBERIAN's Level 6 artifact adapters (``import-*`` and ``batch``).

INDEPENDENCE
    This file imports NOTHING from SIBERIAN. It does not import the ``siberian``
    package, and it does not need SIBERIAN installed, importable, or even
    present on the machine. It re-derives every digest from the rules written
    below.

    That is the point. If a verifier shared code with the producer, agreement
    between them would prove only that the same bug ran twice. An analyst
    verifying evidence should not have to trust the tool that produced it.

    To use it, copy this one file. That is the whole installation.

    Evidence-matrix bundles (from ``siberian seal``) are a different document
    kind and are verified by ``siberian/verify.py``, which is likewise
    stdlib-only. This file detects which kind it is given and says so plainly if
    it is given the wrong one.

HASH PROTOCOL (canonicalization v2)
------------------------------------
Reimplemented here from the specification, not copied from the producer:

    canonicalize(obj):
        bool        -> "true" | "false"
        int         -> f"{obj}:int"
        float       -> "nan" | "inf" | "-inf" | f"{obj + 0.0:.8f}"
        str         -> "s:" + NFC(obj.replace("\\r\\n","\\n").replace("\\r","\\n"))
        None        -> "null"
        dict        -> {k: canonicalize(v) for k, v in sorted(obj.items())}
        list/tuple  -> [canonicalize(v) for v in obj]
        anything else -> TypeError

    canonical_hash(obj) = SHA256(
        json.dumps(canonicalize(obj), sort_keys=True, ensure_ascii=True)
        .encode("utf-8")
    ).hexdigest()

    provenance_hash = canonical_hash({"provenance": doc["provenance"]})
    payload_hash    = canonical_hash(doc without "integrity")
    export_hash     = canonical_hash(
        doc without "integrity"
        + {"integrity": {"provenance_hash": ..., "payload_hash": ...}}
    )

The string prefix "s:" and the ":int" / ":frac" suffixes exist so that a boolean,
an integer and a string can never canonicalize to the same bytes.

WHAT IS CHECKED
    V1  document kind and versions are recognised
    V2  integrity block is present and well formed
    V3  provenance_hash re-derives
    V4  payload_hash re-derives
    V5  export_hash re-derives
    V6  provenance is internally coherent: parser name and version present,
        limitations declared, every source carries a digest or an explicit
        reason it has none
    V7  (optional, --rehash-source) the recorded source digest still matches the
        artifact on disk

V7 is the only check that touches the original evidence. Without it, a sealed
export proves internal consistency only.

WHAT IS NOT PROVEN
    That the parser was correct. That the source digest belongs to the
    analyst's original evidence. Either adapter's own limitations travel inside
    the sealed provenance and are surfaced below; read them.

USAGE
    python3 verify_siberian.py EXPORT.json
    python3 verify_siberian.py EXPORT.json --verbose
    python3 verify_siberian.py EXPORT.json --strict      # non-zero unless all pass
    python3 verify_siberian.py EXPORT.json --json        # machine-readable
    python3 verify_siberian.py EXPORT.json --rehash-source
    python3 verify_siberian.py *.json                    # verify several

    Exit: 0 = verified, 1 = failed, 2 = could not read the document
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

VERIFIER_VERSION = "1.0"

SUPPORTED_EXPORT_VERSIONS = {"1"}
SUPPORTED_CANONICALIZE_VERSIONS = {"2"}
SUPPORTED_KINDS = {"siberian-adapter-export", "siberian-batch-manifest"}

INTEGRITY_KEY = "integrity"


# ---------------------------------------------------------------------------
# Canonicalization v2 — implemented from the specification above.
# ---------------------------------------------------------------------------

class CanonicalizeError(TypeError):
    """Raised for a type the canonical form does not define."""


def _norm_str(s: str) -> str:
    return unicodedata.normalize("NFC", s.replace("\r\n", "\n").replace("\r", "\n"))


def canonicalize(obj: Any) -> Any:
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
        return f"{obj + 0.0:.8f}"
    if isinstance(obj, str):
        return "s:" + _norm_str(obj)
    if obj is None:
        return "null"
    if isinstance(obj, dict):
        return {k: canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [canonicalize(v) for v in obj]
    raise CanonicalizeError(
        f"type {type(obj).__name__} has no canonical form"
    )


def canonical_hash(obj: Any) -> str:
    serialized = json.dumps(
        canonicalize(obj), sort_keys=True, ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def file_sha256(path: str, chunk_size: int = 1 << 20) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

class Report:
    def __init__(self) -> None:
        self.checks: List[Tuple[str, str, bool, str]] = []

    def add(self, code: str, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append((code, name, passed, detail))

    @property
    def ok(self) -> bool:
        return all(passed for _, _, passed, _ in self.checks)

    @property
    def failures(self) -> List[Tuple[str, str, bool, str]]:
        return [c for c in self.checks if not c[2]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verifier_version": VERIFIER_VERSION,
            "verified": self.ok,
            "checks": [
                {"code": c, "name": n, "passed": p, "detail": d}
                for c, n, p, d in self.checks
            ],
            "failed_count": len(self.failures),
        }


def verify_document(
    document: Any, *, rehash_source: bool = False
) -> Tuple[Report, Dict[str, Any]]:
    report = Report()
    summary: Dict[str, Any] = {}

    # --- V1 kind and versions -------------------------------------------------
    if not isinstance(document, dict):
        report.add("V1", "document is a JSON object", False,
                   f"got {type(document).__name__}")
        return report, summary

    kind = document.get("kind")
    if kind not in SUPPORTED_KINDS:
        if kind is None:
            # No envelope at all. The overwhelmingly likely cause is an export
            # that was never sealed, so say that rather than sending the
            # analyst to a different verifier.
            report.add(
                "V1", "document kind is recognised", False,
                "no 'kind' field and no export envelope: this looks like an "
                "UNSEALED export. Adapter exports must carry an integrity block "
                "before they can be verified. If it is an evidence-matrix "
                "bundle from 'siberian seal', use siberian/verify.py instead.",
            )
            return report, summary
        report.add(
            "V1", "document kind is recognised", False,
            f"kind={kind!r}; expected one of {sorted(SUPPORTED_KINDS)}. If this "
            f"is an evidence-matrix bundle from 'siberian seal', use "
            f"siberian/verify.py instead.",
        )
        return report, summary
    report.add("V1", "document kind is recognised", True, f"kind={kind}")

    export_version = str(document.get("export_version", ""))
    canon_version = str(document.get("canonicalize_version", ""))
    if export_version not in SUPPORTED_EXPORT_VERSIONS:
        report.add("V1", "export_version supported", False,
                   f"export_version={export_version!r}; this verifier knows "
                   f"{sorted(SUPPORTED_EXPORT_VERSIONS)}")
        return report, summary
    report.add("V1", "export_version supported", True, f"v{export_version}")

    if canon_version not in SUPPORTED_CANONICALIZE_VERSIONS:
        report.add("V1", "canonicalize_version supported", False,
                   f"canonicalize_version={canon_version!r}; this verifier "
                   f"implements {sorted(SUPPORTED_CANONICALIZE_VERSIONS)}")
        return report, summary
    report.add("V1", "canonicalize_version supported", True, f"v{canon_version}")

    summary["kind"] = kind
    summary["export_version"] = export_version
    summary["canonicalize_version"] = canon_version

    # --- V2 integrity block present ------------------------------------------
    integrity = document.get(INTEGRITY_KEY)
    if not isinstance(integrity, dict):
        report.add("V2", "integrity block present", False,
                   "no 'integrity' object: this export was never sealed, so "
                   "nothing ties its contents to its provenance")
        return report, summary

    missing = [
        field for field in ("provenance_hash", "payload_hash", "export_hash")
        if not isinstance(integrity.get(field), str) or not integrity.get(field)
    ]
    if missing:
        report.add("V2", "integrity block complete", False,
                   f"missing or empty: {', '.join(missing)}")
        return report, summary
    report.add("V2", "integrity block complete", True)

    if integrity.get("algorithm") not in (None, "sha256"):
        report.add("V2", "digest algorithm is sha256", False,
                   f"algorithm={integrity.get('algorithm')!r}")
        return report, summary
    report.add("V2", "digest algorithm is sha256", True)

    for field in ("provenance_hash", "payload_hash", "export_hash"):
        value = integrity[field]
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            report.add("V2", f"{field} is a lowercase sha256 digest", False,
                       f"{value!r}")
            return report, summary
    report.add("V2", "digests are well-formed lowercase sha256", True)

    # --- V3 provenance_hash ---------------------------------------------------
    provenance = document.get("provenance")
    try:
        expected = canonical_hash({"provenance": provenance})
    except CanonicalizeError as exc:
        report.add("V3", "provenance_hash re-derives", False,
                   f"provenance cannot be canonicalized: {exc}")
        return report, summary
    matched = expected == integrity["provenance_hash"]
    report.add("V3", "provenance_hash re-derives", matched,
               "" if matched else
               f"recorded {integrity['provenance_hash'][:16]}... "
               f"re-derived {expected[:16]}...")
    if not matched:
        return report, summary

    # --- V4 payload_hash ------------------------------------------------------
    payload = {k: v for k, v in document.items() if k != INTEGRITY_KEY}
    try:
        expected = canonical_hash(payload)
    except CanonicalizeError as exc:
        report.add("V4", "payload_hash re-derives", False,
                   f"document cannot be canonicalized: {exc}")
        return report, summary
    matched = expected == integrity["payload_hash"]
    report.add("V4", "payload_hash re-derives", matched,
               "" if matched else
               f"recorded {integrity['payload_hash'][:16]}... "
               f"re-derived {expected[:16]}...")
    if not matched:
        return report, summary

    # --- V5 export_hash -------------------------------------------------------
    sealed_for_hash = dict(payload)
    sealed_for_hash[INTEGRITY_KEY] = {
        "provenance_hash": integrity["provenance_hash"],
        "payload_hash": integrity["payload_hash"],
    }
    try:
        expected = canonical_hash(sealed_for_hash)
    except CanonicalizeError as exc:
        report.add("V5", "export_hash re-derives", False,
                   f"document cannot be canonicalized: {exc}")
        return report, summary
    matched = expected == integrity["export_hash"]
    report.add("V5", "export_hash re-derives", matched,
               "" if matched else
               f"recorded {integrity['export_hash'][:16]}... "
               f"re-derived {expected[:16]}...")
    if not matched:
        return report, summary

    # --- V6 provenance coherence ---------------------------------------------
    if not isinstance(provenance, dict):
        report.add("V6", "provenance is an object", False,
                   f"got {type(provenance).__name__}")
        return report, summary
    report.add("V6", "provenance is an object", True)

    parser = provenance.get("parser") or {}
    parser_name = parser.get("name") if isinstance(parser, dict) else None
    parser_version = parser.get("version") if isinstance(parser, dict) else None
    coherent = bool(parser_name) and bool(parser_version)
    report.add("V6", "parser name and version are declared", coherent,
               "" if coherent else
               f"name={parser_name!r} version={parser_version!r}")
    summary["parser"] = {"name": parser_name, "version": parser_version}
    summary["determinism_level"] = (
        parser.get("determinism_level") if isinstance(parser, dict) else None
    )

    transformations = provenance.get("transformations")
    report.add("V6", "transformations are declared",
               isinstance(transformations, list) and len(transformations) > 0,
               f"{len(transformations) if isinstance(transformations, list) else 0}"
               " declared")
    summary["transformations"] = len(transformations) if isinstance(
        transformations, list) else 0

    limitations = provenance.get("limitations")
    report.add("V6", "limitations are declared",
               isinstance(limitations, list) and len(limitations) > 0)
    summary["limitations"] = limitations if isinstance(limitations, list) else []

    sources = provenance.get("sources")
    if not isinstance(sources, list) or not sources:
        report.add("V6", "at least one source is recorded", False,
                   "provenance.sources is missing or empty")
        return report, summary
    summary["sources"] = len(sources)

    digestless = []
    for source in sources:
        if not isinstance(source, dict):
            digestless.append("<malformed>")
            continue
        if not (source.get("sha256") or source.get("tree_sha256")):
            digestless.append(str(source.get("path", "<unknown>")))
    if digestless:
        # Not a failure: a source that does not exist cannot be hashed. But it
        # must be visible, so it is surfaced as a distinct outcome.
        report.add("V6", "every source carries a digest", False,
                   "no digest for: " + ", ".join(digestless)
                   + " (a path that does not exist cannot be hashed)")
        summary["sources_without_digest"] = digestless
    else:
        report.add("V6", "every source carries a digest", True)

    # --- V7 optional: re-hash the source on disk ------------------------------
    if rehash_source:
        _verify_sources_on_disk(sources, report, summary)

    return report, summary


def _verify_sources_on_disk(
    sources: List[Any], report: Report, summary: Dict[str, Any]
) -> None:
    checked, matched, absent = 0, 0, []
    for source in sources:
        if not isinstance(source, dict):
            continue
        path = source.get("path")
        recorded = source.get("sha256")
        if not path or not recorded:
            continue
        checked += 1
        actual = file_sha256(path)
        if actual is None:
            absent.append(path)
        elif actual == recorded:
            matched += 1
    summary["source_rehash"] = {
        "checked": checked, "matched": matched, "unavailable": absent
    }
    if checked == 0:
        report.add("V7", "recorded sources re-hash against disk", False,
                   "no file-backed source digest to re-hash")
    elif matched == checked:
        report.add("V7", "recorded sources re-hash against disk", True,
                   f"{matched}/{checked} match")
    else:
        report.add("V7", "recorded sources re-hash against disk", False,
                   f"{matched}/{checked} match; unavailable: "
                   f"{', '.join(absent) or 'none'}. A mismatch means the "
                   f"artifact changed after it was recorded.")


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def format_report(document: Any, report: Report, summary: Dict[str, Any],
                  verbose: bool) -> str:
    lines: List[str] = []
    if not isinstance(document, dict):
        return "FAILED: document is not a JSON object"

    parser = summary.get("parser") or {}
    if parser.get("name"):
        lines.append(
            f"Document : {summary.get('kind')} "
            f"(export v{summary.get('export_version')}, "
            f"canon v{summary.get('canonicalize_version')})"
        )
        lines.append(
            f"Parser   : {parser.get('name')} v{parser.get('version')}"
            + (f"  [{summary.get('determinism_level')}]"
               if summary.get("determinism_level") else "")
        )
    lines.append("")

    for code, name, passed, detail in report.checks:
        mark = "PASS" if passed else "FAIL"
        suffix = f"  {detail}" if detail else ""
        if verbose or not passed:
            lines.append(f"  [{mark}] {code} {name}{suffix}")
        else:
            lines.append(f"  [{mark}] {code} {name}")

    if summary.get("transformations"):
        lines.append("")
        lines.append(f"Transformations declared: {summary['transformations']}")

    if summary.get("sources") is not None:
        lines.append(f"Sources recorded        : {summary['sources']}")

    rehash = summary.get("source_rehash")
    if rehash:
        lines.append(
            f"Source re-hash          : {rehash['matched']}/{rehash['checked']}"
            + (f" (unavailable: {len(rehash['unavailable'])})"
               if rehash["unavailable"] else "")
        )

    limitations = summary.get("limitations") or []
    if limitations:
        lines.append("")
        lines.append("Limitations declared by the producer (sealed, not a claim "
                     "of correctness):")
        for item in limitations:
            lines.append(f"  - {item}")

    lines.append("")
    if report.ok:
        lines.append("RESULT: VERIFIED — the document is internally consistent "
                     "and unmodified since it was sealed.")
        lines.append("This does NOT establish that the parser was correct. Read "
                     "the limitations above.")
    else:
        lines.append(f"RESULT: FAILED — {len(report.failures)} check(s) did not pass.")
    return "\n".join(lines)


def verify_file(path: str, *, verbose: bool, rehash_source: bool) -> int:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        print(f"{path}: not found", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"{path}: cannot read as JSON: {exc}", file=sys.stderr)
        return 2

    report, summary = verify_document(document, rehash_source=rehash_source)
    print(f"=== {path} ===")
    print(format_report(document, report, summary, verbose))
    return 0 if report.ok else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_siberian.py",
        description=(
            "Independent verifier for SIBERIAN adapter exports. "
            "Standard library only; does not import SIBERIAN."
        ),
    )
    parser.add_argument("paths", nargs="+", metavar="EXPORT.json",
                        help="one or more sealed exports to verify")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="show detail for passing checks too")
    parser.add_argument("--strict", "-s", action="store_true",
                        help="exit non-zero unless every document verifies")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable results")
    parser.add_argument("--rehash-source", action="store_true",
                        help="also re-hash the recorded source artifacts on disk")
    args = parser.parse_args(argv)

    results = []
    worst = 0
    for path in args.paths:
        code = verify_file(path, verbose=args.verbose,
                           rehash_source=args.rehash_source)
        worst = max(worst, code)
        if args.json:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    document = json.load(handle)
            except (OSError, ValueError):
                document = None
            report, _ = verify_document(document,
                                        rehash_source=args.rehash_source)
            results.append({"path": path, "exit_code": code, **report.to_dict()})
        print()

    if args.json and results:
        print(json.dumps(
            {"verifier_version": VERIFIER_VERSION, "documents": results},
            indent=2, sort_keys=True,
        ))
        if args.strict and any(not r["verified"] for r in results):
            return 1
        return worst

    if args.strict:
        return 1 if worst else 0
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
