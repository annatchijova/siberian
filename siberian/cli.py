"""Offline command-line interface for SIBERIAN case files."""
from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Dict

from .adversarial_silence import (
    ObservationReason,
    SilenceAnalysisResult,
    SilenceRecord,
)
from .bundle import BundleBuilder
from .casefile import CaseFileError, load_case_file
from .plaso_import import PlasoImporter, get_default_mappings, PlasoToSiberianMapping
from .rival_analysis import analyze_rivals, format_rival_report
from .mft_parser import parse_mft_file, format_mft_record_summary, MftRecord
from .prefetch_parser import parse_prefetch_file, parse_prefetch_directory, format_prefetch_summary, PrefetchRecord
from .amcache_parser import parse_amcache_hive, format_amcache_summary, AmcacheEntry
from .shimcache_parser import parse_shimcache_from_registry, parse_shimcache_binary, format_shimcache_summary, ShimcacheEntry
from .shellbags_parser import parse_shellbags_from_registry, format_shellbag_summary, ShellbagEntry
from .adapter_provenance import (
    MFT_SPEC,
    PREFETCH_SPEC,
    AMCACHE_SPEC,
    SHIMCACHE_SPEC,
    SHELLBAGS_SPEC,
    PLASO_SPEC,
    build_provenance,
)

_NEXT_CHECKS = {
    ObservationReason.CONDITIONS_UNVERIFIED: "document each required applicability condition across the full analysis interval",
    ObservationReason.CATALOG_SCOPE_UNVERIFIED: "verify the declared product/release against the catalog scope; retain UNKNOWN if unmatched",
    ObservationReason.NOT_COLLECTED: "determine whether the source can be acquired for the case interval",
    ObservationReason.RETENTION_GAP: "review retention/wrap limits and available forwarded or alternate sources",
    ObservationReason.ACQUISITION_GAP: "review acquisition coverage and supplement it from an available source if possible",
    ObservationReason.PARSER_FAILURE: "validate the parser and version against the acquired source before interpreting the row",
    ObservationReason.AMBIGUOUS: "seek an independent observation that discriminates the competing explanations",
}


def _build_parser() -> argparse.ArgumentParser:
    """Construct the full argument parser.

    Extracted from main() so the argument contract can be asserted directly by
    tests rather than only by invoking commands.
    """
    parser = argparse.ArgumentParser(
        prog="siberian",
        description="Review declared forensic evidence gaps; does not infer deletion or intent.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    # Only these commands consume a case file. The standalone artifact parsers
    # (import-mft, import-prefetch, import-amcache, import-shimcache,
    # import-shellbags) read their own target path and emit summary/JSON only;
    # adding "case_file" to them forced a spurious unused positional argument.
    case_file_commands = frozenset(
        {
            "validate",
            "analyze",
            "explain",
            "seal",
            "verify",
            "import-plaso",
            "rivals",
        }
    )

    for command, help_text in (
        ("validate", "validate a case file without producing a report"),
        ("analyze", "produce a deterministic JSON evidence matrix"),
        ("explain", "explain statuses and unresolved conditions in a case"),
        ("seal", "produce a tamper-evident sealed bundle from a case file"),
        ("verify", "verify a sealed bundle (stdlib-only verifier)"),
        ("import-plaso", "import Plaso l2tcsv as UNKNOWN observations into a case file"),
        ("import-mft", "parse NTFS $MFT records and produce summary output"),
        ("import-prefetch", "parse Windows Prefetch files and produce summary output"),
        ("import-amcache", "parse Windows Amcache.hve and produce summary output"),
        ("import-shimcache", "parse AppCompatCache (Shimcache) from SYSTEM hive"),
        ("import-shellbags", "parse Shellbags from NTUSER.DAT/USRCLASS.DAT hive"),
        ("rivals", "evaluate rival hypotheses against analysis result"),
    ):
        subparser = commands.add_parser(command, help=help_text)
        if command in case_file_commands:
            subparser.add_argument("case_file", type=Path, help="analyst-authored JSON case file")

    # import-shellbags specific options
    import_shellbags_parser = commands.choices["import-shellbags"]
    import_shellbags_parser.add_argument("hive_path", type=Path, help="Path to NTUSER.DAT or USRCLASS.DAT hive")
    import_shellbags_parser.add_argument("--bag-type", default="BagMRU", choices=["BagMRU", "Bags"], help="bag subkey to parse")
    import_shellbags_parser.add_argument("--max-entries", type=int, default=0, help="max entries to show (0=all)")
    import_shellbags_parser.add_argument("--output", type=Path, help="optional JSON output path")
    import_shellbags_parser.add_argument("--summary", action="store_true", help="print summary of parsed entries")
    import_shellbags_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when the hive could not be fully read (still reported on stderr)",
    )

    # import-shimcache specific options
    import_shimcache_parser = commands.choices["import-shimcache"]
    import_shimcache_parser.add_argument("system_hive", type=Path, help="Path to SYSTEM registry hive")
    import_shimcache_parser.add_argument("--max-entries", type=int, default=0, help="max entries to show (0=all)")
    import_shimcache_parser.add_argument("--output", type=Path, help="optional JSON output path")
    import_shimcache_parser.add_argument("--summary", action="store_true", help="print summary of parsed entries")
    import_shimcache_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when the hive could not be fully read (still reported on stderr)",
    )

    # import-amcache specific options
    import_amcache_parser = commands.choices["import-amcache"]
    import_amcache_parser.add_argument("amcache_hve", type=Path, help="Path to Amcache.hve file")
    import_amcache_parser.add_argument("--max-entries", type=int, default=0, help="max entries to show (0=all)")
    import_amcache_parser.add_argument("--output", type=Path, help="optional JSON output path")
    import_amcache_parser.add_argument("--summary", action="store_true", help="print summary of parsed entries")
    import_amcache_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when the hive could not be fully read (still reported on stderr)",
    )

    # import-prefetch specific options
    import_prefetch_parser = commands.choices["import-prefetch"]
    import_prefetch_parser.add_argument("target", type=Path, help="Prefetch file or directory")
    import_prefetch_parser.add_argument("--max-files", type=int, default=0, help="max files to parse (0=all)")
    import_prefetch_parser.add_argument("--output", type=Path, help="optional JSON output path")
    import_prefetch_parser.add_argument("--summary", action="store_true", help="print summary of parsed records")
    import_prefetch_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when some files failed or degraded (still reported on stderr)",
    )

    # import-mft specific options
    import_mft_parser = commands.choices["import-mft"]
    import_mft_parser.add_argument("mft_file", type=Path, help="Path to NTFS $MFT binary file")
    import_mft_parser.add_argument("--max-records", type=int, default=0, help="max records to parse (0=all)")
    import_mft_parser.add_argument("--output", type=Path, help="optional JSON output path")
    import_mft_parser.add_argument("--summary", action="store_true", help="print summary of parsed records")
    import_mft_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when some records failed to parse (still reported on stderr)",
    )

    # import-plaso specific options
    import_parser = commands.choices["import-plaso"]
    import_parser.add_argument("plaso_csv", type=Path, help="Plaso l2tcsv export file")
    import_parser.add_argument("-o", "--output", type=Path, required=True, help="output enriched case file")
    import_parser.add_argument("--mappings", type=Path, help="optional custom mappings JSON file")
    import_parser.add_argument("--evidence-prefix", default="case://import/plaso", help="evidence ref prefix")
    import_parser.add_argument("--max-rows", type=int, default=1_000_000, help="max rows to process")
    import_parser.add_argument("--diagnostics", type=Path, help="write diagnostics JSON to file")

    # seal-specific options
    seal_parser = commands.choices["seal"]
    seal_parser.add_argument(
        "-o", "--output", type=Path, help="output path for sealed bundle (default: stdout)"
    )
    seal_parser.add_argument(
        "--engine-attestation", action="store_true",
        help="include engine_attestation_hash (hashes source + deps)"
    )

    # verify-specific options
    verify_parser = commands.choices["verify"]
    verify_parser.add_argument(
        "--strict", "-s", action="store_true", help="require Level 3 (fully compliant)"
    )
    verify_parser.add_argument(
        "--verbose", "-v", action="store_true"
    )
    verify_parser.add_argument(
        "--json", action="store_true", help="JSON output"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify":
        return _cmd_verify(args)

    if args.command == "import-plaso":
        return _cmd_import_plaso(args)

    if args.command == "import-mft":
        return _cmd_import_mft(args)

    if args.command == "import-prefetch":
        return _cmd_import_prefetch(args)

    if args.command == "import-amcache":
        return _cmd_import_amcache(args)

    if args.command == "import-shimcache":
        return _cmd_import_shimcache(args)

    if args.command == "import-shellbags":
        return _cmd_import_shellbags(args)

    if args.command == "rivals":
        return _cmd_rivals(args)

    try:
        analyzer, activity_count, observation_count = load_case_file(args.case_file)
        result = analyzer.analyze()
    except (CaseFileError, OSError, TypeError, ValueError) as exc:
        print(f"siberian: error: {_safe_display(str(exc))}", file=sys.stderr)
        return 2

    if args.command == "validate":
        print(
            f"Valid case: {activity_count} activities, {observation_count} explicit "
            f"observations, {result.expected_count} catalog expectations."
        )
    elif args.command == "analyze":
        print(json.dumps(_result_payload(result), ensure_ascii=False, indent=2))
    elif args.command == "seal":
        return _cmd_seal(analyzer, result, args)
    else:
        print(_explain(result))
    return 0


def _result_payload(result: SilenceAnalysisResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "catalog_version": result.catalog_version,
        "context": {
            "os_profile": result.context.os_profile,
            "os_release": result.context.os_release,
            "system_build": result.context.system_build,
            "os_edition": result.context.os_edition,
            "architecture": result.context.architecture,
            "build_revision": result.context.build_revision,
            "servicing_channel": result.context.servicing_channel,
            "scope": result.context.scope,
            "interval_start": _time(result.context.interval_start),
            "interval_end": _time(result.context.interval_end),
            "acquisition_ref": result.context.acquisition_ref,
        },
        "counts": {
            "expected": result.expected_count,
            "present": result.present_count,
            "confirmed_absent": result.confirmed_absent_count,
            "unknown": result.unknown_count,
            "out_of_scope": result.out_of_scope_count,
            "known": result.known_count,
        },
        "audit_hash": result.audit_hash,
        "records": [_record_payload(record) for record in result.records],
        "interpretation": (
            "Descriptive evidence matrix only. Absence does not establish deletion, "
            "tampering, attribution, or intent."
        ),
    }


def _record_payload(record: SilenceRecord) -> dict[str, object]:
    entry = record.expected_artifact
    observation = record.observation
    action_evidence = record.action_evidence
    return {
        "action": record.action,
        "artifact_type": entry.artifact_type,
        "description": entry.description,
        "scope": entry.scope,
        "required_conditions": list(entry.required_conditions),
        "retention": entry.retention,
        "interpretation_limit": entry.interpretation_limit,
        "source_refs": [
            {"title": title, "url": url} for title, url in entry.source_refs
        ],
        "status": observation.status.value,
        "reason": observation.reason.value if observation.reason else None,
        "evidence_ref": observation.evidence_ref,
        "primary_action_evidence": (
            {
                "evidence_ref": action_evidence.evidence_ref,
                "observed_at": _time(action_evidence.observed_at),
            }
            if action_evidence else None
        ),
        "condition_evidence": [
            {
                "condition": name,
                "evidence_ref": evidence.evidence_ref,
                "valid_from": _time(evidence.valid_from),
                "valid_until": _time(evidence.valid_until),
            }
            for name, evidence in observation.condition_evidence
        ],
    }


def _explain(result: SilenceAnalysisResult) -> str:
    lines = [
        f"SIBERIAN {result.schema_version} · catalog {result.catalog_version}",
        f"Case scope: {_safe_display(result.context.scope)}",
        f"Acquisition: {_safe_display(result.context.acquisition_ref)}",
        f"Interval: {_time(result.context.interval_start)} — {_time(result.context.interval_end)}",
        f"Coverage: {result.present_count} present, {result.confirmed_absent_count} confirmed absent, "
        f"{result.unknown_count} unknown, {result.out_of_scope_count} out of scope.",
        f"Digest: {result.audit_hash}",
    ]
    for record in result.records:
        observation = record.observation
        lines.append("")
        lines.append(f"{record.action} / {record.expected_artifact.artifact_type}: {observation.status.value}")
        if observation.reason:
            lines.append(f"  Reason: {observation.reason.value}")
        if observation.evidence_ref:
            lines.append(f"  Evidence: {_safe_display(observation.evidence_ref)}")
        if record.action_evidence:
            lines.append(
                "  Primary action: "
                f"{_safe_display(record.action_evidence.evidence_ref)} at "
                f"{_time(record.action_evidence.observed_at)}"
            )
        for name, evidence in observation.condition_evidence:
            lines.append(
                f"  Condition {name}: {_safe_display(evidence.evidence_ref)} "
                f"[{_time(evidence.valid_from)} .. {_time(evidence.valid_until)}]"
            )
        if observation.status.value == "unknown":
            covered = {name for name, _ in observation.condition_evidence}
            missing = sorted(set(record.expected_artifact.required_conditions) - covered)
            if missing:
                lines.append(f"  Applicability evidence still needed: {', '.join(missing)}")
            next_check = _NEXT_CHECKS.get(
                observation.reason,
                "review source coverage and applicability; preserve UNKNOWN until evidence resolves it",
            )
            lines.append(f"  Suggested next check: {next_check}")
            lines.append("  Do not interpret this row as evidence that an artifact was deleted.")
        lines.append(f"  Catalog scope: {record.expected_artifact.scope}")
        lines.append("  Sources:")
        lines.extend(f"    - {title}: {url}" for title, url in record.expected_artifact.source_refs)
    lines.extend(("", "This matrix does not establish deletion, tampering, attribution, or intent."))
    return "\n".join(lines)


def _time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _safe_display(value: str) -> str:
    """Escape terminal control/format characters in analyst-supplied text."""
    return "".join(
        char if not unicodedata.category(char).startswith("C") else f"\\u{ord(char):04x}"
        for char in value
    )


def _cmd_seal(analyzer, result: SilenceAnalysisResult, args) -> int:
    """Produce a tamper-evident sealed bundle from a case file."""
    engine_attestation_hash = ""
    if args.engine_attestation:
        engine_attestation_hash = BundleBuilder.compute_engine_attestation()

    tool_log_tip = None  # Could be extended to accept tool log from file

    sealed = analyzer.seal(result, engine_attestation_hash, tool_log_tip)

    if args.output:
        file_hash = BundleBuilder.save(sealed, str(args.output))
        print(f"Sealed bundle written to {args.output} (file hash: {file_hash})", file=sys.stderr)
    else:
        print(json.dumps(sealed, ensure_ascii=False, indent=2))
    return 0


def _cmd_verify(args) -> int:
    """Verify a sealed bundle using the standalone stdlib-only verifier."""
    from .verify import verify_bundle, VerificationResult

    try:
        with open(args.case_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except FileNotFoundError:
        print(f"siberian: error: not found: {args.case_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"siberian: error: invalid JSON: {e}", file=sys.stderr)
        return 1

    result = verify_bundle(bundle, strict=args.strict, verbose=args.verbose)

    if args.json:
        print(result.to_json())
    else:
        d = result.to_dict()
        status = "PASS" if result.passed else "FAIL"
        print(f"\n{'='*60}")
        print(f"  SIBERIAN — Independent Verifier")
        print(f"{'='*60}")
        print(f"  Result      : {status}")
        print(f"  Conformity  : Level {result.conformity_level} — {d['conformity_label']}")
        print(f"  Timestamp   : {result.timestamp}")
        s = d["summary"]
        print(f"  Checks      : {s['passed']}/{s['total']} OK")
        print(f"{'='*60}")

        if args.verbose or not result.passed:
            print()
            for check in result.checks:
                icon = "OK  " if check["passed"] else ("FAIL" if check["severity"] == "ERROR" else "WARN")
                print(f"  [{icon}] {check['rule']}")
                print(f"          {check['message']}")
                if check.get("detail") and args.verbose:
                    for v in (check["detail"] if isinstance(check["detail"], list) else [check["detail"]]):
                        print(f"          > {v}")

        if not result.passed:
            print("\n  CRITICAL FAILURES:")
            for fail in result.critical_failures():
                print(f"    - {fail['rule']}: {fail['message']}")
            print()

    return 0 if result.passed else 1


def _cmd_import_plaso(args) -> int:
    """Import Plaso l2tcsv as UNKNOWN (conditions_unverified) observations into a case file."""
    mappings = get_default_mappings()
    if args.mappings:
        with args.mappings.open("r", encoding="utf-8") as f:
            custom = json.load(f)
        mappings = [PlasoToSiberianMapping(**m) for m in custom]

    importer = PlasoImporter(
        mappings=mappings,
        evidence_ref_prefix=args.evidence_prefix,
        max_rows=args.max_rows,
    )

    try:
        case, diagnostics = importer.import_file(
            args.plaso_csv, args.case_file, args.output
        )
        print(f"Import complete: {diagnostics.unknown_conditions_created} UNKNOWN (conditions_unverified) observations created")
        print(f"  Total rows: {diagnostics.total_rows}")
        print(f"  Matched: {diagnostics.matched_rows}")
        print(f"  Unmatched: {diagnostics.unmatched_rows}")
        print(f"  Rejected: {diagnostics.rejected_rows}")
        print(f"  Output: {args.output}")

        if args.diagnostics:
            args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
            payload = diagnostics.to_dict()
            # Level 6 requires the parser version and transformations to travel
            # with the run; Plaso recorded neither.
            payload["provenance"] = build_provenance(
                PLASO_SPEC,
                [args.plaso_csv, args.case_file],
                extra={
                    "mappings_used": diagnostics.mappings_used,
                    "total_rows": diagnostics.total_rows,
                    "matched_rows": diagnostics.matched_rows,
                    "unmatched_rows": diagnostics.unmatched_rows,
                    "rejected_rows": diagnostics.rejected_rows,
                    "observations_created": diagnostics.observations_created,
                    "unknown_conditions_created": diagnostics.unknown_conditions_created,
                },
            )
            with args.diagnostics.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"  Diagnostics: {args.diagnostics}")

        if diagnostics.errors:
            print(f"  Errors: {len(diagnostics.errors)} (see diagnostics)", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Import failed: {e}", file=sys.stderr)
        return 1

    return 0


def _cmd_rivals(args) -> int:
    """Evaluate rival hypotheses against an analysis result from a case file."""
    try:
        analyzer, activity_count, observation_count = load_case_file(args.case_file)
        result = analyzer.analyze()
    except (CaseFileError, OSError, TypeError, ValueError) as exc:
        print(f"siberian: error: {_safe_display(str(exc))}", file=sys.stderr)
        return 2

    rival_result = analyze_rivals(result)
    print(format_rival_report(rival_result))
    return 0


def _cmd_import_shellbags(args) -> int:
    """Parse Shellbags from a registry hive."""
    try:
        entries = parse_shellbags_from_registry(args.hive_path, bag_type=args.bag_type)
        parsed = [e for e in entries if not e.error]
        print(f"Parsed {len(parsed)} Shellbag entries from {args.hive_path} ({args.bag_type})")

        if args.summary:
            for entry in entries[:args.max_entries or 100]:
                print(format_shellbag_summary(entry))
            if args.max_entries > 0 and len(entries) > args.max_entries:
                print(f"... and {len(entries) - args.max_entries} more")

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "provenance": build_provenance(
                    SHELLBAGS_SPEC,
                    [args.hive_path],
                    extra={
                        "bag_type": args.bag_type,
                        "entries_parsed": len(parsed),
                    },
                ),
                "entries": [e.to_dict() for e in entries],
            }
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"JSON output written to {args.output}")

        if not args.summary and not args.output:
            for entry in entries[:50]:
                print(format_shellbag_summary(entry))
            if len(entries) > 50:
                print(f"... and {len(entries) - 50} more")

        # Same contract as the other adapters: a failed or degraded parse is
        # not a success.
        failures = [e for e in entries if e.error]
        if failures:
            for entry in failures:
                print(f"siberian: {entry.error}", file=sys.stderr)
            if not args.allow_partial:
                return 1
            print(
                "siberian: accepting partial result because --allow-partial was given",
                file=sys.stderr,
            )
        return 0
    except Exception as e:
        print(f"siberian: error importing Shellbags: {e}", file=sys.stderr)
        return 2


def _cmd_import_shimcache(args) -> int:
    """Parse AppCompatCache (Shimcache) from SYSTEM hive."""
    try:
        entries = parse_shimcache_from_registry(args.system_hive)
        parsed = [e for e in entries if not e.error]
        print(f"Parsed {len(parsed)} Shimcache entries from {args.system_hive}")

        if args.summary:
            for entry in entries[:args.max_entries or 100]:
                print(format_shimcache_summary(entry))
            if args.max_entries > 0 and len(entries) > args.max_entries:
                print(f"... and {len(entries) - args.max_entries} more")

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "provenance": build_provenance(
                    SHIMCACHE_SPEC,
                    [args.system_hive],
                    extra={
                        "entries_parsed": len(parsed),
                        "parse_methods": sorted({e.parse_method for e in parsed}),
                        "control_sets": sorted(
                            {e.control_set for e in parsed if e.control_set}
                        ),
                    },
                ),
                "entries": [e.to_dict() for e in entries],
            }
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"JSON output written to {args.output}")

        if not args.summary and not args.output:
            for entry in entries[:50]:
                print(format_shimcache_summary(entry))
            if len(entries) > 50:
                print(f"... and {len(entries) - 50} more")

        # A failed or degraded parse must not exit 0. A previous revision
        # printed "Parsed 1 entries" and returned 0 for a missing hive.
        failures = [e for e in entries if e.error or e.degraded]
        if failures:
            for entry in failures:
                print(
                    f"siberian: {entry.error or entry.degraded}",
                    file=sys.stderr,
                )
            if not args.allow_partial:
                return 1
            print(
                "siberian: accepting partial result because --allow-partial was given",
                file=sys.stderr,
            )
        return 0
    except Exception as e:
        print(f"siberian: error importing Shimcache: {e}", file=sys.stderr)
        return 2


def _cmd_import_amcache(args) -> int:
    """Parse Windows Amcache.hve and produce summary/JSON output."""
    try:
        result = parse_amcache_hive(args.amcache_hve)
        entries = result.entries

        for message in result.errors:
            print(f"siberian: {message}", file=sys.stderr)
        if result.degraded:
            print(f"siberian: {result.degraded}", file=sys.stderr)

        print(f"Parsed {len(entries)} Amcache entries from {args.amcache_hve}")
        if result.sections_found:
            print(f"  sections found : {', '.join(result.sections_found)}")
        if result.sections_absent:
            print(f"  sections absent: {', '.join(result.sections_absent)}")
        if result.errors or result.degraded:
            print(f"  errors={len(result.errors)} degraded={1 if result.degraded else 0}")

        if args.summary:
            for entry in entries[:args.max_entries or 100]:
                print(format_amcache_summary(entry))
            if args.max_entries > 0 and len(entries) > args.max_entries:
                print(f"... and {len(entries) - args.max_entries} more")

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "provenance": build_provenance(
                    AMCACHE_SPEC,
                    [args.amcache_hve],
                    extra={
                        "entries_parsed": len(entries),
                        "sections_found": result.sections_found,
                        "sections_absent": result.sections_absent,
                        "degraded": result.degraded,
                    },
                ),
                "entries": [e.to_dict() for e in entries],
                "sections_found": result.sections_found,
                "sections_absent": result.sections_absent,
                "errors": result.errors,
                "degraded": result.degraded,
            }
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"JSON output written to {args.output}")

        if not args.summary and not args.output:
            for entry in entries[:50]:
                print(format_amcache_summary(entry))
            if len(entries) > 50:
                print(f"... and {len(entries) - 50} more")

        # A hive that could not be read must not exit 0. The previous revision
        # printed "Parsed 1 entries" and returned 0 for a missing file.
        if result.errors or result.degraded:
            if not args.allow_partial:
                return 1
            print(
                "siberian: accepting partial result because --allow-partial was given",
                file=sys.stderr,
            )
        return 0
    except Exception as e:
        print(f"siberian: error importing Amcache: {e}", file=sys.stderr)
        return 2


def _cmd_import_prefetch(args) -> int:
    """Parse Windows Prefetch files and produce summary/JSON output."""
    try:
        stats: Dict[str, int] = {}
        if args.target.is_file():
            record = parse_prefetch_file(args.target)
            records = [record]
            stats = {
                "available": 1,
                "processed": 1,
                "truncated": 0,
                "max_files": args.max_files,
                "parsed": 0 if (record.error or record.degraded) else 1,
                "errors": 1 if record.error else 0,
                "degraded": 1 if record.degraded else 0,
                "total": 1,
            }
        elif args.target.is_dir():
            records, stats = parse_prefetch_directory(args.target, max_files=args.max_files)
        else:
            print(f"siberian: error: {args.target} is not a file or directory", file=sys.stderr)
            return 2

        print(f"Parsed {len(records)} Prefetch record(s)")

        # A partial parse must never be reported as a clean success.
        if stats:
            print(
                f"  available={stats.get('available')} "
                f"processed={stats.get('processed')} "
                f"truncated={stats.get('truncated')} "
                f"parsed={stats['parsed']} errors={stats['errors']} "
                f"degraded={stats['degraded']}"
            )
        if stats.get("truncated"):
            print(
                f"siberian: {stats['truncated']} file(s) were NOT parsed because "
                f"--max-files={args.max_files} was reached; this is a partial result",
                file=sys.stderr,
            )
        for record in records:
            if record.error:
                print(f"siberian: {record.filename}: {record.error}", file=sys.stderr)
            elif record.degraded:
                print(f"siberian: {record.filename}: {record.degraded}", file=sys.stderr)
            if record.filename_matches_content is False:
                print(
                    f"siberian: {record.filename}: filename hash {record.stem_hash} "
                    f"does not match content hash {record.prefetch_hash}",
                    file=sys.stderr,
                )

        if args.summary:
            for record in records[:100]:
                print(format_prefetch_summary(record))
            if len(records) > 100:
                print(f"... and {len(records) - 100} more")

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "provenance": build_provenance(
                    PREFETCH_SPEC, [args.target], extra={"stats": stats}
                ),
                "records": [r.to_dict() for r in records],
            }
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"JSON output written to {args.output}")

        if not args.summary and not args.output:
            for record in records[:50]:
                print(format_prefetch_summary(record))
            if len(records) > 50:
                print(f"... and {len(records) - 50} more")

        # Nonzero when any file failed or degraded, so a caller cannot mistake
        # a partial parse for a complete one. --allow-partial downgrades this
        # to a warning for batch triage.
        incomplete = (
            stats.get("errors", 0)
            + stats.get("degraded", 0)
            + (stats.get("truncated", 0) or 0)
        )
        if incomplete and not args.allow_partial:
            denominator = stats.get("available") or stats.get("total") or len(records)
            reasons = []
            if stats.get("errors"):
                reasons.append(f"{stats['errors']} failed")
            if stats.get("degraded"):
                reasons.append(f"{stats['degraded']} degraded")
            if stats.get("truncated"):
                reasons.append(f"{stats['truncated']} not parsed (limit)")
            print(
                f"siberian: {denominator} file(s) available, "
                f"{stats.get('processed', len(records))} processed; "
                + ", ".join(reasons)
                + ". Re-run with --allow-partial to accept a partial result.",
                file=sys.stderr,
            )
            return 1
        return 0
    except Exception as e:
        print(f"siberian: error importing Prefetch: {e}", file=sys.stderr)
        return 2


def _cmd_import_mft(args) -> int:
    """Parse NTFS $MFT records and produce summary/JSON output."""
    try:
        mft_stats: Dict[str, object] = {}
        records = parse_mft_file(
            args.mft_file, max_records=args.max_records, stats=mft_stats
        )
        print(f"Parsed {len(records)} records from {args.mft_file}")
        if mft_stats.get("available") is not None:
            print(
                f"  available={mft_stats['available']} "
                f"processed={mft_stats['processed']} "
                f"truncated={mft_stats['truncated']} "
                f"record_size={mft_stats['record_size']}"
            )
        if mft_stats.get("truncated"):
            print(
                f"siberian: {mft_stats['truncated']} record(s) were NOT parsed "
                f"because --max-records={args.max_records} was reached; this is "
                f"a partial result",
                file=sys.stderr,
            )

        if args.summary:
            for record in records[:100]:
                print(format_mft_record_summary(record))
            if len(records) > 100:
                print(f"... and {len(records) - 100} more")

        invalid = [r for r in records if not r.is_valid]

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "provenance": build_provenance(
                    MFT_SPEC,
                    [args.mft_file],
                    extra={
                        "records_parsed": len(records),
                        "records_invalid": len(invalid),
                        "record_size": records[0].allocated_size if records else None,
                        "available": mft_stats.get("available"),
                        "processed": mft_stats.get("processed"),
                        "truncated": mft_stats.get("truncated"),
                        "max_records": args.max_records,
                        "invalid_sample": [
                            {"expected_record_number": r.expected_record_number,
                             "error": r.error}
                            for r in invalid[:10]
                        ],
                    },
                ),
                "records": [r.to_dict() for r in records],
            }
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"JSON output written to {args.output}")

        if not args.summary and not args.output:
            # Default: print summary
            for record in records[:50]:
                print(format_mft_record_summary(record))
            if len(records) > 50:
                print(f"... and {len(records) - 50} more")

        # Invalid records are a partial result, not a clean parse. They are
        # always reported; --allow-partial only governs the exit code.
        if invalid or mft_stats.get("truncated"):
            if invalid:
                print(
                    f"  {len(invalid)} of {len(records)} record(s) did not parse",
                    file=sys.stderr,
                )
            for record in invalid[:10]:
                print(
                    f"siberian: record {record.expected_record_number}: {record.error}",
                    file=sys.stderr,
                )
            if not args.allow_partial:
                print(
                    "siberian: re-run with --allow-partial to accept a partial result",
                    file=sys.stderr,
                )
                return 1
            print(
                "siberian: accepting partial result because --allow-partial was given",
                file=sys.stderr,
            )
        return 0
    except Exception as e:
        print(f"siberian: error importing MFT: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
