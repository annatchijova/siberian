"""Offline command-line interface for SIBERIAN case files."""
from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

from .adversarial_silence import (
    ObservationReason,
    SilenceAnalysisResult,
    SilenceRecord,
)
from .casefile import CaseFileError, load_case_file

_NEXT_CHECKS = {
    ObservationReason.CONDITIONS_UNVERIFIED: "document each required applicability condition across the full analysis interval",
    ObservationReason.CATALOG_SCOPE_UNVERIFIED: "verify the declared product/release against the catalog scope; retain UNKNOWN if unmatched",
    ObservationReason.NOT_COLLECTED: "determine whether the source can be acquired for the case interval",
    ObservationReason.RETENTION_GAP: "review retention/wrap limits and available forwarded or alternate sources",
    ObservationReason.ACQUISITION_GAP: "review acquisition coverage and supplement it from an available source if possible",
    ObservationReason.PARSER_FAILURE: "validate the parser and version against the acquired source before interpreting the row",
    ObservationReason.AMBIGUOUS: "seek an independent observation that discriminates the competing explanations",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="siberian",
        description="Review declared forensic evidence gaps; does not infer deletion or intent.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("validate", "validate a case file without producing a report"),
        ("analyze", "produce a deterministic JSON evidence matrix"),
        ("explain", "explain statuses and unresolved conditions in a case"),
    ):
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("case_file", type=Path, help="analyst-authored JSON case file")

    args = parser.parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
