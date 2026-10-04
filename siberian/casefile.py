"""Strict, dependency-free loader for analyst-authored SIBERIAN case files."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .adversarial_silence import (
    ActionEvidence,
    AdversarialSilenceAnalyzer,
    AnalysisContext,
    ConditionEvidence,
)

CASE_SCHEMA_VERSION = "siberian-case-v1"
MAX_CASE_FILE_BYTES = 5 * 1024 * 1024


class CaseFileError(ValueError):
    """Raised when a case file is malformed or violates the input contract."""


def load_case_file(path: str | Path) -> tuple[AdversarialSilenceAnalyzer, int, int]:
    """Load and validate a bounded JSON case file without reading evidence data.

    Returns the analyzer, number of declared activities, and number of explicit
    observations. JSON duplicate keys and unknown object fields are rejected.
    """
    case_path = Path(path)
    try:
        with case_path.open("rb") as case_stream:
            raw = case_stream.read(MAX_CASE_FILE_BYTES + 1)
    except OSError:
        raise
    if len(raw) > MAX_CASE_FILE_BYTES:
        raise CaseFileError(
            f"case file exceeds the {MAX_CASE_FILE_BYTES}-byte size limit"
        )
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaseFileError(f"invalid UTF-8 JSON: {exc}") from exc
    except RecursionError as exc:
        raise CaseFileError("case file exceeds the maximum JSON nesting depth") from exc

    root = _object(
        document,
        "case",
        required={"schema_version", "context", "activities"},
        allowed={"schema_version", "context", "activities"},
    )
    if root["schema_version"] != CASE_SCHEMA_VERSION:
        raise CaseFileError(
            f"unsupported schema_version {root['schema_version']!r}; "
            f"expected {CASE_SCHEMA_VERSION!r}"
        )
    context_data = _object(
        root["context"],
        "context",
        required={
            "os_profile", "os_release", "system_build", "scope",
            "interval_start", "interval_end", "acquisition_ref",
        },
        allowed={
            "os_profile", "os_release", "system_build", "scope",
            "interval_start", "interval_end", "acquisition_ref", "os_edition",
            "architecture", "build_revision", "servicing_channel",
        },
    )
    context_args = dict(context_data)
    context_args["interval_start"] = _timestamp(
        context_data["interval_start"], "context.interval_start"
    )
    context_args["interval_end"] = _timestamp(
        context_data["interval_end"], "context.interval_end"
    )
    try:
        context = AnalysisContext(**context_args)
        analyzer = AdversarialSilenceAnalyzer(context)
    except (TypeError, ValueError) as exc:
        raise CaseFileError(f"invalid context: {exc}") from exc

    activities = root["activities"]
    if not isinstance(activities, list) or not activities:
        raise CaseFileError("activities must be a non-empty array")
    seen_actions: set[str] = set()
    observation_count = 0
    for activity_index, activity_data in enumerate(activities):
        activity_path = f"activities[{activity_index}]"
        activity = _object(
            activity_data,
            activity_path,
            required={"action", "observations"},
            allowed={"action", "primary_action_evidence", "observations"},
        )
        action = activity["action"]
        if not isinstance(action, str) or not action.strip():
            raise CaseFileError(f"{activity_path}.action must be a non-empty string")
        action = action.strip()
        if action in seen_actions:
            raise CaseFileError(f"duplicate activity action: {action!r}")
        seen_actions.add(action)

        action_evidence = None
        if "primary_action_evidence" in activity:
            evidence_data = _object(
                activity["primary_action_evidence"],
                f"{activity_path}.primary_action_evidence",
                required={"evidence_ref", "observed_at"},
                allowed={"evidence_ref", "observed_at"},
            )
            action_evidence = ActionEvidence(
                evidence_data["evidence_ref"],
                _timestamp(
                    evidence_data["observed_at"],
                    f"{activity_path}.primary_action_evidence.observed_at",
                ),
            )
        try:
            analyzer.register_primary_action(action, evidence=action_evidence)
        except (TypeError, ValueError) as exc:
            raise CaseFileError(f"{activity_path}: {exc}") from exc

        observations = activity["observations"]
        if not isinstance(observations, list):
            raise CaseFileError(f"{activity_path}.observations must be an array")
        seen_artifacts: set[str] = set()
        for observation_index, observation_data in enumerate(observations):
            observation_path = f"{activity_path}.observations[{observation_index}]"
            observation = _object(
                observation_data,
                observation_path,
                required={"artifact_type", "status"},
                allowed={
                    "artifact_type", "status", "evidence_ref", "reason", "conditions"
                },
            )
            artifact_type = observation["artifact_type"]
            if not isinstance(artifact_type, str) or not artifact_type.strip():
                raise CaseFileError(
                    f"{observation_path}.artifact_type must be a non-empty string"
                )
            artifact_type = artifact_type.strip()
            if artifact_type in seen_artifacts:
                raise CaseFileError(
                    f"{observation_path}: duplicate artifact_type {artifact_type!r}"
                )
            seen_artifacts.add(artifact_type)

            status = observation["status"]
            reason = observation.get("reason")
            if status == "unknown" and reason is None:
                raise CaseFileError(
                    f"{observation_path}: an explicit unknown status requires a reason"
                )
            condition_data = observation.get("conditions", {})
            if not isinstance(condition_data, dict):
                raise CaseFileError(f"{observation_path}.conditions must be an object")
            conditions: dict[str, ConditionEvidence] = {}
            for condition_name, condition_item in condition_data.items():
                condition = _object(
                    condition_item,
                    f"{observation_path}.conditions.{condition_name}",
                    required={"evidence_ref", "valid_from", "valid_until"},
                    allowed={"evidence_ref", "valid_from", "valid_until"},
                )
                conditions[condition_name] = ConditionEvidence(
                    condition["evidence_ref"],
                    _timestamp(
                        condition["valid_from"],
                        f"{observation_path}.conditions.{condition_name}.valid_from",
                    ),
                    _timestamp(
                        condition["valid_until"],
                        f"{observation_path}.conditions.{condition_name}.valid_until",
                    ),
                )
            try:
                analyzer.register_observation(
                    action,
                    artifact_type,
                    status,
                    evidence_ref=observation.get("evidence_ref"),
                    condition_evidence=conditions,
                    reason=reason,
                )
            except (TypeError, ValueError) as exc:
                raise CaseFileError(f"{observation_path}: {exc}") from exc
            observation_count += 1

    return analyzer, len(activities), observation_count


def _object(
    value: Any, path: str, *, required: set[str], allowed: set[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CaseFileError(f"{path} must be an object")
    keys = set(value)
    missing = required - keys
    extra = keys - allowed
    if missing:
        raise CaseFileError(f"{path} is missing fields: {sorted(missing)}")
    if extra:
        raise CaseFileError(f"{path} has unknown fields: {sorted(extra)}")
    return value


def _timestamp(value: Any, path: str):
    if not isinstance(value, str) or not value.strip():
        raise CaseFileError(f"{path} must be an ISO 8601 timestamp with a timezone")
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CaseFileError(f"{path} is not a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CaseFileError(f"{path} must include a timezone")
    return parsed


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaseFileError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise CaseFileError(f"invalid JSON constant: {value}")
