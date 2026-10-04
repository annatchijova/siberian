"""Contextual evidence matrix for conditional artifact expectations.

This module records observations and collection conditions. It deliberately
does not calculate suspicion scores or decide whether an absence is malicious.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .catalog import CATALOG_VERSION, ExpectedArtifact, catalog_for_profile

ANALYSIS_SCHEMA_VERSION = "siberian-evidence-matrix-v3"


class ArtifactStatus(str, Enum):
    PRESENT = "present"
    CONFIRMED_ABSENT = "confirmed_absent"
    UNKNOWN = "unknown"
    OUT_OF_SCOPE = "out_of_scope"


class ObservationReason(str, Enum):
    CONDITIONS_UNVERIFIED = "conditions_unverified"
    CATALOG_SCOPE_UNVERIFIED = "catalog_scope_unverified"
    NOT_COLLECTED = "not_collected"
    RETENTION_GAP = "retention_gap"
    ACQUISITION_GAP = "acquisition_gap"
    PARSER_FAILURE = "parser_failure"
    AMBIGUOUS = "ambiguous"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class AnalysisContext:
    """Declared system, time interval, and acquired scope for one analysis."""

    os_profile: str
    os_release: str
    system_build: str | None
    scope: str
    interval_start: datetime
    interval_end: datetime
    acquisition_ref: str
    os_edition: str | None = None
    architecture: str | None = None
    build_revision: str | None = None
    servicing_channel: str | None = None

    def __post_init__(self) -> None:
        for name in ("os_profile", "os_release", "scope", "acquisition_ref"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.system_build is not None and (
            not isinstance(self.system_build, str) or not self.system_build.strip()
        ):
            raise ValueError("system_build must be a non-empty string or None")
        for name in ("os_edition", "architecture", "build_revision", "servicing_channel"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string or None")
        if not isinstance(self.interval_start, datetime) or not isinstance(
            self.interval_end, datetime
        ):
            raise TypeError("analysis interval endpoints must be datetime values")
        start = _as_utc(self.interval_start, "interval_start")
        end = _as_utc(self.interval_end, "interval_end")
        if start >= end:
            raise ValueError("interval_start must be earlier than interval_end")
        object.__setattr__(self, "os_profile", self.os_profile.strip().lower())
        object.__setattr__(self, "os_release", self.os_release.strip())
        object.__setattr__(self, "scope", self.scope.strip())
        object.__setattr__(self, "acquisition_ref", self.acquisition_ref.strip())
        object.__setattr__(self, "system_build", self.system_build.strip() if self.system_build else None)
        for name in ("os_edition", "architecture", "build_revision", "servicing_channel"):
            value = getattr(self, name)
            object.__setattr__(self, name, value.strip() if value is not None else None)
        object.__setattr__(self, "interval_start", start)
        object.__setattr__(self, "interval_end", end)


@dataclass(frozen=True)
class ConditionEvidence:
    """Analyst reference and declared validity interval for one condition."""

    evidence_ref: str
    valid_from: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_ref, str) or not self.evidence_ref.strip():
            raise ValueError("condition evidence_ref must be a non-empty string")
        if not isinstance(self.valid_from, datetime) or not isinstance(
            self.valid_until, datetime
        ):
            raise TypeError("condition validity endpoints must be datetime values")
        start = _as_utc(self.valid_from, "condition valid_from")
        end = _as_utc(self.valid_until, "condition valid_until")
        if start >= end:
            raise ValueError("condition valid_from must be earlier than valid_until")
        object.__setattr__(self, "evidence_ref", self.evidence_ref.strip())
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_until", end)

    def covers(self, context: AnalysisContext) -> bool:
        return (
            self.valid_from <= context.interval_start
            and self.valid_until >= context.interval_end
        )


@dataclass(frozen=True)
class ActionEvidence:
    """Reference and timestamp supporting one registered primary action."""

    evidence_ref: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_ref, str) or not self.evidence_ref.strip():
            raise ValueError("action evidence_ref must be a non-empty string")
        if not isinstance(self.observed_at, datetime):
            raise TypeError("action observed_at must be a datetime value")
        object.__setattr__(self, "evidence_ref", self.evidence_ref.strip())
        object.__setattr__(self, "observed_at", _as_utc(self.observed_at, "observed_at"))


@dataclass(frozen=True)
class Observation:
    status: ArtifactStatus
    evidence_ref: str | None = None
    reason: ObservationReason | None = None
    condition_evidence: tuple[tuple[str, ConditionEvidence], ...] = ()


@dataclass(frozen=True)
class SilenceRecord:
    action: str
    expected_artifact: ExpectedArtifact
    observation: Observation
    action_evidence: ActionEvidence | None = None


@dataclass(frozen=True)
class SilenceAnalysisResult:
    context: AnalysisContext
    catalog_version: str
    expected_count: int
    present_count: int
    confirmed_absent_count: int
    unknown_count: int
    out_of_scope_count: int
    audit_hash: str
    records: tuple[SilenceRecord, ...]
    schema_version: str = ANALYSIS_SCHEMA_VERSION

    @property
    def known_count(self) -> int:
        return self.present_count + self.confirmed_absent_count


class AdversarialSilenceAnalyzer:
    """Build an auditable matrix for source-backed, conditional expectations.

    A ``CONFIRMED_ABSENT`` observation requires evidence for the registered
    primary action, a reference to the acquired source/query, and references
    supporting every catalog condition. These are identifiers/locators, not a
    substitute for reviewing the underlying evidence.
    """

    def __init__(self, context: AnalysisContext) -> None:
        if not isinstance(context, AnalysisContext):
            raise TypeError("context must be an AnalysisContext")
        self._context = context
        self._catalog = catalog_for_profile(context.os_profile)
        self._entries_by_key = {
            (entry.action, entry.artifact_type): entry for entry in self._catalog
        }
        self._actions: set[str] = set()
        self._action_evidence: dict[str, ActionEvidence] = {}
        self._observations: dict[tuple[str, str], Observation] = {}

    def register_primary_action(
        self, action: str, *, evidence: ActionEvidence | None = None
    ) -> None:
        """Include a cataloged activity and, optionally, its supporting evidence."""
        if not isinstance(action, str):
            raise TypeError("action must be str")
        available = sorted({entry.action for entry in self._catalog})
        if action not in available:
            raise ValueError(
                f"unknown action {action!r}; known actions: {', '.join(available)}"
            )
        if evidence is not None:
            if not isinstance(evidence, ActionEvidence):
                raise TypeError("evidence must be an ActionEvidence or None")
            if not (
                self._context.interval_start
                <= evidence.observed_at
                <= self._context.interval_end
            ):
                raise ValueError("primary action evidence must fall within the analysis interval")
            previous = self._action_evidence.get(action)
            if previous is not None and previous != evidence:
                raise ValueError(f"conflicting primary action evidence for {action!r}")
            self._action_evidence[action] = evidence
        self._actions.add(action)

    def register_observation(
        self,
        action: str,
        artifact_type: str,
        status: ArtifactStatus | str,
        *,
        evidence_ref: str | None = None,
        condition_evidence: Mapping[str, ConditionEvidence] | None = None,
        reason: ObservationReason | str | None = None,
    ) -> None:
        """Record status and source references for one expected artifact.

        ``condition_evidence`` maps each catalog condition to an analyst-
        maintained reference and declared validity interval. The interval must
        cover the complete analysis interval. Do not put raw evidence or
        sensitive content here.
        """
        if not isinstance(action, str) or not isinstance(artifact_type, str):
            raise TypeError("action and artifact_type must be str")
        if action not in self._actions:
            raise ValueError(f"register action {action!r} before its observations")
        key = (action, artifact_type)
        entry = self._entries_by_key.get(key)
        if entry is None:
            raise ValueError(f"artifact {artifact_type!r} is not cataloged for {action!r}")
        try:
            parsed_status = ArtifactStatus(status)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid artifact status: {status!r}") from exc
        if reason is None:
            parsed_reason = None
        else:
            try:
                parsed_reason = ObservationReason(reason)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid observation reason: {reason!r}") from exc
        if evidence_ref is not None and (
            not isinstance(evidence_ref, str) or not evidence_ref.strip()
        ):
            raise ValueError("evidence_ref must be a non-empty reference or None")
        if condition_evidence is None:
            conditions: dict[str, str] = {}
        elif not isinstance(condition_evidence, Mapping):
            raise TypeError("condition_evidence must map conditions to ConditionEvidence")
        else:
            conditions = dict(condition_evidence)
        if any(
            not isinstance(name, str) or not isinstance(evidence, ConditionEvidence)
            for name, evidence in conditions.items()
        ):
            raise TypeError("condition names must be strings and values ConditionEvidence")
        unknown_conditions = set(conditions) - set(entry.required_conditions)
        if unknown_conditions:
            raise ValueError(f"unrecognized catalog conditions: {sorted(unknown_conditions)}")

        if parsed_status in {ArtifactStatus.PRESENT, ArtifactStatus.CONFIRMED_ABSENT}:
            if evidence_ref is None:
                raise ValueError(f"{parsed_status.value} requires an evidence_ref")
            if parsed_reason is not None:
                raise ValueError("known observations cannot have an unknown/out-of-scope reason")
        if parsed_status is ArtifactStatus.CONFIRMED_ABSENT:
            if action not in self._action_evidence:
                raise ValueError(
                    "confirmed absence requires evidence for the primary action"
                )
            if self._context.system_build is None:
                raise ValueError("confirmed absence requires a declared system_build")
            if not entry.supports_os_release(self._context.os_release):
                raise ValueError(
                    f"catalog sources do not document {self._context.os_release!r} "
                    f"for {artifact_type!r}"
                )
            missing = set(entry.required_conditions) - set(conditions)
            if missing:
                raise ValueError(
                    "confirmed absence requires evidence for every applicability condition; "
                    f"missing: {sorted(missing)}"
                )
            uncovered = sorted(
                name for name, evidence in conditions.items()
                if not evidence.covers(self._context)
            )
            if uncovered:
                raise ValueError(
                    "condition evidence does not cover the complete analysis interval; "
                    f"uncovered: {uncovered}"
                )
        if parsed_status is ArtifactStatus.OUT_OF_SCOPE:
            if parsed_reason is not ObservationReason.NOT_APPLICABLE or evidence_ref is None:
                raise ValueError("out_of_scope requires reason='not_applicable' and evidence_ref")
        if parsed_status is ArtifactStatus.UNKNOWN and parsed_reason is ObservationReason.NOT_APPLICABLE:
            raise ValueError("use out_of_scope when non-applicability is established")

        observation = Observation(
            status=parsed_status,
            evidence_ref=evidence_ref,
            reason=parsed_reason,
            condition_evidence=tuple(sorted(conditions.items())),
        )
        previous = self._observations.get(key)
        if previous is not None and previous != observation:
            raise ValueError(f"conflicting observations for {action}/{artifact_type}")
        self._observations[key] = observation

    def analyze(self) -> SilenceAnalysisResult:
        """Return the evidence matrix, coverage counts, and deterministic digest."""
        records = tuple(
            SilenceRecord(
                action=entry.action,
                expected_artifact=entry,
                action_evidence=self._action_evidence.get(entry.action),
                observation=self._observations.get(
                    (entry.action, entry.artifact_type),
                    Observation(
                        status=ArtifactStatus.UNKNOWN,
                        reason=(
                            ObservationReason.CONDITIONS_UNVERIFIED
                            if entry.supports_os_release(self._context.os_release)
                            else ObservationReason.CATALOG_SCOPE_UNVERIFIED
                        ),
                    ),
                ),
            )
            for entry in sorted(
                (item for item in self._catalog if item.action in self._actions),
                key=lambda item: (item.action, item.artifact_type),
            )
        )
        counts = {
            status: sum(record.observation.status is status for record in records)
            for status in ArtifactStatus
        }
        digest = _compute_analysis_hash(self._context, records)
        return SilenceAnalysisResult(
            context=self._context,
            catalog_version=CATALOG_VERSION,
            expected_count=len(records),
            present_count=counts[ArtifactStatus.PRESENT],
            confirmed_absent_count=counts[ArtifactStatus.CONFIRMED_ABSENT],
            unknown_count=counts[ArtifactStatus.UNKNOWN],
            out_of_scope_count=counts[ArtifactStatus.OUT_OF_SCOPE],
            audit_hash=digest,
            records=records,
            schema_version=ANALYSIS_SCHEMA_VERSION,
        )


def _entry_payload(entry: ExpectedArtifact) -> dict[str, object]:
    return {
        "action": entry.action,
        "artifact_type": entry.artifact_type,
        "description": entry.description,
        "scope": entry.scope,
        "required_conditions": list(entry.required_conditions),
        "retention": entry.retention,
        "interpretation_limit": entry.interpretation_limit,
        "source_refs": [list(item) for item in entry.source_refs],
        "documented_os_release_prefix": entry.documented_os_release_prefix,
    }


def _as_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return value.astimezone(timezone.utc)


def _context_payload(context: AnalysisContext) -> dict[str, str | None]:
    return {
        "os_profile": context.os_profile,
        "os_release": context.os_release,
        "system_build": context.system_build,
        "os_edition": context.os_edition,
        "architecture": context.architecture,
        "build_revision": context.build_revision,
        "servicing_channel": context.servicing_channel,
        "scope": context.scope,
        "interval_start": context.interval_start.isoformat(timespec="microseconds"),
        "interval_end": context.interval_end.isoformat(timespec="microseconds"),
        "acquisition_ref": context.acquisition_ref,
    }


def _action_evidence_payload(evidence: ActionEvidence | None) -> dict[str, str] | None:
    if evidence is None:
        return None
    return {
        "evidence_ref": evidence.evidence_ref,
        "observed_at": evidence.observed_at.isoformat(timespec="microseconds"),
    }


def _condition_payload(evidence: ConditionEvidence) -> dict[str, str]:
    return {
        "evidence_ref": evidence.evidence_ref,
        "valid_from": evidence.valid_from.isoformat(timespec="microseconds"),
        "valid_until": evidence.valid_until.isoformat(timespec="microseconds"),
    }


def _compute_analysis_hash(
    context: AnalysisContext, records: tuple[SilenceRecord, ...]
) -> str:
    payload = {
        "schema": ANALYSIS_SCHEMA_VERSION,
        "catalog_version": CATALOG_VERSION,
        "context": _context_payload(context),
        "records": [
            {
                "expectation": _entry_payload(record.expected_artifact),
                "action_evidence": _action_evidence_payload(record.action_evidence),
                "status": record.observation.status.value,
                "evidence_ref": record.observation.evidence_ref,
                "reason": (
                    record.observation.reason.value
                    if record.observation.reason is not None else None
                ),
                "condition_evidence": [
                    [name, _condition_payload(evidence)]
                    for name, evidence in record.observation.condition_evidence
                ],
            }
            for record in records
        ],
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
