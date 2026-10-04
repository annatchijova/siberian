from datetime import datetime, timedelta, timezone
import unittest

from siberian import (
    AnalysisContext,
    AdversarialSilenceAnalyzer,
    ArtifactStatus,
    ConditionEvidence,
    ObservationReason,
)


def make_context(**overrides: object) -> AnalysisContext:
    values: dict[str, object] = {
        "os_profile": "windows",
        "os_release": "Windows 10",
        "system_build": "26100",
        "scope": "host:case-123 / Security.evtx",
        "interval_start": datetime(2026, 10, 1, tzinfo=timezone.utc),
        "interval_end": datetime(2026, 10, 2, tzinfo=timezone.utc),
        "acquisition_ref": "case://acquisition/security.evtx",
    }
    values.update(overrides)
    return AnalysisContext(**values)  # type: ignore[arg-type]


def analyzer(context: AnalysisContext | None = None) -> AdversarialSilenceAnalyzer:
    instance = AdversarialSilenceAnalyzer(context or make_context())
    instance.register_primary_action("process_execution")
    return instance


def condition_evidence(ref: str) -> ConditionEvidence:
    return ConditionEvidence(
        evidence_ref=ref,
        valid_from=datetime(2026, 10, 1, tzinfo=timezone.utc),
        valid_until=datetime(2026, 10, 2, tzinfo=timezone.utc),
    )


class ContextualAnalysisTests(unittest.TestCase):
    def test_unrecorded_expectation_is_unknown(self) -> None:
        result = analyzer().analyze()
        self.assertEqual(result.expected_count, 1)
        self.assertEqual(result.unknown_count, 1)
        self.assertEqual(result.confirmed_absent_count, 0)

    def test_confirmed_absence_requires_all_applicability_references(self) -> None:
        instance = analyzer()
        with self.assertRaisesRegex(ValueError, "applicability condition"):
            instance.register_observation(
                "process_execution",
                "security_event_4688",
                ArtifactStatus.CONFIRMED_ABSENT,
                evidence_ref="case://query/4688",
            )

    def test_confirmed_absence_with_conditions_is_recorded(self) -> None:
        instance = analyzer()
        instance.register_observation(
            "process_execution",
            "security_event_4688",
            ArtifactStatus.CONFIRMED_ABSENT,
            evidence_ref="case://query/4688",
            condition_evidence={
                "audit_process_creation_enabled_for_interval": condition_evidence("case://policy/auditpol"),
                "security_log_acquired_and_covers_interval": condition_evidence("case://coverage/security"),
            },
        )
        result = instance.analyze()
        self.assertEqual(result.confirmed_absent_count, 1)
        self.assertEqual(result.unknown_count, 0)

    def test_condition_evidence_must_cover_analysis_interval(self) -> None:
        instance = analyzer()
        too_short = ConditionEvidence(
            evidence_ref="case://coverage/security",
            valid_from=datetime(2026, 10, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 10, 1, 12, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(ValueError, "complete analysis interval"):
            instance.register_observation(
                "process_execution",
                "security_event_4688",
                ArtifactStatus.CONFIRMED_ABSENT,
                evidence_ref="case://query/4688",
                condition_evidence={
                    "audit_process_creation_enabled_for_interval": condition_evidence("case://policy/auditpol"),
                    "security_log_acquired_and_covers_interval": too_short,
                },
            )

    def test_condition_evidence_rejects_non_datetime_endpoints(self) -> None:
        with self.assertRaisesRegex(TypeError, "datetime values"):
            ConditionEvidence(
                evidence_ref="case://coverage/security",
                valid_from="2026-10-01",  # type: ignore[arg-type]
                valid_until=datetime(2026, 10, 2, tzinfo=timezone.utc),
            )

    def test_digest_includes_context_and_normalizes_timezone(self) -> None:
        utc_result = analyzer(make_context()).analyze()
        offset_context = make_context(
            interval_start=datetime(2026, 10, 1, 3, tzinfo=timezone(timedelta(hours=3))),
            interval_end=datetime(2026, 10, 2, 3, tzinfo=timezone(timedelta(hours=3))),
        )
        offset_result = analyzer(offset_context).analyze()
        changed_scope_result = analyzer(make_context(scope="host:other / Security.evtx")).analyze()
        self.assertEqual(utc_result.audit_hash, offset_result.audit_hash)
        self.assertNotEqual(utc_result.audit_hash, changed_scope_result.audit_hash)

    def test_context_rejects_naive_or_reversed_intervals(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone"):
            make_context(interval_start=datetime(2026, 10, 1))
        with self.assertRaisesRegex(ValueError, "earlier"):
            make_context(
                interval_start=datetime(2026, 10, 2, tzinfo=timezone.utc),
                interval_end=datetime(2026, 10, 1, tzinfo=timezone.utc),
            )

    def test_unsupported_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported OS profile"):
            analyzer(make_context(os_profile="linux"))

    def test_undocumented_release_stays_unknown_and_rejects_absence(self) -> None:
        instance = analyzer(make_context(os_release="Windows 11 24H2"))
        record = instance.analyze().records[0]
        self.assertEqual(record.observation.status, ArtifactStatus.UNKNOWN)
        self.assertEqual(record.observation.reason, ObservationReason.CATALOG_SCOPE_UNVERIFIED)
        with self.assertRaisesRegex(ValueError, "do not document"):
            instance.register_observation(
                "process_execution",
                "security_event_4688",
                ArtifactStatus.CONFIRMED_ABSENT,
                evidence_ref="case://query/4688",
                condition_evidence={
                    "audit_process_creation_enabled_for_interval": condition_evidence("case://policy/auditpol"),
                    "security_log_acquired_and_covers_interval": condition_evidence("case://coverage/security"),
                },
            )


if __name__ == "__main__":
    unittest.main()
