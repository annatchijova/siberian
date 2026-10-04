# SIBERIAN — Technical README

[English](README.md) · [Español](README_ES.md) · **Technical**

## Status and scope

This repository contains a first standalone Python library port of VIGÍA's adversarial-silence pattern. It has no command-line interface, calibrated statistical model, or validation corpus. It returns an evidence matrix and coverage counts; it does not issue a forensic verdict.

The seed is VIGÍA idea 24, supported there by `vigia/patterns/adversarial_silence.py` and `vigia/tools/temporal_drift.py`. The source catalogue describes the idea as comparing selective loss of difficult-to-erase artifacts with easier-to-erase artifacts. SIBERIAN treats this as a hypothesis to investigate, not an attribution method.

## Current API and inputs

The library API is in `siberian/adversarial_silence.py`. Each analysis requires a declared system and acquisition context: OS release/build, scope, time interval, and acquisition reference. Callers then register cataloged actions and attach observations to an `(action, artifact_type)` pair:

```python
from datetime import datetime, timezone
from siberian import AnalysisContext, AdversarialSilenceAnalyzer, ArtifactStatus, ConditionEvidence

context = AnalysisContext(
    os_profile="windows", os_release="Windows 10", system_build="recorded-build",
    scope="host:case-123 / Security.evtx",
    interval_start=datetime(2026, 10, 1, tzinfo=timezone.utc),
    interval_end=datetime(2026, 10, 2, tzinfo=timezone.utc),
    acquisition_ref="case://acquisition/security.evtx",
)
detector = AdversarialSilenceAnalyzer(context)
detector.register_primary_action("process_execution")
detector.register_observation(
    "process_execution", "security_event_4688", ArtifactStatus.CONFIRMED_ABSENT,
    evidence_ref="case://acquisition/security.evtx/query-4688",
    condition_evidence={
        "audit_process_creation_enabled_for_interval": ConditionEvidence(
            "case://policy/auditpol",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
        "security_log_acquired_and_covers_interval": ConditionEvidence(
            "case://acquisition/security.evtx/coverage",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
    },
)
result = detector.analyze()
```

The versioned Windows catalog contains conditional entries for Security events 4688, 5156, 4624, 4634, and the NTFS USN change journal. The linked source set documents Windows 10; confirmed absences for other releases are rejected, while entries remain `UNKNOWN` with `catalog_scope_unverified`. Unsupported operating systems fail closed. Each entry lists applicability conditions, retention limits, interpretation limits, and primary documentation sources. The catalog is not yet a matrix across Windows 10 builds and policy configurations. See the [catalog review](docs/CATALOG_REVIEW.md).

Observations are `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN`, or `OUT_OF_SCOPE`. Unreported catalog entries default to `UNKNOWN` with `conditions_unverified`. Known states require an evidence reference. Confirmed absence additionally requires a `ConditionEvidence` reference for each entry-specific applicability condition; every condition interval must cover the complete analysis interval. These are caller-provided locators and declarations, not automatically verified evidence. Out-of-scope entries require a documented `not_applicable` reason and reference.

## Current analysis

The result includes expected, present, confirmed-absent, unknown, and out-of-scope counts; the complete records; declared context; catalog version; and a SHA-256 digest. Weighted scores were removed because their inherited ordinal weights had no empirical support. There is no composite score, threshold, or `PASS` / `WARN` / `ABSTAIN` decision.

## Source-code observations

The module is adapted from `vigia/patterns/adversarial_silence.py` in VIGÍA, under Apache-2.0; see [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Its expectation catalogues and ordinal weights are carried over as research assumptions.

The standalone port addresses representation and provenance issues from the source:

- Observations are associated with a specific action and artifact type.
- Unknown and out-of-scope artifacts remain distinct from known presence and confirmed absence.
- Unsupported OS profiles, actions, artifact identifiers, and conflicting observations raise errors.
- The probability-sounding `fabrication_likelihood` field is omitted.
- Each confirmed absence is gated on catalog applicability evidence.

Important limits remain: the catalog is not yet a version/configuration matrix and does not validate a declared Windows release/build; references are locators and validity declarations supplied by the caller; collection quality and artifact dependencies are not modeled; and there is no calibrated inference, rival-hypothesis comparison, CLI, or empirical validation. The SHA-256 digest covers the declared context, catalog version and entries, and observation/status/reference records, including validity intervals for condition evidence. It does not attest to truth or completeness and is not a sealed chain-of-custody report. The temporal-drift module is a separate VIGÍA subsystem and is not part of this port.

## Determinism, provenance, and integrity

The implementation sorts catalog entries and uses a fixed versioned JSON structure with sorted keys and compact separators before hashing its UTF-8 bytes with SHA-256. This is a deterministic digest for the current API payload. It is not a canonical manifest or an independent verifier format; schema/version evolution remains open.

## Threat and trust boundaries

API arguments are checked for supported action/artifact identifiers, valid states, and known condition names. There is not yet a manifest parser, input-size policy, acquisition metadata model, or typed source-reference format.

The analyst, acquisition process, clocks, expectation model, operating-system documentation, and chain-of-custody records are separate trust dependencies. SIBERIAN cannot infer completeness where those sources do not establish it.

## Planned validation

No tests or empirical evaluation are present in this repository yet. Before describing the detector as useful for forensic conclusions, validation should include at minimum:

- valid and incomplete applicability evidence for confirmed absences;
- mixtures of present, confirmed absent, unknown, and out-of-scope records;
- artifacts inapplicable under the declared platform/configuration;
- benign retention, disabled logging, sensor gaps, and acquisition failures;
- correlated artifact loss and duplicate/conflicting observations;
- stability of serialized output and hashes across repeated runs;
- blind cases with known provenance, including benign controls and selective-removal cases;
- empirical validation before any calibrated score or decision threshold.

The checks are not yet implemented or run.

## Open design decisions

- Version/configuration-specific source matrix and maintenance process for artifact expectations.
- Collection coverage and acquisition provenance model.
- Statistical model, thresholds, and evaluation corpus.
- Versioned manifest/output schema and independent verification format.
- Contribution terms.
- Whether `PASS` means “no selective-loss signal under this model” or something narrower; it must not imply proof that no tampering occurred.

The language decision is recorded in [`docs/decisions/language-selection.md`](docs/decisions/language-selection.md).

The product destination and construction gates are in the [Spanish level plan](docs/NIVELES.md).
