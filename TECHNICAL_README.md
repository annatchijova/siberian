# SIBERIAN — Technical README

[English](README.md) · [Español](README_ES.md) · **Technical**

## Status and scope

This repository contains a standalone Python library port of VIGÍA's adversarial-silence pattern and an early offline CLI for analyst-authored JSON cases. It has no calibrated statistical model, operational validation corpus, or empirical Windows validation. It returns an evidence matrix and coverage counts; it does not issue a forensic verdict.

The seed is VIGÍA idea 24, whose catalogue entry names `vigia/patterns/adversarial_silence.py` and `vigia/tools/temporal_drift.py`. Code review shows that only the first implements the adversarial-silence calculation; `temporal_drift.py` is a separate timestamp-consistency tool and does not feed or validate it. See the [VIGÍA source excavation](docs/VIGIA_SOURCE_EXCAVATION.md). SIBERIAN treats selective loss as a hypothesis to investigate, not an attribution method.

## Current API and inputs

The library API is in `siberian/adversarial_silence.py`. Each analysis requires a declared system and acquisition context: OS release/build, scope, time interval, and acquisition reference. Callers then register cataloged actions and attach observations to an `(action, artifact_type)` pair:

```python
from datetime import datetime, timezone
from siberian import ActionEvidence, AnalysisContext, AdversarialSilenceAnalyzer, ArtifactStatus, ConditionEvidence

context = AnalysisContext(
    os_profile="windows", os_release="Windows 10", system_build="recorded-build",
    os_edition="recorded-edition", architecture="recorded-architecture",
    build_revision="recorded-revision", servicing_channel="recorded-channel",
    scope="host:case-123 / Security.evtx",
    interval_start=datetime(2026, 10, 1, tzinfo=timezone.utc),
    interval_end=datetime(2026, 10, 2, tzinfo=timezone.utc),
    acquisition_ref="case://acquisition/security.evtx",
)
detector = AdversarialSilenceAnalyzer(context)
detector.register_primary_action(
    "process_execution",
    evidence=ActionEvidence(
        "case://corroboration/process-execution",
        datetime(2026, 10, 1, 12, tzinfo=timezone.utc),
    ),
)
detector.register_observation(
    "process_execution", "security_event_4688", ArtifactStatus.CONFIRMED_ABSENT,
    evidence_ref="case://acquisition/security.evtx/query-4688",
    condition_evidence={
        "host_build_matches_documented_catalog_scope": ConditionEvidence(
            "case://host/build-and-event-schema",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
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

Observations are `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN`, or `OUT_OF_SCOPE`. Unreported catalog entries default to `UNKNOWN` with `conditions_unverified`. Known states require an evidence reference. Confirmed absence also requires timestamped `ActionEvidence` for the primary action inside the analysis interval, a declared OS build, a reference to the acquired source/query, and a `ConditionEvidence` reference for each entry-specific applicability condition, including an analyst attestation that the host build is within catalog scope. Every condition interval must cover the complete analysis interval. The program checks that the action timestamp lies inside the interval; it does not verify evidence contents or that the action source is independent from other sources. Out-of-scope entries require a documented `not_applicable` reason and reference.

## Current analysis

The result includes schema version `siberian-evidence-matrix-v3`, expected/present/confirmed-absent/unknown/out-of-scope counts, complete records, declared context, catalog version, and a SHA-256 digest. Confirmed absence requires a timestamped primary-action reference within the analysis interval, in addition to an acquired-source reference and applicability-condition references. The digest covers that action reference and timestamp. References and optional platform fields are analyst declarations; they are not independently verified. Weighted scores were removed because their inherited ordinal weights had no empirical support. There is no composite score, threshold, or `PASS` / `WARN` / `ABSTAIN` decision.

## Source-code observations

The module is adapted from `vigia/patterns/adversarial_silence.py` in VIGÍA, under Apache-2.0; see [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Its expectation catalogues and ordinal weights are carried over as research assumptions.

The standalone port addresses representation and provenance issues from the source:

- Observations are associated with a specific action and artifact type.
- Unknown and out-of-scope artifacts remain distinct from known presence and confirmed absence.
- Unsupported OS profiles, actions, artifact identifiers, and conflicting observations raise errors.
- The probability-sounding `fabrication_likelihood` field is omitted.
- Each confirmed absence is gated on catalog applicability evidence.

Important limits remain: the catalog is not yet a version/configuration matrix and does not validate a declared Windows release/build; references are locators and validity declarations supplied by the caller; collection quality and artifact dependencies are not modeled; and there is no calibrated inference. Rival-hypothesis comparison is implemented (`rivals`, Level 3) but is not calibration. The CLI now includes raw-evidence parsers (see below), and every adapter export is sealed and independently verifiable.

The artifact parsers are new and their limits are severe enough to state plainly. Five adapters ship — MFT, Prefetch, Amcache, Shimcache, Shellbags — and **not one has been validated against a real artifact**. Each was found to emit wrong values while passing its own tests: the MFT parser reported a file's creation time as its modification time; Prefetch decoded filename characters as a FILETIME; Amcache rendered `bytes(range(64))` as the date 3204-10-05 and exited 0 for a hive that did not exist; Shimcache consumed an unrelated registry value and blamed the artifact format; Shellbags returned `C:\Users\Bob\Deskto` for `Desktop` and recovered 0 of 200 folders from a realistically shaped hive. Only Prefetch has been validated, against 225 real Windows 10 artifacts from the OWL 2019 image. See `docs/red-team/` — including what verification does *not* establish, in `docs/EXPORT_VERIFICATION.md`. The SHA-256 digest covers the declared context, catalog version and entries, and observation/status/reference records, including validity intervals for condition evidence. It does not attest to truth or completeness and is not a sealed chain-of-custody report. The temporal-drift module is a separate VIGÍA subsystem and is not part of this port.

## Determinism, provenance, and integrity

The implementation sorts catalog entries and uses a fixed versioned JSON structure with sorted keys and compact separators before hashing its UTF-8 bytes with SHA-256. This is a deterministic digest for the current API payload. Schema v3 changes the digest namespace from v1/v2 and adds primary-action evidence; digests across schema versions are not comparable. There is not yet a persisted-manifest reader or historical digest verifier. The digest is not a canonical manifest or an independent verifier format; schema/version evolution remains open.

## Threat and trust boundaries

API arguments are checked for supported action/artifact identifiers, valid states, and known condition names. The CLI reader accepts `siberian-case-v1`, rejects duplicate and unknown fields, requires timezone-aware timestamps, and caps input at 5 MiB. The file contains source references, not evidence payloads. It is not a general manifest, does not open referenced paths, and does not verify reference contents. See the [case file contract](docs/CASE_FILE_FORMAT.md).

The analyst, acquisition process, clocks, expectation model, operating-system documentation, and chain-of-custody records are separate trust dependencies. SIBERIAN cannot infer completeness where those sources do not establish it.

## Artifact adapters, sealing and independent verification

`import-*` and `batch` read raw forensic artifacts and emit sealed JSON exports.
Each export carries an integrity block (`provenance_hash`, `payload_hash`,
`export_hash`) bound to its provenance, its records, and the parser's identity and
declared limitations.

`forensics/verify_siberian.py` re-derives those digests from the documented
protocol alone. It is a single stdlib-only file that imports nothing from
SIBERIAN, so an analyst can verify evidence without trusting — or even installing
— the tool that produced it. Tampering with a record, with the provenance, with
the parser's name, or with the declared limitations is detected; reordering JSON
keys is not, and should not be, because key order is not a property of the
evidence.

Sealing proves the document is unmodified. It does not prove the parser was
correct, and it does not prove the recorded source digest belongs to the
analyst's original evidence.

`batch` refuses to mix sources or cases: one output per input, and an existing
output whose source digest differs causes the run to fail rather than overwrite.

## Planned validation

Unit tests (342) exercise the contextual core, the CLI, the artifact adapters and
the verifier. They do not validate the Windows artifact catalog empirically, do
not establish practitioner demand, and — except for Prefetch against 225 real
artifacts — do not validate any parser against a real forensic artifact. They do not validate the Windows artifact catalog empirically or establish practitioner demand. Before describing the analysis as useful for forensic conclusions, validation should include at minimum:

- valid and incomplete applicability evidence for confirmed absences;
- mixtures of present, confirmed absent, unknown, and out-of-scope records;
- artifacts inapplicable under the declared platform/configuration;
- benign retention, disabled logging, sensor gaps, and acquisition failures;
- correlated artifact loss and duplicate/conflicting observations;
- stability of serialized output and hashes across repeated runs;
- blind cases with known provenance, including benign controls and selective-removal cases;
- empirical validation before any calibrated score or decision threshold.

The empirical and integration checks above are not yet implemented or run.

## Open design decisions

- Version/configuration-specific source matrix and maintenance process for artifact expectations.
- Collection coverage and acquisition provenance model.
- Statistical model, thresholds, and evaluation corpus.
- Versioned manifest/output schema and independent verification format.
- Contribution terms.
- Whether `PASS` means “no selective-loss signal under this model” or something narrower; it must not imply proof that no tampering occurred.

The language decision is recorded in [`docs/decisions/language-selection.md`](docs/decisions/language-selection.md).

The product destination and construction gates are in the [Spanish level plan](docs/NIVELES.md).
