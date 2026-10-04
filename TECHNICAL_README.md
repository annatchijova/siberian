# SIBERIAN — Technical README

[English](README.md) · [Español](README_ES.md) · **Technical**

## Status and scope

This repository contains a first standalone Python library port of VIGÍA's adversarial-silence pattern. It has no command-line interface, calibrated statistical model, or validation corpus. It returns descriptive metrics; it does not issue a forensic verdict.

The seed is VIGÍA idea 24, supported there by `vigia/patterns/adversarial_silence.py` and `vigia/tools/temporal_drift.py`. The source catalogue describes the idea as comparing selective loss of difficult-to-erase artifacts with easier-to-erase artifacts. SIBERIAN treats this as a hypothesis to investigate, not an attribution method.

## Current API and inputs

The library API is in `siberian/adversarial_silence.py`. Callers select an OS profile, register known actions, and attach observations to an `(action, artifact_type)` pair:

```python
from siberian import AdversarialSilenceDetector, ArtifactStatus

detector = AdversarialSilenceDetector("windows")
detector.register_primary_action("process_execution")
detector.register_observation(
    "process_execution", "prefetch_entry", ArtifactStatus.CONFIRMED_ABSENT,
    explanation="Checked in the acquired Prefetch directory",
)
result = detector.analyze()
```

Supported profiles/actions and their expected-artifact tables are embedded in this release. Their applicability to a particular machine, version, configuration, action, or collection period is **not** evaluated. The caller is responsible for establishing those conditions before recording `CONFIRMED_ABSENT`.

Observations are `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN`, or `OUT_OF_SCOPE`. Unreported expected artifacts default to `UNKNOWN`. Only `PRESENT` and `CONFIRMED_ABSENT` observations are used in metric denominators; the other two states remain visible in the returned records and are excluded.

## Current metrics

The library returns `silence_score`, `selectivity_score`, and `erasure_sophistication` as exact `Fraction` values, plus counts of expected, known, absent, unknown, and out-of-scope artifacts. Counts are necessary context: a ratio based on one observation is not equivalent to one based on a large sample. The metrics summarize supplied observations and inherited research weights; they are not probability estimates.

- **`silence_score`**: sum of `forensic_value` weights for confirmed-absent artifacts divided by the sum of weights for all known in-scope artifacts. It is `None` when there are no known observations.
- **`selectivity_score`**: `max(hard_absence_rate - easy_absence_rate, 0)`, where “hard” means `erasure_difficulty > 1/2`. It is `None` unless both groups have at least one known observation.
- **`erasure_sophistication`**: mean `erasure_difficulty` among confirmed-absent artifacts. It is `None` when there are no confirmed absences.

No composite score or threshold is provided. The source field `fabrication_likelihood` was dropped because it was an uncalibrated weighted score whose name implied more than the evidence supported. The output has no `PASS` / `WARN` / `ABSTAIN` decision yet.

## Source-code observations

The module is adapted from `vigia/patterns/adversarial_silence.py` in VIGÍA, under Apache-2.0; see [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Its expectation catalogues and ordinal weights are carried over as research assumptions.

The standalone port addresses some representation issues from the source:

- Observations are associated with a specific action and artifact type.
- Unknown and out-of-scope artifacts are excluded from metric denominators rather than counted as present.
- Unsupported OS profiles, actions, artifact identifiers, and conflicting observations raise errors.
- The probability-sounding `fabrication_likelihood` field is omitted.

Important limits remain: the catalogue is not version/configuration-aware; collection scope and acquisition quality are not modeled; dependence between artifacts is ignored; explanations are caller-supplied text; and there is no calibrated inference, rival-hypothesis comparison, CLI, or empirical validation. The SHA-256 digest covers the profile and returned expected-artifact/status/explanation records, including the catalog weights and command hints. It does not attest to the truth or completeness of observations, and is not a sealed chain-of-custody report. The temporal-drift module is a separate VIGÍA subsystem and is not part of this port.

## Determinism, provenance, and integrity

The current implementation uses `Fraction` for calculations, sorts actions and artifact identifiers before building records, serializes a fixed versioned dictionary using sorted compact JSON, then hashes its UTF-8 bytes with SHA-256. This is a deterministic digest for the current API payload. It is not a canonical manifest or an independent verifier format; schema/version evolution remains open.

## Threat and trust boundaries

API arguments are checked for supported action/artifact identifiers and valid states. There is not yet a manifest parser, input-size policy, acquisition metadata model, or source-reference type. The module never executes the command hints; they are inert text for an examiner to review against the system and tool versions in scope.

The analyst, acquisition process, clocks, expectation model, operating-system documentation, and chain-of-custody records are separate trust dependencies. SIBERIAN cannot infer completeness where those sources do not establish it.

## Planned validation

No tests or empirical evaluation are present in this repository yet. Before describing the detector as useful for forensic conclusions, validation should include at minimum:

- all-present and all-confirmed-absent observations;
- mixtures of present, confirmed absent, unknown, and out-of-scope records;
- artifacts inapplicable under the declared platform/configuration;
- benign retention, disabled logging, sensor gaps, and acquisition failures;
- correlated artifact loss and duplicate/conflicting observations;
- stability of canonical output and hashes across repeated runs;
- blind cases with known provenance, including benign controls and selective-removal cases;
- calibration or an explicit decision to report only descriptive metrics.

The checks are not yet implemented or run.

## Open design decisions

- Version/configuration-specific sources and maintenance process for artifact expectations.
- Collection coverage and acquisition provenance model.
- Statistical model, thresholds, and evaluation corpus.
- Versioned manifest/output schema and independent verification format.
- Contribution terms.
- Whether `PASS` means “no selective-loss signal under this model” or something narrower; it must not imply proof that no tampering occurred.

The language decision is recorded in [`docs/decisions/language-selection.md`](docs/decisions/language-selection.md).
