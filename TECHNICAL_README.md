# SIBERIAN — Technical README

[English](README.md) · [Español](README_ES.md) · **Technical**

## Status and scope

This repository is a bootstrap for a proposed deterministic forensic analysis core. There is no implementation, command-line interface, calibrated statistical model, or validation corpus in this repository yet. The illustrative report in the primary README is explicitly not program output.

The seed is VIGÍA idea 24, supported there by `vigia/patterns/adversarial_silence.py` and `vigia/tools/temporal_drift.py`. The source catalogue describes the idea as comparing selective loss of difficult-to-erase artifacts with easier-to-erase artifacts. SIBERIAN treats this as a hypothesis to investigate, not an attribution method.

## Proposed inputs

The first manifest format should represent at least:

- **Activity claim:** the action or event for which secondary artifacts are expected, with provenance and confidence kept separate from the absence analysis.
- **Artifact expectation:** artifact type, platform and configuration conditions, expected persistence, forensic value, and the source/version of the expectation model.
- **Observation:** `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN`, or `OUT_OF_SCOPE`, with acquisition method, time, source, and supporting reference.
- **Collection context:** time range, sensors and sources actually acquired, known gaps, retention policy, and integrity metadata.
- **Alternative explanations:** explicit hypotheses such as normal expiry, disabled telemetry, platform behavior, acquisition failure, or selective removal.

An artifact is eligible for absence analysis only when the expectation applies and collection could have observed it. `UNKNOWN` and `OUT_OF_SCOPE` must not be converted into absence.

## Proposed analysis path

```text
manifest + versioned expectation model
                 │
                 ▼
       applicability / coverage gate
                 │
                 ▼
 present · confirmed absent · unknown · out of scope
                 │
                 ▼
       selective-loss comparison
                 │
                 ▼
   rival explanations + counterfactuals
                 │
                 ▼
    PASS / WARN / ABSTAIN + provenance
```

The result should include the exact observations used, exclusions and reasons, expectation-model version, calculations, rival hypotheses, and the observations that could distinguish them. An LLM must not participate in the consequential decision path. A later narrative renderer, if added, may only describe a finalized result.

## Scoring and decision semantics

No score formula or threshold is adopted yet. VIGÍA's source implementation uses `Fraction` arithmetic and combines weighted silence, selectivity, and erasure difficulty into `fabrication_likelihood`. That name can be read as a calibrated probability even though the implementation does not establish calibration. SIBERIAN must not reuse it as a probability.

Before scoring is implemented, the project needs an explicit model for:

1. Applicability of each expected artifact to the operating system, version, configuration, and action.
2. Probability or defensible interval of survival under the benign hypotheses being compared.
3. Collection coverage and the chance the acquisition process would have captured the artifact.
4. Dependence between artifacts (for example, artifacts removed together by one retention action).
5. How the comparison is calibrated and evaluated against benign loss and known selective-removal cases.

Until the evidence model and thresholds are validated, scores must be labeled as descriptive metrics, not likelihoods, probabilities, or evidence of intent. `ABSTAIN` is required when the hypotheses are not discriminated by the observations or their assumptions are unverified.

## Source-code observations

The source module `vigia/patterns/adversarial_silence.py` was inspected as the seed. Its records are frozen dataclasses and its calculations use `Fraction`; its audit hash is SHA-256 over a JSON subset containing the two scores and sorted absent artifact names.

The current source also has material modeling limits that the standalone design must not inherit silently:

- Present and absent artifacts are stored in shared sets rather than tied to a specific action, time, or source.
- Every expected artifact contributes to the denominator. An artifact that was never registered as present or confirmed absent behaves like non-absence in the selectivity calculation, even though its status is unknown.
- A confirmed absence is applied by artifact type across all registered actions, so context-specific observations cannot be represented faithfully.
- The result named `fabrication_likelihood` is an uncalibrated weighted score; it must not be presented as a probability.
- The hash does not include all observations, assumptions, expectation-model provenance, or alternative explanations, so it is not a complete sealed report.

These are findings from reading the implementation, not claims that its tests or production use have validated behavior. The temporal-drift module is a separate VIGÍA subsystem; no coupling to it has been designed or implemented here.

## Determinism, provenance, and integrity

The intended core is deterministic for an identical canonical manifest, expectation model, and software version. The implementation should avoid floating-point decision arithmetic unless its cross-platform behavior is explicitly bounded and tested. Any content hash must cover the canonical input, model/version identifiers, exclusions, intermediate calculations, and final result. A hash can show that a report has not changed under the stated hashing scheme; it cannot prove that observations are true or complete.

The canonical serialization format, hash domain, schema versioning, and verifier design remain open decisions.

## Threat and trust boundaries

Inputs and artifact descriptions are untrusted. Parsers must validate schema, bound input size and collection counts, reject ambiguous states, and preserve original source references. The analysis process must not execute commands copied from evidence or generated investigation hints. Any suggested command is inert text for a qualified examiner to review.

The analyst, acquisition process, clocks, expectation model, operating-system documentation, and chain-of-custody records are separate trust dependencies. SIBERIAN cannot infer completeness where those sources do not establish it.

## Planned validation

No tests or empirical evaluation are present yet. Before describing the detector as useful for forensic conclusions, validation should include at minimum:

- all-present and all-confirmed-absent observations;
- mixtures of present, confirmed absent, unknown, and out-of-scope records;
- artifacts inapplicable under the declared platform/configuration;
- benign retention, disabled logging, sensor gaps, and acquisition failures;
- correlated artifact loss and duplicate/conflicting observations;
- stability of canonical output and hashes across repeated runs;
- blind cases with known provenance, including benign controls and selective-removal cases;
- calibration or an explicit decision to report only descriptive metrics.

The repository currently contains no implementation against which these checks can run.

## Open design decisions

- Input schema and compatibility/versioning policy.
- Empirical source and maintenance process for artifact expectations.
- Statistical model, thresholds, and evaluation corpus.
- Output schema and independent verification format.
- License and contribution terms.
- Whether `PASS` means “no selective-loss signal under this model” or something narrower; it must not imply proof that no tampering occurred.
