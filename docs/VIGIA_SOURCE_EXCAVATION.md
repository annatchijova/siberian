# VIGÍA source excavation: idea 24

**Review date:** 2026-10-04  
**Purpose:** record what the cited VIGÍA code does, what SIBERIAN carries forward, and what it deliberately does not inherit.

## Scope and source state

The source repository is `/home/labestiadevigia/vigia-repo`. At review time its `main` checkout was at `01b7fe0e`; the two source modules reviewed had no local diff. The checkout did contain extensive unrelated modified and untracked result files (432 status entries). No files in that checkout were changed and no VIGÍA test suite was run.

The idea catalogue is maintained separately at `/home/labestiadevigia/Desktop/VIGIA_20_IDEAS_2026-08-13.md`. Idea 24 names both `patterns/adversarial_silence.py` and `tools/temporal_drift.py`; it describes selectivity between difficult-to-erase artifacts (examples include `$MFT` and Prefetch) and easier-to-erase ones. The code review below narrows what those references establish.

Source revision pointers:

- [`adversarial_silence.py` at its introducing commit `b0cb16c83a8358d65b17a01a49c8ae5fa1547dfd`](https://github.com/annatchijova/vigia-repo/blob/b0cb16c83a8358d65b17a01a49c8ae5fa1547dfd/vigia/patterns/adversarial_silence.py), introduced 2026-05-04.
- [`temporal_drift.py` at inspected VIGÍA revision `01b7fe0e`](https://github.com/annatchijova/vigia-repo/blob/01b7fe0e/vigia/tools/temporal_drift.py); its history includes a 2026-06-25 error-logging change at `b85615e5546633b46cb565c7da91dc2189965b97`.
- [`test_b123_producer_characterization.py` at VIGÍA main](https://github.com/annatchijova/vigia-repo/blob/01b7fe0e/tests/test_b123_producer_characterization.py), added 2026-07-23.
- [`B123_EXCAVATION_20260723.md` at VIGÍA main](https://github.com/annatchijova/vigia-repo/blob/01b7fe0e/docs/B123_EXCAVATION_20260723.md), which records the later producer/consumer audit.

## What the inherited detector computes

`AdversarialSilenceDetector` contains a static Windows/Linux table keyed by action. Each expected artifact has an `erasure_difficulty`, `forensic_value`, and a suggested `detection_command`. The caller registers action names and two global sets of artifact type names: present and confirmed absent. The analyzer expands each registered action into its expected artifacts and computes:

1. `silence_score`: forensic-value-weighted absent artifacts divided by forensic-value-weighted expected artifacts;
2. `selectivity_score`: the positive difference between absence rates for artifacts whose declared erasure difficulty is above `1/2` and the remaining artifacts;
3. `erasure_sophistication`: mean declared difficulty among absent records;
4. `fabrication_likelihood`: a fixed weighted sum of those three values, capped at one.

All arithmetic is exact `Fraction` arithmetic. The result also includes per-row records, up to five investigation hints, and a SHA-256 value over only the two scores and sorted absent artifact type names. The source test characterizes the canonical process-execution/absent-Prefetch case as `silence_score=9/32`, `selectivity_score=1/3`, `erasure_sophistication=4/5`, and `fabrication_likelihood=487/1200`.

Exact arithmetic and deterministic execution make these calculations repeatable. They do not establish that the inputs, artifact expectations, difficulty ordering, forensic-value weights, or output labels are empirically valid.

## Findings and limits in the source

These are code observations from the reviewed source, not allegations about the author or a claim that every caller encounters every issue.

- **Status loses its action association.** Presence and absence are keyed only by `artifact_type`, then reused for every registered action. An absent artifact name therefore marks every expectation with that name absent, regardless of which action or scope the observation came from.
- **Unknown is folded into the non-absent denominator.** An expected artifact not registered as absent contributes to the hard/easy survival denominator just like a known present artifact. `SilenceRecord` has only a boolean absence flag; the human-readable alternative string distinguishes present from unknown, but the arithmetic does not.
- **Conflicting status is not rejected.** Registering the same artifact as both present and absent makes absence win in the analyzer.
- **Duplicate actions change the calculation.** Actions are stored in a list and are not deduplicated, so repeated registration repeats expectations in the totals.
- **Unknown OS profiles silently select Windows.** The constructor uses the Windows knowledge base as fallback when the requested profile is unrecognized.
- **Several table entries are not comparable durable traces.** For example, `Get-NetTCPConnection` reports current connection state, and DNS cache entries are volatile. A command string alone does not specify time scope, acquisition coverage, or what a failed query means.
- **The evidence hash is not a complete analysis commitment.** Its payload omits action identities, present/unknown states, OS profile, source references, the catalog version, and the expected-artifact definitions. Equal score/absence summaries can therefore have equal hashes while representing different analysis contexts.
- **The labels outrun the measured method.** The implementation calls a hand-weighted score `fabrication_likelihood` and the difficulty mean `erasure_sophistication`; the module contains no fitted probability model, calibrated error rate, or direct observation of attacker knowledge or intent.

The characterization tests added 2026-07-23 pin several current outputs and determinism. They do not show that this behavior is forensically valid. VIGÍA's own B-123 excavation also records that the detector had no live producer feeding it and that mapping evidence to its actions and absences remained an unresolved methodological decision.

## Relationship to `temporal_drift.py`

The catalogue lists `temporal_drift.py` with idea 24, but the module implements a separate timestamp consistency analyzer. It accepts temporal events, normalizes naive timestamps by assuming UTC, checks heuristic creation/modification/send orderings, future timestamps, and timezone-offset differences, then emits `BENIGN`, `SUSPICIOUS`, or `MALICIOUS` with hand-set confidence values. Its helper extracts dates from PDF metadata and email headers.

The reviewed code has no artifact-absence input, no expected-artifact model, and no import or call to `AdversarialSilenceDetector`. A repository-wide reference search found no test exercising `TemporalDriftDetector` or `TimestampExtractor`; its visible invocation is the module's standalone PDF/email command-line path. Therefore:

- the catalogue establishes a conceptual association between both modules and idea 24;
- `temporal_drift.py` is not an implementation component of adversarial-silence analysis;
- its chronology checks and labels are not evidence validating the absence detector;
- a future SIBERIAN temporal input adapter would need its own source review and validation and must not import the module's verdict or confidence as an established fact.

## Relationship to hypothesis lineage and counterfactual modules

The earlier SIBERIAN direction also cited VIGÍA's `hypothesis_lineage.py` and `vigia_counter_fact.py` as possible foundations for rival explanations and counterfactuals. Review shows useful interface ideas, but neither module consumes SIBERIAN-style artifact observations.

`HypothesisLineageTracker` stores nodes with verdicts, iteration numbers, costs, and sets of covered/ignored signal names. It selects the last node with a requested winner ID, calls other hypotheses within a fixed 20% cost margin near-misses, and calls ignored signals covered by another hypothesis pivots. Its `verdict_stability` is `count(winner-ID nodes) / count(distinct iteration values)`; this can exceed one if the winner ID has multiple nodes in an iteration. The lineage hash includes only winner ID plus each node's ID, verdict, final cost, and iteration, omitting signal sets, parent links, elimination reasons, and other costs. The characterization test records an example value, not validity of the metric or pivot claims.

`CounterFactEngine` accepts an abductive-result dictionary from VIGÍA, then perturbs its winner/challenger artifact lists and costs according to VIGÍA's `(cost, -coverage, required-count)` ordering. It uses a fixed logistic-shaped `plausibility` heuristic with floating-point exponentiation and emits human-readable investigative directives. Its report hash includes `generated_at`, so equal substantive input analyzed at different times produces a different hash. The report's use of terms such as “verified”, “plausibility”, and “Daubert” is stronger than what its calculations alone establish. A repository-wide test search found no direct `CounterFactEngine` test reference.

**Disposition for SIBERIAN:** retain the output ideas—list competing explanations, identify observations that could distinguish them, state the effect of changing an assumption, and preserve lineage—but implement them over versioned SIBERIAN records and explicit, testable rules. Do not reuse VIGÍA's cost scale, 20% near-miss threshold, pivot confidence delta, logistic plausibility, generated report hash, or forensic/legal labels without independent methodological justification and evaluation.

## What SIBERIAN carries forward

SIBERIAN retains the research question: compare an observed, action-linked evidence pattern with a bounded expectation, including what is absent. Its current implementation intentionally does not port the source weights or inference labels. It associates observations with `(action, artifact_type)`, distinguishes `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN`, and `OUT_OF_SCOPE`, and records source/context references. Schema v3 requires timestamped, referenced primary-action evidence before an absence can be confirmed. Its current Windows catalog is a narrow, conditional subset, not a complete port of the source knowledge base.

The current build-applicability check still requires caller-supplied attestations; it does not compare builds against a maintained matrix. That open Level 1 limitation is tracked in the [catalog review](CATALOG_REVIEW.md) and [validation protocol](LEVEL1_VALIDATION_PROTOCOL.md).

## Recommended next sequence

1. Preserve SIBERIAN's contextual, non-scoring evidence matrix as the foundation; do not port the VIGÍA `fabrication_likelihood` formula.
2. Finish the bounded artifact applicability matrix and validate generation, retention, and acquisition limits per the Level 1 protocol.
3. Before adding a selectivity measure, define which artifacts are comparable, how missing/unknown data affect denominators, how correlated losses are handled, and what evidence supports any difficulty ordering.
4. Add rival explanations and counterfactuals only after the expected-artifact and acquisition model can represent them. Keep any temporal-chronology analysis a separate evidence input with its own validated contract.
5. Consider a score, calibrated probability, or `PASS` / `WARN` / `ABSTAIN` decision only after a blinded evaluation with predeclared outcomes and measured error bounds.

## Claim audit

- **Observed in code:** static action-to-artifact catalog, global status sets, exact-rational formulas, limited hash payload, temporal timestamp rules and labels.
- **Observed in repository indices:** the VIGÍA characterization test was added on 2026-07-23; the B-123 report calls the detector unwired and identifies evidence-to-action mapping as an open method choice; no temporal-drift test reference was found in the source/test tree search.
- **Inference:** the temporal module is a conceptual companion in the idea catalogue, not part of the adversarial-silence computation.
- **Not established:** empirical artifact survival, soundness of difficulty/forensic-value weights, calibrated intent/fabrication probability, accuracy of temporal-drift verdicts, or generalization to untested builds and configurations.
