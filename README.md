# SIBERIAN

[English](README.md) · [Español](README_ES.md) · **[Technical README](TECHNICAL_README.md)**

## Adversarial Silence Analysis

**What disappeared can be evidence too.**

Digital investigations usually begin with artifacts that survived collection. SIBERIAN is for the complementary question: given an activity and a collection scope, what should have been observable, and what might explain the artifacts that are missing?

The first Python analysis library is now ported. It compares confirmed absences with the other artifacts expected for an action. It reports exact descriptive metrics and a hash of the analysis inputs; it does **not** classify intent or produce a verdict.

```python
from siberian import AdversarialSilenceDetector, ArtifactStatus

analysis = AdversarialSilenceDetector(os_profile="windows")
analysis.register_primary_action("process_execution")
analysis.register_observation(
    "process_execution", "prefetch_entry", ArtifactStatus.CONFIRMED_ABSENT,
    explanation="Checked in the acquired Prefetch directory",
)
analysis.register_observation(
    "process_execution", "event_4688", ArtifactStatus.PRESENT,
)
result = analysis.analyze()
print(result.selectivity_score, result.known_count, result.audit_hash)
```

Unreported artifacts remain `UNKNOWN`; they are excluded from the metrics. Absence alone does not establish deletion, tampering, attribution, or intent. The technical design, formulas, and limits are described in the prominent **[Technical README](TECHNICAL_README.md)**.

## What makes the question useful

| Common evidence review | SIBERIAN's planned analysis |
| --- | --- |
| Lists artifacts that were found | Also models expected artifacts and their observation status |
| Can treat a missing record as a gap | Separates present, confirmed absent, unknown, and out of scope |
| May collapse the result to one explanation | Returns descriptive metrics without an intent verdict |

The current library implements the observation states and descriptive metrics. It does not yet model rival hypotheses or issue `PASS` / `WARN` / `ABSTAIN` outcomes.

## Project status and origin

SIBERIAN is based on idea 24 in VIGÍA's catalogue of **40** product ideas: “Detector de silencio adversarial (el borrado selectivo delata).” The source note records the concept and the starting modules: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) and `vigia/tools/temporal_drift.py` in the separate `vigia-repo` project.

The VIGÍA detector is a research starting point, not a validated standalone product. SIBERIAN is an independent Python package without a VIGÍA runtime dependency. The adaptation and source license are recorded in [`NOTICE`](NOTICE).

## Current package and next work

- `siberian/`: dependency-free analysis library and Windows/Linux seed catalogues.
- `docs/`: source provenance, technical behavior, and the language decision.
- Next: validate the artifact expectations, add a versioned manifest format, then evaluate rival hypotheses.

There is no CLI, calibrated model, or validation corpus yet. The descriptive weights are inherited research assumptions, not probabilities. Licensed under Apache-2.0.

> Evidence is not only what remains.
