# SIBERIAN

[English](README.md) · [Español](README_ES.md) · **[Technical README](TECHNICAL_README.md)**

<p align="center">
  <img src="visual/logo.png" alt="SIBERIAN: Adversarial Silence Analysis — Evidence is not only what remains." width="100%">
</p>

## Adversarial Silence Analysis

**What disappeared can be evidence too.**

Digital investigations usually begin with artifacts that survived collection. SIBERIAN is for the complementary question: given an activity and a collection scope, what should have been observable, and what might explain the artifacts that are missing?

The first Python library builds a contextual evidence matrix for documented Windows artifact expectations. It records presence, confirmed absence, uncertainty, and out-of-scope status with source references. It reports coverage counts and a deterministic hash; it does **not** calculate suspicion scores, classify intent, or produce a verdict.

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
analysis = AdversarialSilenceAnalyzer(context)
analysis.register_primary_action(
    "process_execution",
    evidence=ActionEvidence(
        "case://corroboration/process-execution",
        datetime(2026, 10, 1, 12, tzinfo=timezone.utc),
    ),
)
analysis.register_observation(
    "process_execution", "security_event_4688", ArtifactStatus.CONFIRMED_ABSENT,
    evidence_ref="case://acquisition/security.evtx/query-4688",
    condition_evidence={
        "host_build_matches_documented_catalog_scope": ConditionEvidence(
            "case://host/build-and-event-schema",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
        "audit_process_creation_enabled_for_interval": ConditionEvidence(
            "case://policy/auditpol-2026-10-01",
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
result = analysis.analyze()
print(result.confirmed_absent_count, result.unknown_count, result.audit_hash)
```

Unreported artifacts remain `UNKNOWN`. The result exposes schema version `siberian-evidence-matrix-v3`; its digest covers declared platform context, primary-action evidence, and observation evidence. `CONFIRMED_ABSENT` requires an evidence reference and timestamp for the primary action, a separate reference to the acquired source/query, and evidence for every applicability condition. The program checks that the action timestamp falls within the analysis interval; it does not validate the referenced material. Absence alone does not establish deletion, tampering, attribution, or intent. See the **[Technical README](TECHNICAL_README.md)** and [catalog review](docs/CATALOG_REVIEW.md).

## What makes the question useful

| Common evidence review | SIBERIAN's planned analysis |
| --- | --- |
| Lists artifacts that were found | Also models expected artifacts and their observation status |
| Can treat a missing record as a gap | Separates present, confirmed absent, unknown, and out of scope |
| May collapse the result to one explanation | Reports coverage and source-linked observations without an intent verdict |

The current library implements observation states, conditional expectations, provenance references, coverage counts, and a deterministic digest. It does not yet model rival hypotheses or issue `PASS` / `WARN` / `ABSTAIN` outcomes.

## Project status and origin

SIBERIAN is based on idea 24 in VIGÍA's catalogue of **40** product ideas: “Detector de silencio adversarial (el borrado selectivo delata).” The source note records the concept and the starting modules: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) and `vigia/tools/temporal_drift.py` in the separate `vigia-repo` project.

The VIGÍA detector is a research starting point, not a validated standalone product. SIBERIAN is an independent Python package without a VIGÍA runtime dependency. The adaptation and source license are recorded in [`NOTICE`](NOTICE).

## Current package and next work

- `siberian/`: dependency-free analysis library and source-linked conditional Windows catalog.
- [Active catalog matrix](docs/CATALOG_MATRIX.md): source claims and applicability gaps for each expectation.
- [Windows lab kit](lab/README.md): read-only baseline collector and run record guidance; it contains no empirical results.
- `docs/`: source provenance, technical behavior, build levels, and the language decision.
- [Construction levels](docs/NIVELES.md): destination-driven path from a contextualized analysis core to calibrated, independently verifiable forensic reports.
- [Level 1 validation protocol](docs/LEVEL1_VALIDATION_PROTOCOL.md): applicability-matrix fields, official-source review, and a controlled validation design. It records a plan, not results.
- [Open work](PENDIENTES.md): what can proceed without Windows and the experiments that still require a Windows VM.
- Next: complete the Level 1 catalog matrix across supported Windows versions and configurations, then validate it empirically.

There is no CLI, calibrated model, or validation corpus yet. There are no weighted suspicion metrics. Licensed under Apache-2.0.

> Evidence is not only what remains.
