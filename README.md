# SIBERIAN

[English](README.md) · [Español](README_ES.md) · **[Technical README](TECHNICAL_README.md)**

> 🚧 **UNDER CONSTRUCTION — NOT READY FOR OPERATIONAL USE.** SIBERIAN is an early prototype; its catalog, interfaces, and claims are still being developed and validated.

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

| Common evidence review | SIBERIAN's analysis |
| --- | --- |
| Lists artifacts that were found | Also models expected artifacts and their observation status |
| Can treat a missing record as a gap | Separates present, confirmed absent, unknown, and out of scope |
| May collapse the result to one explanation | Reports coverage and source-linked observations without an intent verdict |

The library implements observation states, conditional expectations, provenance references, coverage counts, a deterministic digest, **rival hypothesis evaluation**, **counterfactual scenario generation**, and a **standalone stdlib-only verifier** for sealed bundles. It does not yet issue calibrated `PASS` / `WARN` / `ABSTAIN` outcomes.

## Project status and origin

SIBERIAN is based on idea 24 in VIGÍA's catalogue of **40** product ideas: “Detector de silencio adversarial (el borrado selectivo delata).” The source note records the concept and the starting modules: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) and `vigia/tools/temporal_drift.py` in the separate `vigia-repo` project.

The VIGÍA detector is a research starting point, not a validated standalone product. SIBERIAN is an independent Python package without a VIGÍA runtime dependency. The adaptation and source license are recorded in [`NOTICE`](NOTICE).

## Current package and next work

- `siberian/`: dependency-free analysis library and source-linked conditional Windows catalog.
- [Active catalog matrix](docs/CATALOG_MATRIX.md): source claims and applicability gaps for each expectation.
- [Windows lab kit](lab/README.md): read-only baseline collector and run record guidance; it contains no empirical results.
- [Focused product scope](docs/PRODUCT_SCOPE.md): target analyst, workflow, first release, and explicit non-claims.
- [Case file and CLI](docs/CASE_FILE_FORMAT.md): strict JSON input and the `validate`, `analyze`, `explain`, `seal`, `verify`, `import-plaso`, `rivals` commands.
- `docs/`: source provenance, technical behavior, build levels, and the language decision.
- [Construction levels](docs/NIVELES.md): destination-driven path from a contextualized analysis core to calibrated, independently verifiable forensic reports.
- [Level 1 validation protocol](docs/LEVEL1_VALIDATION_PROTOCOL.md): applicability-matrix fields, official-source review, and a controlled validation design. It records a plan, not results.
- [Open work](PENDIENTES.md): what can proceed without Windows and the experiments that still require a Windows VM.
- [Red-team audit reports](docs/red-team/): adversarial reviews of each level.

---

## Build Levels — Status Summary

| Level | Description | Status | Blocker |
|-------|-------------|--------|---------|
| **1** | Contextualized evidence matrix (catalog, conditions, states, digest) | ✅ Core complete | **Windows VM** — empirical validation of catalog entries (generation, retention, acquisition) |
| **2** | Reproducible case file + CLI (`validate`/`analyze`/`explain`) | ✅ Complete | — |
| **3** | Rival hypotheses & counterfactuals (`rivals` CLI) | ✅ Complete | — |
| **4** | Empirical evaluation & calibration (blind corpus) | ⏳ Planned | **Windows VM** — controlled corpus with ground truth |
| **5** | Sealed bundle + standalone verifier (`seal`/`verify`) | ✅ Complete | — |
| **6** | Forensic tool adapters (Plaso → case file) | 🟡 Partial | **Windows VM** — additional format adapters (EVTX, USN, etc.) and real-fixture validation of the ones shipped |

**What "✅ Complete" means:** implemented, tested, red-team audited, deterministic, and documented.

**What "⏳ Planned" means:** design documented, awaiting blocker resolution.

---

## Blocked by Windows VM (Empirical Validation)

The following **cannot be completed without a Windows VM** because they require empirical observation of artifact behavior on actual Windows systems:

| Work Item | Why Windows Required |
|-----------|---------------------|
| **Level 1 catalog validation** — confirm artifact generation, retention limits, rollover behavior, audit policy effects on actual Windows 10/11 builds | Artifact generation depends on OS build, edition, audit policy, and configuration — only observable on real Windows |
| **Level 4 calibration corpus** — controlled ground-truth cases (benign + selective deletion) with known ground truth | Requires executing attacker techniques and measuring artifact survival on real Windows |
| **Level 6 additional adapters** — EVTX, USN, Jump Lists, LNK, and consolidation of the existing MFT/Prefetch/Amcache/Shimcache/Shellbags parsers | Format specifics, edge cases, and Windows version differences only observable on real Windows |
| **Collector validation** — `lab/collect_windows_baseline.ps1` syntax and runtime behavior on PowerShell 5.1 | PowerShell 5.1 behavior differs from 7+; only verifiable on Windows |

**What CAN proceed without Windows:**
- Core library, CLI, bundle sealing/verification, rival hypotheses, Plaso import adapter
- Catalog matrix review against Microsoft documentation (docs/CATALOG_MATRIX.md)
- Red-team audits, deterministic testing, documentation
- All 89 unit tests pass without Windows

---

## Quick Start

```bash
# Install
pip install -e .

# Validate a case file
siberian validate case.json

# Analyze and produce evidence matrix
siberian analyze case.json

# Explain observation statuses
siberian explain case.json

# Seal into tamper-evident bundle
siberian seal case.json -o bundle.json --engine-attestation

# Verify bundle (stdlib-only, no deps)
python3 -m siberian.verify bundle.json --strict

# Import Plaso l2tcsv as UNKNOWN observations
siberian import-plaso template.json plaso.csv -o enriched.json

# Artifact parsers (summary/JSON — these do NOT modify a case file)
siberian import-mft $MFT --summary
siberian import-prefetch /mnt/evidence/Prefetch --summary
siberian import-amcache Amcache.hve --summary
siberian import-shimcache SYSTEM --summary
siberian import-shellbags NTUSER.DAT --bag-type BagMRU --summary

# Evaluate rival hypotheses
siberian rivals case.json
```

---

## Red-Team Audit Reports

All levels undergo red-team audit before merge. Reports in `docs/red-team/`:

- `docs/red-team/NIVEL3_AUDIT.md` — Rival hypotheses & counterfactuals (9 findings, all fixed)
- `docs/red-team/NIVEL5_AUDIT.md` — Bundle sealing & verification (pending)
- `docs/red-team/NIVEL6_MFT_AUDIT.md` — MFT parser (7 findings: 1 critical, 2 high, 2 medium, 2 low/info; all fixed, 2 claims refuted and withdrawn)

> A green suite is not the same as a correct parser. The MFT parser shipped with
> six passing tests while reporting the file's **creation** time as its
> modification time, because the fixture's timestamps were all zero. Read the
> audit, not the test count.

---

## Project Status

- **License:** Apache-2.0
- **Tests:** 89 passing (deterministic, no Windows required)
- **Red-team audits:** Level 3 complete, Level 6 (MFT) complete, Level 5 pending
- **Artifact parsers shipped:** Plaso l2tcsv (imports into case file), MFT, Prefetch, Amcache, Shimcache, Shellbags (summary/JSON only — see caveat)
- **Windows validation:** Pending VM access; no parser has been validated against a real artifact

> Evidence is not only what remains.