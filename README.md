# SIBERIAN

[English](README.md) · [Español](README_ES.md) · **[Technical README](TECHNICAL_README.md)**

## Adversarial Silence Analysis

**What disappeared can be evidence too.**

Digital investigations usually begin with artifacts that survived collection. SIBERIAN is for the complementary question: given an activity and a collection scope, what should have been observable, and what might explain the artifacts that are missing?

The project is at bootstrap. Its first implementation will compare confirmed absences with surviving artifacts and competing explanations. It will report `ABSTAIN` when the available evidence cannot distinguish selective removal from benign loss or a collection gap.

```text
Illustrative report — not output from an implemented analyzer

OBSERVED
  Prefetch             confirmed absent
  USN Journal          unknown (not collected)
  DNS cache            present

RESULT
  Insufficient evidence to distinguish selective removal
  from retention or collection effects.

VERDICT: ABSTAIN
```

Absence alone does not establish deletion, tampering, attribution, or intent. The technical design and its known limits are described in the prominent **[Technical README](TECHNICAL_README.md)**.

## What makes the question useful

| Common evidence review | SIBERIAN's planned analysis |
| --- | --- |
| Lists artifacts that were found | Also models expected artifacts and their observation status |
| Can treat a missing record as a gap | Separates present, confirmed absent, unknown, and out of scope |
| May collapse the result to one explanation | Preserves rival explanations and can abstain |

These are design goals, not capabilities claimed for a released implementation.

## Project status and origin

SIBERIAN is based on idea 24 in VIGÍA's catalogue of **40** product ideas: “Detector de silencio adversarial (el borrado selectivo delata).” The source note records the concept and the starting modules: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) and `vigia/tools/temporal_drift.py` in the separate `vigia-repo` project.

The VIGÍA detector is a research starting point, not a validated standalone product. SIBERIAN is intended to become an independent Python project without a VIGÍA runtime dependency.

## Planned first milestone

- Typed evidence manifest with explicit observation and collection states.
- Deterministic comparison of expected artifacts and confirmed observations.
- Rival hypotheses, investigation suggestions, and `PASS` / `WARN` / `ABSTAIN` outcomes.
- Canonical report with provenance and a content hash.
- Small CLI for user-supplied evidence manifests.

No standalone CLI or production-ready inference is available yet. License and contribution terms are not selected.

> Evidence is not only what remains.
