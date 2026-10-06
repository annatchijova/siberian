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

- `siberian/`: analysis library and source-linked conditional Windows catalog. The **core is stdlib-only**; the Level 6 artifact adapters (`import-amcache`, `import-shimcache`, `import-shellbags`, `import-prefetch`) need optional extras:

```bash
pip install -e '.[adapters]'   # python-registry, pyscca
```

  Without them those commands report an explicit failure or a `degraded` record and recover nothing. They never substitute a guess, and `seal` / `verify` remain dependency-free.
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

## What Is Blocked, And By What

An important distinction: **almost nothing here needs Windows to run.** The core
library and all five artifact parsers are stdlib-only and platform-independent.
An `$MFT`, a `SYSTEM` hive and an `Amcache.hve` are byte streams; parsing them
on Linux is routine. The Prefetch parser has already been validated against 225
**real Windows 10** artifacts from the OWL 2019 disk image while running on
Linux.

What is blocked is **empirical validation**, and the two blockers are not the
same thing:

### Needs a live Windows system (cannot be done on Linux at all)

| Work item | Why a running Windows is required |
|-----------|------------------------------------|
| **Level 1 catalog validation** — confirm artifact generation, retention limits, rollover behaviour, audit-policy effects | These are properties of a *running* OS under a *configuration*. Nothing observes them from a parsed file, because the file cannot tell you what would have been in it |
| **Level 4 calibration corpus** — controlled ground-truth cases with selective deletion | Requires executing techniques and measuring artifact survival over time |
| **Collector validation** — `lab/collect_windows_baseline.ps1` on PowerShell 5.1 | PowerShell 5.1 behaviour differs from 7+; only verifiable on Windows |

### Needs a real artifact sample (Windows OS not required — only the file)

| Work item | What is actually missing |
|-----------|--------------------------|
| **MFT validation** | A genuine `$MFT` from an acquired volume. The parser runs on Linux; it has only ever been tested on synthetic records |
| **Amcache validation** | A genuine `Amcache.hve`. Neither `python-registry` nor `regipy` can author one, so no fixture could be synthesised |
| **Shimcache / Shellbags validation** | A genuine `SYSTEM`, `NTUSER.DAT` or `UsrClass.dat`. Traversal is covered only by a stub of the `python-registry` interface |
| **Prefetch SCCA** | A Windows XP-8.1 prefetch file. The MAM path (Win10+) is validated; SCCA is delegated to libscca and unverified because no sample exists locally |

An artifact copied off a Windows volume is sufficient for every item in the
second table. No Windows licence, VM or dual boot is needed — only the file.

**What CAN proceed without Windows:**
- Core library, CLI, bundle sealing/verification, rival hypotheses, Plaso import adapter
- Catalog matrix review against Microsoft documentation (docs/CATALOG_MATRIX.md)
- Red-team audits, deterministic testing, documentation
- All 370 unit tests pass on Linux, with no Windows and no evidence

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

# Verify an adapter export WITHOUT SIBERIAN INSTALLED
# (copy this one file; it imports nothing from the package)
python3 forensics/verify_siberian.py out/0000_*.json --rehash-source

# When Windows artifacts arrive: one command turns them into a validation report
python3 lab/validate_artifacts.py --artifacts /mnt/acquired --out report/

# Import Plaso l2tcsv as UNKNOWN observations
siberian import-plaso template.json plaso.csv -o enriched.json

# Artifact parsers (summary/JSON — these do NOT modify a case file)
# Every JSON export carries a provenance block: source digest, parser name and
# version, the ordered transformations applied, and the adapter's limitations.
siberian import-mft $MFT --summary --output mft.json
siberian import-prefetch /mnt/evidence/Prefetch --output prefetch.json
siberian import-amcache Amcache.hve --output amcache.json
siberian import-shimcache SYSTEM --output shimcache.json
siberian import-shellbags NTUSER.DAT --bag-type BagMRU --output shellbags.json

# A partial result (some files failed or degraded) exits 1 and says so on
# stderr. Accept it explicitly when triaging a batch:
siberian import-prefetch /mnt/evidence/Prefetch --allow-partial

# Batch: one adapter over many artifacts, ONE OUTPUT PER INPUT
siberian batch --adapter prefetch --out-dir out/ \
    --pattern '*.pf' --max-inputs 200 --max-items-per-input 50 \
    /mnt/evidence/Prefetch
#   -> out/0000_<artifact>.json, 0001_<artifact>.json, ... plus out/batch-manifest.json

# Evaluate rival hypotheses
siberian rivals case.json
```

---

## Red-Team Audit Reports

All levels undergo red-team audit before merge. Reports in `docs/red-team/`:

- `docs/red-team/NIVEL3_AUDIT.md` — Rival hypotheses & counterfactuals (9 findings, all fixed)
- `docs/red-team/NIVEL5_AUDIT.md` — Bundle sealing & verification (pending)
- `docs/red-team/NIVEL6_MFT_AUDIT.md` — MFT parser (7 findings; 2 claims refuted, one of them the reviewer's own circular probe)
- `docs/red-team/NIVEL6_PREFETCH_AUDIT.md` — Prefetch parser (8 findings; validated against 225 real artifacts, and the MAM path was found to be already correct)
- `docs/red-team/NIVEL6_AMCACHE_AUDIT.md` — Amcache parser (9 findings; arbitrary bytes were being rendered as year-3204 dates)
- `docs/red-team/NIVEL6_SHIMCACHE_AUDIT.md` — Shimcache parser (7 findings; 2 hypotheses refuted by experiment)
- `docs/red-team/NIVEL6_SHELLBAGS_AUDIT.md` — Shellbags parser (9 findings; produced the fabricated path `C:\Users\Bob\Deskto`)
- `docs/red-team/NIVEL6_INFRA_AUDIT.md` — sealing, batch and the independent verifier (5 findings; the verifier implemented a subset of the hash protocol it claimed to implement, and the sealed batch manifest could not be verified at all)
- `docs/EXPORT_VERIFICATION.md` — how to verify an export without SIBERIAN, and what verification does not prove

> A green suite is not the same as a correct parser. Across these five parsers,
> every one shipped with passing tests while doing something wrong:
>
> - **MFT** reported a file's *creation* time as its modification time, because
>   the fixture's timestamps were all zero.
> - **Prefetch** decoded filename characters as a FILETIME execution timestamp,
>   and its version assertion was `is not None or is not None`.
> - **Amcache** rendered `bytes(range(64))` as the date **3204-10-05**, and
>   exited 0 for a hive that did not exist.
> - **Shimcache** consumed an unrelated registry value, then blamed the artifact
>   format for the failure.
> - **Shellbags** returned `C:\Users\Bob\Deskto` for `Desktop`, invented view
>   and sort modes for ~25% of entries, and recovered 0 of 200 folders from a
>   realistically shaped hive.
>
> Read the audits, not the test count.

---

## Project Status

- **License:** Apache-2.0
- **Tests:** 370 passing on Linux (deterministic, no Windows required)
- **Red-team audits:** Level 3 complete, Level 6 complete (all five shipped adapters), Level 5 pending
- **Artifact parsers shipped:** Plaso l2tcsv (imports into case file), MFT, Prefetch, Amcache, Shimcache, Shellbags (summary/JSON only — see caveat)
- **VM handoff:** `lab/validate_artifacts.py` turns acquired artifacts into a validation report with one command, re-verifying every export with SIBERIAN absent. It states at the top that a verified export is not a correct export
- **Provenance:** every adapter records the source digest (a sorted manifest digest for directories), the parser name and version, its ordered transformations, and its declared limitations
- **Batch (`siberian batch`):** runs one adapter over many artifacts, one output file per artifact plus a manifest. It refuses to start rather than mix sources or overwrite another case's export, isolates each input's failure, and discloses any limit that truncated the run
- **Independent verification:** every export is sealed (`provenance_hash`, `payload_hash`, `export_hash`). `forensics/verify_siberian.py` re-derives them from the documented protocol alone — one stdlib-only file that imports nothing from SIBERIAN, so an analyst can verify evidence without trusting the tool that produced it. See [docs/EXPORT_VERIFICATION.md](docs/EXPORT_VERIFICATION.md)
- **Platform:** Linux-native and stdlib-only. Validated against real Windows artifacts (225 prefetch files from the OWL 2019 image) without a Windows host
- **Outstanding validation:** no MFT, Amcache, Shimcache or Shellbags parser has run against a real artifact; SCCA prefetch is unverified. See "What Is Blocked, And By What"

> Evidence is not only what remains.