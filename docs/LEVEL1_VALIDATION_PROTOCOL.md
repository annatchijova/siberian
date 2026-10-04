# Level 1 catalog and empirical validation protocol

**Status:** protocol proposal; no compatibility matrix or empirical results are claimed.
**Review date:** 2026-10-04

This protocol defines the evidence needed before SIBERIAN can mark Level 1 complete. The current catalog is a research starting point. Microsoft documentation establishes event semantics, policy behavior, and some platform scope; it does not establish artifact survival rates or a complete compatibility matrix for every Windows build, edition, update, and configuration.

## 1. Catalog applicability matrix

Maintain one versioned row for each `(artifact, activity, platform configuration)` combination. Do not use a single `Windows 10` label as a substitute for a tested or documented scope.

Required fields:

| Field | Record |
| --- | --- |
| Identity | Catalog ID, artifact, activity, schema/version, row revision |
| System scope | Product, release, edition/SKU, architecture, build and revision/UBR, servicing channel |
| Feature conditions | Required component/filesystem, audit subcategory and success/failure setting, relevant policy values |
| Generation semantics | Triggering event/action, host on which it is generated, event/schema version, known exceptions |
| Retention and loss | Retention/overwrite behavior, capacity or wrap conditions, volatility, reset/clear behavior |
| Acquisition | Source location, collector/parser and version, coverage evidence, known collection gaps |
| Interpretation | What a present record supports, what it does not support, dependencies and rival explanations |
| Provenance | Primary source URL, exact section/claim, retrieval date, reviewer, and whether evidence is documentary or empirical |
| Status | `documented`, `lab-observed`, `not-tested`, `contradicted`, or `out-of-scope`, with rationale |

Documentary support and laboratory observations are separate evidence classes. A source that says a feature exists does not establish that an event survives log rollover, that a collector exports it, or that a particular build behaves identically. A lab observation on one image does not generalize to all editions or updates.

For an entry to support a confirmed-absence claim, the matrix must identify a bounded configuration and the observed case must match it. Unsupported or unmatched configurations stay `UNKNOWN`; analysts' references remain locators and do not become automated validation merely because the API accepts them.

The current `AnalysisContext` records declared release/build and optional edition, architecture, build revision, and servicing channel. The result digest includes these values when supplied. They improve case description but do not perform matrix lookup or validate an analyst's applicability attestation.

## 2. Source review findings (2026-10-04)

The official [Windows 10 lifecycle page](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro) lists feature releases and states that Windows 10 Home/Pro 22H2 was the final release, with support ending October 14, 2025. LTSC editions follow their own lifecycle. The [Windows lifecycle FAQ](https://learn.microsoft.com/en-us/lifecycle/faq/windows) likewise distinguishes editions and servicing timelines. This supports recording edition and release, not collapsing the whole family into one scope.

Microsoft's [event 4688 documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) describes event versions and notes that command-line content has an additional policy dependency. [Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation) describes the audit subcategory. The [5156 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156) describes permitted Windows Filtering Platform connections. The [`fsutil usn` documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn) identifies supported product families and journal operations. These references do not supply measured survival probabilities or a complete build-by-build matrix for this catalog.

**Disposition:** keep the current generic build-applicability condition as a caller attestation only. It is not an implementation-verified compatibility check. Do not report the catalog as complete or a confirmed absence as proof of selective deletion.

## 3. Controlled validation study

### Questions

1. Under documented, matched conditions, does each artifact appear when its triggering activity occurs?
2. How often does it remain observable after benign loss mechanisms and collection transformations?
3. Can predeclared artifact combinations distinguish controlled selective removal from benign loss, configuration gaps, retention, acquisition gaps, and tool failure?

The first two questions validate expectations and boundaries. The third evaluates discrimination and is required before any score or decision threshold.

### Test units and conditions

Use disposable, snapshot-restorable virtual machines. Record exact image provenance, product/release/edition, architecture, build/UBR, policy export, filesystem, clock source, collector/parser versions, and all actions. For each catalog row, test at minimum:

- a positive generation control with the relevant feature enabled;
- a negative control with the feature disabled or the artifact out of scope;
- normal operation with no induced loss;
- benign loss cases applicable to that artifact (for example log rollover, journal wrap, cache expiry, reboot, acquisition truncation, or parser/collector omission);
- a controlled selective-removal case with a known intervention record;
- a matched benign case with similar volume and timing but no selective-removal intervention.

Run configurations as separate strata. Randomize case ordering. Preserve VM snapshots, setup scripts, raw acquired images/logs, intervention records, and analysis outputs under hashes. Never pool multiple events from one VM as independent machines; report the VM/run as the unit and account for repeated runs.

### Blind evaluation and analysis

Separate development cases from a held-out evaluation set by VM image/configuration and run, not by individual artifact row. The analyst applying the frozen SIBERIAN rules must not know the intervention labels until outputs are locked. Include benign controls and selective-removal cases with known provenance. Preserve misses and ambiguous runs; do not silently drop them.

Before unblinding, record hypotheses, case inclusion rules, missing-data handling, primary outcomes, subgroup analyses, and any proposed thresholds. Report counts and uncertainty intervals for generation failures, false absence claims, benign warnings, missed selective-removal cases, coverage, and abstentions. A threshold is not justified by a convenient development-set separation. If the held-out results do not discriminate the rival explanations, retain descriptive output and abstain.

No minimum sample count or acceptable error rate is set here: those depend on intended use and loss costs and must be justified before the blind evaluation. A pilot estimates operational variance and informs a separately preregistered sample-size plan; pilot cases do not become blind evaluation cases.

## 4. Reproducibility package and completion gate

Publish or retain for independent review:

- the versioned applicability matrix and source snapshots/retrieval dates;
- VM image identifiers, configuration exports, scripts, and run logs;
- raw evidence or a lawful, privacy-reviewed representative corpus, plus hashes and custody records;
- frozen analyzer/catalog versions and exact commands;
- preregistration, case labels held until output lock, analysis code, and complete results;
- limitations, failed runs, and conditions not examined.

Level 1 can close only when supported catalog rows have bounded documented applicability, the API represents acquisition/context and uncertainty without treating analyst attestations as verified facts, the deterministic output contract is reviewed, and the controlled validation establishes each row's generation and loss boundaries. Claims of discrimination, calibrated scores, or decision thresholds remain outside Level 1 and require the blind evaluation described above.

## Claim audit

- **Observation:** current Microsoft pages describe event semantics, audit settings, lifecycle scopes, and USN operations (linked above).
- **Inference:** these pages alone do not establish a complete build/configuration compatibility matrix or empirical survival rates.
- **Status:** this document is a proposed protocol; no laboratory study has been run and no error rate is known.
- **Falsifier:** a cited primary source or reproducible, independently reviewable experiment establishing the missing bounded compatibility or survival claim would update the relevant matrix row.
