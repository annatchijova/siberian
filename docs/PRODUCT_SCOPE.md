# SIBERIAN: focused product scope

**First intended user:** a DFIR examiner or incident responder reviewing evidence already collected from a host.

**Problem:** analysts often know or suspect that an activity occurred, then have to decide whether an expected artifact's absence means anything. That decision depends on host/version, policy, time range, retention, acquisition, and parser coverage. A missing row in a timeline does not record those assumptions for the next reviewer.

**SIBERIAN's job:** make those assumptions and evidence gaps explicit. Given an analyst-declared activity and collection scope, it checks a source-backed catalog, records what was observed, keeps uncertainty reasons visible, and produces a reproducible case report for review.

This sits beside timeline and artifact tools such as [Plaso](https://github.com/log2timeline/plaso), which extract and correlate events from forensic sources. SIBERIAN should consume their exports or analyst observations; it should not become another raw evidence parser.

## Short first release

The first useful release is an offline Python CLI for one case at a time:

1. `validate` checks a versioned, analyst-authored JSON case file and refuses malformed or contradictory records.
2. `analyze` creates an evidence matrix with `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN`, and `OUT_OF_SCOPE`, reasons, source references, coverage counts, and a deterministic digest.
3. `explain` displays the conditions behind a row and what evidence is still missing.

The input describes evidence and its provenance; it does not contain raw forensic content. A human remains responsible for deciding whether each reference supports its claim. The library never queries a live endpoint or changes evidence.

## Claims and non-claims

SIBERIAN can help an analyst:

- distinguish an observed absence from an uncollected source, a coverage gap, an unverified condition, or an inapplicable artifact;
- see which applicability claims and source references support each row;
- hand another reviewer the same declared inputs and a digest that changes when those inputs change.

SIBERIAN does not detect deletion, prove intent, attribute an actor, estimate probability, or declare a host clean or compromised. A digest only binds the declared report fields; it does not establish that the evidence references are true or authentic.

## First-release acceptance boundary

- A case can be validated, analyzed, explained, and reproduced offline from a clean Python installation.
- Missing or malformed acquisition details remain errors or `UNKNOWN`; they never become `CONFIRMED_ABSENT` by default.
- Reports include every expected row for registered activities, distinct status/reason counts, provenance references, catalog/schema versions, and digest.
- Synthetic fixtures demonstrate complete coverage, unknown coverage, explicit non-applicability, and contradictory input handling. They exercise software behavior only; they are not Windows compatibility or adversary-validation results.
- `explain` suggests a next evidence check from the recorded uncertainty reason while keeping the row `UNKNOWN`.

## Evidence still needed to establish field utility

The workflow is plausible but not yet validated with practitioners. Before calling the tool useful in routine investigations, ask DFIR examiners to review realistic but privacy-safe case examples and determine whether the report helps them make a better next-step decision. Before claiming Windows artifact behavior, validate supported configurations and acquisition/loss boundaries in controlled Windows runs as defined in the [Level 1 protocol](LEVEL1_VALIDATION_PROTOCOL.md). NIST's [scientific foundation review](https://doi.org/10.6028/NIST.IR.8354) emphasizes context-sensitive interpretation and error mitigation in digital investigations; it does not validate SIBERIAN or establish demand for it.

## Deliberately deferred

- raw event-log, disk-image, or memory parsers;
- automatic collection or endpoint agents;
- weighted scores, probabilities, `PASS` / `WARN` / `ABSTAIN` verdicts, attribution, or intent inference;
- cross-case analytics, hosted service, LLM-generated conclusions, and broad multi-OS support;
- validated deletion-detection claims before controlled empirical results exist.

This keeps the first release small while preserving a credible path to a larger, validated analysis system if practitioner feedback and evidence justify it.
