# Plaso timeline import boundary

**Status:** design decision; no Plaso importer is implemented yet.

## Decision

SIBERIAN will not infer artifact absence from a missing row in a Plaso timeline.
Plaso exports are useful sources of observed events, but the `l2tcsv` format is
a general timeline format, not a SIBERIAN activity or coverage manifest. An
event row may support a `PRESENT` observation only after an analyst maps its
source and meaning to a SIBERIAN catalog artifact and records a traceable
reference. Unmapped rows remain outside the SIBERIAN case model.

An import must never create `CONFIRMED_ABSENT`, `UNKNOWN`, or
`OUT_OF_SCOPE` observations by counting or not finding rows. Those states
require explicit case declarations and supporting reasons or coverage evidence
under the existing [case file contract](CASE_FILE_FORMAT.md).

## Why generic CSV is insufficient

The official Plaso documentation describes `l2tcsv` as 17 fixed fields:
`date`, `time`, `timezone`, `MACB`, `source`, `sourcetype`, `type`, `user`,
`host`, `short`, `desc`, `version`, `filename`, `inode`, `notes`, `format`,
and `extra`. They describe timeline events and their sources, but do not
provide a SIBERIAN activity identifier or a complete-collection assertion.
Plaso also supports other output formats, so the importer must identify the
format rather than guess from a file extension.

`psort` can filter events and remove duplicates; its documentation reports
included and filtered counts, and describes duplicate removal. Therefore an
export with no matching row cannot distinguish “did not occur,” “not parsed,”
“filtered,” “deduplicated,” or “not included in this export.”

Primary references:

- [Plaso l2tcsv output format](https://github.com/log2timeline/plaso/blob/main/docs/sources/user/Output-format-l2tcsv.md)
- [Plaso using psort](https://github.com/log2timeline/plaso/blob/main/docs/sources/user/Using-psort.md)
- [Plaso using log2timeline](https://github.com/log2timeline/plaso/blob/main/docs/sources/user/Using-log2timeline.md)

## Future importer contract

If practitioner feedback justifies an adapter, its first version will:

1. Accept only a documented, explicitly selected Plaso output format and a
   bounded input file; reject malformed CSV, unexpected headers, invalid
   encoding, oversized fields, and ambiguous mappings.
2. Require a user-authored mapping from Plaso event attributes (at minimum
   `source`, `sourcetype`, `type`, and where needed `format`) to a registered
   SIBERIAN activity and artifact type. Free-text `desc` matching alone is not
   a sufficient mapping.
3. Convert only matched rows into `PRESENT` observations. Preserve source row
   identity and the input file's digest as provenance; never rewrite or modify
   the source export.
4. Keep unmatched rows as import diagnostics, not as artifact states.
5. Make no completeness claim from CSV row counts, export counters, or absent
   matches. An analyst may separately provide coverage and acquisition evidence
   through the case file, with the applicable scope and limitations recorded.
6. Produce deterministic import diagnostics and fail closed on ambiguity.

## Threat model and falsification

An importer must treat the CSV and mapping as untrusted input. A malformed,
filtered, truncated, or attacker-crafted export can cause incorrect present
claims or resource exhaustion. Bounds, strict parsing, explicit mapping, and
provenance address those risks; the adapter cannot establish that the Plaso
storage file or underlying acquisition is authentic or complete.

This decision should be revisited if Plaso documents a stable machine-readable
coverage manifest that binds the source set, parser configuration, filters,
processing outcomes, and exported events, and if an independent reviewer
confirms that the manifest supports the completeness claim. Even then, a
missing event would only be interpretable relative to that manifest's stated
scope and parser coverage.
