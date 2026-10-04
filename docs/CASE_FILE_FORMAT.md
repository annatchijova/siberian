# SIBERIAN case file v1

The CLI accepts one analyst-authored JSON object per case. It contains references and declarations, not raw evidence. Unknown fields and duplicate JSON keys are errors. Files are limited to 5 MiB. Timestamps must be ISO 8601 strings with a timezone.

## Commands

Run from a source checkout:

```console
python -m siberian.cli validate examples/case-acquisition-gap.json
python -m siberian.cli analyze examples/case-acquisition-gap.json
python -m siberian.cli explain examples/case-acquisition-gap.json
```

After package installation, use the equivalent `siberian` command. `validate` checks the whole case against the catalog and API rules. `analyze` writes a JSON evidence matrix to standard output. `explain` prints each row, its reason, catalog conditions, and sources. All commands are offline and read-only apart from reading the case file.

## Shape

- Root keys: `schema_version`, `context`, and `activities`.
- `schema_version` must be `siberian-case-v1`.
- `context` requires `os_profile`, `os_release`, `system_build` (string or `null`), `scope`, timezone-aware `interval_start` / `interval_end`, and `acquisition_ref`. Edition, architecture, build revision, and servicing channel are optional declarations.
- Each activity has a catalog `action`, optional `primary_action_evidence`, and an `observations` array. Each action can occur once.
- Each observation names a catalog `artifact_type` and one of `present`, `confirmed_absent`, `unknown`, or `out_of_scope`. An artifact can occur once under an activity.
- `present` needs `evidence_ref`. `confirmed_absent` needs `evidence_ref`, timestamped `primary_action_evidence` inside the case interval, a declared system build, catalog scope, and a reference with validity interval for every required condition. References are checked for presence and declared interval only, not truth.
- An explicit `unknown` requires a reason from `ObservationReason`; an omitted catalog row remains `UNKNOWN` with `conditions_unverified` or `catalog_scope_unverified`.
- `out_of_scope` requires reason `not_applicable` and an `evidence_ref`.

See [`examples/case-acquisition-gap.json`](../examples/case-acquisition-gap.json) for one unknown row caused by an acquisition gap and [`examples/case-mixed-statuses.json`](../examples/case-mixed-statuses.json) for a synthetic example of all four statuses. These files exercise the report model only; they are not Windows test results.

## Result contract

`analyze` reports schema/catalog versions, declared context, status counts, all catalog rows for registered activities, evidence references, applicability evidence, and the library's deterministic SHA-256 digest. The digest is not a signature and does not authenticate source material. The CLI never turns `UNKNOWN` into `CONFIRMED_ABSENT` and never infers deletion or intent.
