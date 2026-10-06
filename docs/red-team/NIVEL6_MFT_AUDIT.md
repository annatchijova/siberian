# Red-Team Audit — Nivel 6 Artifact Adapters (MFT pass)

Audit date: 2026-10-05
Scope: `siberian/mft_parser.py`, `siberian/cli.py` (`import-mft` and the shared
argument loop), `tests/test_mft_parser.py`
Method: adversarial self-review against NTFS on-disk layout, with every claim
backed by an executed probe. Claims that could not be reproduced were retracted.

---

## 1. Verdict

The MFT parser as committed in `f6729d6` was **not safe to use against real
evidence**. It reported wrong values while exiting `0`, and its JSON output path
crashed. Six defects were confirmed; four are fixed and verified by regression
tests that fail on the previous code. Two remain documented as limitations
because closing them requires Windows fixtures this repository does not have.

The single most serious defect is a **silent field misalignment**: resident
attribute content was read 8 bytes early, so `modification_time` reported the
file's **creation** time. That is a confidently false claim about when a file's
contents last changed — the kind of error that survives into a report because
nothing crashes and every value is plausible.

---

## 2. Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| MFT-01 | Critical | Resident attribute content read at `+16` instead of the resident content offset (`0x18`), shifting every `$STANDARD_INFORMATION` timestamp one field (8 bytes) | Fixed |
| MFT-02 | High | `MftRecord` had no `to_dict()`; `import-mft --output` raised `AttributeError` and exited `2` | Fixed |
| MFT-03 | High | Record size hardcoded to 1024; a 4096-byte-record volume misaligned every record (8 "records" read, 2 valid) | Fixed |
| MFT-04 | Medium | Truncated final record silently discarded instead of reported | Fixed |
| MFT-05 | Medium | `record_number` taken from the caller's index; the authoritative value at `0x2C` was parsed into an unused local and thrown away | Fixed |
| MFT-06 | Low | FILETIME conversion used float division (`ts / 10`) on a forensic value | Fixed |
| MFT-07 | Info | Update sequence array (fixups) was parsed but never applied | Fixed (see §4) |

### CLI-01 — Spurious `case_file` positional on every `import-*` command

The argument loop added a `case_file` positional to *every* subcommand, but the
five standalone artifact parsers never read it. All of them therefore demanded
an extra, meaningless positional argument:

```
$ python3 -m siberian.cli import-mft --help
positional arguments:
  case_file             analyst-authored JSON case file   <- never read
  mft_file              Path to NTFS $MFT binary file
```

Fixed by gating `case_file` to the seven commands that actually consume one
(`validate`, `analyze`, `explain`, `seal`, `verify`, `import-plaso`, `rivals`).
Verified: those seven still expose `case_file`; the five parsers now expose only
their own target.

---

## 3. Evidence

Ground truth was constructed independently of the parser: four **distinct,
non-zero** FILETIMEs written at known offsets inside a resident
`$STANDARD_INFORMATION`, then the parser's output compared field by field.

The pre-existing fixture wrote **all-zero** timestamps
(`tests/test_mft_parser.py`, lines 65-68), so an 8-byte misalignment produced
`None` in both the correct and the incorrect slot. No assertion on timestamps
could ever have detected MFT-01. This is the reason the defect survived six
passing tests.

### Before (`f6729d6`)

```
FAIL  SI modification_time == 2024-03-02  <- got 2024-03-01 00:00:00+00:00
FAIL  record.to_dict() -> JSON            <- 'MftRecord' object has no attribute 'to_dict'
FAIL  4096-byte records parse             <- n=8 valid=2
FAIL  truncated final record reported     <- n=1
REGRESSIONS DETECTED: 4
```

All four MACE timestamps were displaced by one field:

| Field | Reported | Ground truth |
|-------|----------|--------------|
| `creation_time` | `1601-01-01 02:51:47` (garbage) | `2024-03-01` |
| `modification_time` | `2024-03-01` | `2024-03-02` |
| `mft_modification_time` | `2024-03-02` | `2024-03-03` |
| `access_time` | `2024-03-03` | `2024-03-04` |

`creation_time` decoded the resident header's own content-length/offset fields as
a timestamp — a 1601 date presented as a file creation time.

### After

```
PASS  SI modification_time == 2024-03-02
PASS  sector tail 510 restored (fixups applied)
PASS  record_number comes from 0x2C
PASS  record.to_dict() -> JSON
PASS  4096-byte records parse
PASS  truncated final record reported
REGRESSIONS DETECTED: 0
```

Suite: **89 passed** (was 77; +12 MFT regression tests).

---

## 4. Refuted and narrowed claims

Per the mandatory refutation protocol, hypotheses that did not survive contact
with the evidence are recorded rather than quietly dropped.

### 4.1 RETRACTED — "real MFT records are rejected as invalid signature"

This audit initially concluded that unapplied fixups made the parser reject every
genuine `$MFT` record, because a probe using the fixup sentinel byte at offset 3
returned `Invalid signature: b'FIL\x00'`.

**That probe was circular.** I had written the sentinel into the signature
myself. NTFS fixups overwrite the last two bytes of each 512-byte **sector
tail** (offsets 510, 1022, 1534, ...), not the 4-byte signature at offset 0.
The signature is not corrupted by fixups. The claim is false and has been
withdrawn from the findings table as a "critical" defect.

### 4.2 NARROWED — fixups are defence in depth, not a timestamp fix

The mature reference parser in `vigia-repo/vigia/sift/mft_parser.py` (lines
20-22) deliberately skips fixups and documents why:

> NO aplica el fixup de Update Sequence Array (USA). Los timestamps viven en el
> primer sector del registro, antes del primer límite de sector, así que el
> fixup no los afecta en la práctica.

**This reasoning holds for MACE timestamps**, which sit at offset 56+ and so
almost never cross offset 510. The benign explanation largely survives: fixups
were not needed to fix MFT-01.

Fixups are still applied, on narrower and honest grounds: attribute *content*
and `$FILE_NAME` payloads can fall past offset 510 in records with many
attributes, and in 4096-byte records the protected positions are 510, 1022,
1534, 2046, 2558, 3070 and 3582. `apply_fixups()` is guarded to be idempotent —
it rewrites a sector tail only when that tail still holds the update sequence
number, so applying it twice, or to a record already repaired, cannot corrupt
genuine bytes (`test_fixups_do_not_corrupt_already_repaired_record`).

Severity therefore drops from Critical to Info (MFT-07).

### 4.3 Rejected — "the 12 new tests are sufficient evidence"

Passing tests are not evidence of correctness against an artifact class I cannot
produce here. All 12 new tests use synthetic records built from the layout
described above. They are **regression** tests: their demonstrated value is that
they fail on the previous code (verified by restoring `mft_parser.py.bak` and
re-running, §3). They are not validation against Windows.

---

## 5. Remaining limitations

These are **not** closed and must not be reported as working:

1. **No real `$MFT` fixture.** Every test uses synthetic records. Layout
   conformance rests on the NTFS specification, not on observed bytes.
2. **Windows validation still pending.** Requires an acquired image on a real
   volume.
3. **No non-resident `$DATA` extraction.** `$FILE_NAME` and
   `$STANDARD_INFORMATION` are always resident and are handled. Non-resident
   attribute content is deliberately **not** interpreted — the run list is not
   content — so file size for large files is not yet reported. The reference
   implementation derives it from `$DATA`; this parser does not.
4. **`real_size` is misnamed.** Header offset `0x18` is the *used size of the
   MFT record*, not the size of the file the record describes. The field name
   invites exactly the wrong conclusion and is left in place only to avoid a
   breaking rename; it is flagged here for correction.
5. **Third MFT parser in the workspace.** `siberian/mft_parser.py`,
   `vigia-repo/vigia/sift/mft_parser.py` and
   `crucible-corpora/.../analyzing-mft.../scripts/agent.py` now diverge. The VIGÍA
   implementation is more mature (extracts `$DATA` sizes, ADS names, produces
   JSON, has real-fixture tests). Maintaining a third divergent parser is itself
   a defect; consolidating onto one canonical implementation is the correct
   direction.

---

## 6. Test evidence

New regression tests in `tests/test_mft_parser.py`:

- `test_resident_si_timestamps_are_not_field_shifted` — MFT-01, four distinct dates
- `test_fixups_restore_sector_tail_bytes` — MFT-07
- `test_fixups_do_not_corrupt_already_repaired_record` — idempotence guard
- `test_embedded_record_number_is_authoritative` — MFT-05, via mismatch
- `test_record_number_agreement_recorded` — agreement is provenance, not silence
- `test_non_resident_standard_information_is_not_read_as_timestamps` — run list is not content
- `test_detect_mft_record_size_from_allocated_size` — MFT-03
- `test_parse_mft_file_handles_4096_byte_records` — MFT-03 end-to-end
- `test_parse_mft_file_reports_truncated_final_record` — MFT-04
- `test_record_to_dict_is_json_serializable` — MFT-02
- `test_timestamp_conversion_is_exact_and_deterministic` — MFT-06
- `test_negative_and_huge_timestamps_rejected` — nonsense in, `None` out

---

*Defects are claims until reproduced against the running code. Two claims in this
audit were refuted by that discipline, one of them by the reviewer's own
circular probe.*
