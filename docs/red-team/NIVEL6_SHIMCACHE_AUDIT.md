# Red-Team Audit — Nivel 6 Shimcache Parser

Audit date: 2026-10-05
Scope: `siberian/shimcache_parser.py`, `tests/test_shimcache_parser.py`
Evidence available: **none.** No `SYSTEM` hive exists in this workspace.
Reference consulted: `regipy` shimcache plugin (installed)

---

## 1. Verdict

Two of my initial hypotheses were **refuted by experiment** and are recorded as
such in §4. What survived is narrower but real: the parser could consume the
wrong registry value and blame the artifact format for the result, it presented
a constant `0` as a parsed `flags` field, and a failed lookup was
undiagnosable.

The deeper problem is structural. This parser does not decode the shimcache
record layout at all — it looks for a length prefix and then scans for a UTF-16
path — yet it emitted fields (`flags`, `last_modified`, `entry_size`) that read
as though they had been parsed. The fix was to make the recovery method visible
in the data and the terminal output, not to add more guessed fields.

---

## 2. Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SHIM-01 | High | The `AppCompatCache` subkey branch accepted **any** binary value: the condition was `name == "AppCompatCache" or isinstance(value.value(), bytes)`. The first unrelated binary value was consumed | Fixed — name-matched only |
| SHIM-02 | High | Only one registry value name was accepted; the alternate spelling used by other Windows versions was never tried, with no fallback that reports what was present | Fixed — both names tried, match recorded |
| SHIM-03 | Medium | Failure reported only as "AppCompatCache key not found", indistinguishable from a hive with no shimcache at all | Fixed — names the control sets and values actually inspected |
| SHIM-04 | Medium | `flags` defaulted to `0`, indistinguishable from a real flag value of zero, and was never populated | Fixed — now `None`, explicitly absent |
| SHIM-05 | Medium | No provenance: a path recovered by whole-blob scanning was indistinguishable from a length-framed record | Fixed — `parse_method` on every entry and in the summary line |
| SHIM-06 | Low | An unrecovered timestamp printed as `unknown`, which reads like a value | Fixed — prints `not recovered` |
| SHIM-07 | Low | Two bare `except Exception: pass` blocks silently swallowed navigation errors, then reported "not found" | Fixed — navigation failures surface in the diagnostic message |

---

## 3. Evidence

SHIM-01 and SHIM-02 were demonstrated with a stub hive, because python-registry
can only open real hives and none is available. The stub mimics the
python-registry surface (`root`/`subkeys`/`subkey`/`values`/`name`/`value`) and
therefore tests the **selection logic only**, not the on-disk format.

Case: `Session Manager` holds an `AppCompatCache` subkey containing an unrelated
`SomeVendorBlob` (REG_BINARY) followed by the real payload under a name this
parser does not recognise.

```
OLD: path='' error='No entries parsed - format may be unsupported for this Windows version'
NEW: path='' error='AppCompatCache value not found. Looked for AppCompatCache and
     AppCompatibilityCache under ControlSet\Control\Session Manager.
     control sets seen: ControlSet001;
     values present: AppCompatCache\OtherName, AppCompatCache\SomeVendorBlob'
```

The old behaviour is the damaging one twice over: it consumed the wrong value,
produced nothing from it, and then attributed the failure to the *format* —
sending an analyst to debug the artifact instead of the parser.

Both new tests fail against the previous parser:

```
FAILED test_unnamed_binary_in_cache_subkey_is_not_consumed
FAILED test_known_name_inside_cache_subkey_is_found
```

A defect was also introduced and caught during this audit: the first version of
the corrected failure message reported "Session Manager not reachable" when
Session Manager *was* reachable but held no direct values. Caught by the stub
probe, fixed, and now asserted.

---

## 4. Refuted claims

### 4.1 RETRACTED — "the parser invents timestamps from arbitrary bytes"

The code does scan for the first 8-byte window decoding to a FILETIME between
2010 and 2030. I expected this to fire constantly. It does not.

```
trials                        : 400
entries with an invented time : 0  (0.0%)
```

400 realistic entries — ASCII path fragments, `.dll` names, repeated separators —
produced **zero** false-positive timestamps, because the 2010-2030 FILETIME
window is numerically narrow (~6.4e15 of 2^64) and structured ASCII does not land
in it. Pure random noise also produced nothing, since the scan only runs after a
plausible path has already been found.

The code is still fragile in principle: a timestamp is attributed to
`last_modified` purely by falling in a date range, with no positional
justification. But "it would invent timestamps" was not demonstrated and is
withdrawn as a finding.

### 4.2 RETRACTED — "the registry value name is misspelled"

I expected `AppCompatCache` to be wrong, believing the Windows 10 value is
`AppCompatibilityCache`. Searching the workspace found **zero** occurrences of
the longer spelling and `regipy` — a mature implementation — uses `AppCompatCache`
for both the subkey and the value. The existing spelling was not a typo.

The defensible version of the concern is SHIM-02: name matching was exact and
single-spelled, with no diagnostic on failure, so a spelling this parser does not
know is indistinguishable from an absent artifact. Both spellings are now tried
and the match is recorded; no claim is made about which Windows versions use
which.

### 4.3 Rejected — "the odd-offset UTF-16 slice truncates paths"

`_extract_utf16_paths` searches for `b"\x00\x00"` from a moving offset, which can
land on an odd index and yield an odd-length slice that drops the final
character. This is a real latent bug (it was observed in the sibling Shellbags
parser, where `Desktop` came back as `Deskto`). It did **not** reproduce here, so
it is recorded as a latent risk rather than a confirmed Shimcache defect.

---

## 5. Remaining limitations

1. **No SYSTEM hive exists in this workspace.** Neither the record layout nor the
   registry value name is validated against real evidence. This is the central
   limitation.
2. **The record layout is not implemented.** `entry_size` is the heuristic length
   that framed a scan, not a verified record size. `flags` is absent by design.
   Any consumer must treat these entries as *recovered path strings*, not decoded
   records.
3. **The timestamp heuristic is positionally unjustified.** A value is labelled
   `last_modified` because it decodes into 2010-2030, not because its offset is
   known. It is retained because it did not produce false positives in testing,
   and it is now accompanied by `parse_method` so a reader can discount it.
4. **Undocumented Windows-version coverage.** No claim is made about which
   versions produce which layout.
5. **`Registry` is still an undeclared dependency** (`dependencies = []`).

---

## 6. Test evidence

17 tests, up from 7. Provenance tests:

- `test_flags_is_never_a_defaulted_zero`
- `test_entry_declares_how_it_was_recovered`
- `test_summary_shows_recovery_method_and_source`
- `test_summary_does_not_say_unknown_for_an_unrecovered_timestamp`
- `test_json_roundtrip_includes_provenance`

Registry selection tests (stub hive):

- `test_both_known_value_names_are_found` (both spellings)
- `test_unrelated_binary_value_is_not_taken`
- `test_unnamed_binary_in_cache_subkey_is_not_consumed` — SHIM-01
- `test_known_name_inside_cache_subkey_is_found`
- `test_failure_message_names_what_was_actually_present` — SHIM-03
- `test_no_control_set_present_is_reported`

7 of these fail against the previous parser.

Suite: **149 passing**.

---

*The honest description of a heuristic scanner is "a heuristic scanner".
Adding a field that looks parsed is how a tool starts lying by accident.*
