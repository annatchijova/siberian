# Red-Team Audit — Nivel 6 Shellbags Parser

Audit date: 2026-10-05
Scope: `siberian/shellbags_parser.py`, `tests/test_shellbags_parser.py`
Evidence available: **none.** No `NTUSER.DAT` or `UsrClass.dat` in this workspace.

---

## 1. Verdict

The worst defects of the five parsers audited so far. This one produced
**plausible-looking wrong paths** and **invented user-interface settings** that
no artifact contained.

Two of the three headline defects are silent: nothing crashes, every value looks
reasonable, and the tool exits 0.

```
FAIL  clean path not truncated            <- got 'C:\Users\Bob\Deskto'
FAIL  paths found in realistic blobs      <- exact 0/200, not-found 199/200
FAIL  paths recovered from the REAL tree level  <- recovered 0/5
```

---

## 2. Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SHB-01 | Critical | `_extract_path_from_binary` sliced to wherever `b"\x00\x00"` happened to land. On an odd offset the slice had odd length and UTF-16 decoding **silently dropped the final character**: `C:\Users\Bob\Desktop` → `C:\Users\Bob\Deskto` | Fixed |
| SHB-02 | Critical | With any bytes before the path, extraction failed **199 of 200** times — the scan never realigned. A real shellbag value is not a bare path at offset 0 | Fixed — both byte parities scanned |
| SHB-03 | High | Read only the values on the `BagMRU` key itself. In a real hive the per-entry data lives in the numbered subkeys *below* it, so **0 of 200** folders were recovered from a realistically shaped hive | Fixed — both levels read |
| SHB-04 | High | `view_mode` invented by scanning 11 fixed byte offsets and taking the first byte present in a 7-entry lookup table. A random byte matches that table **2.7%** of the time, so roughly a quarter of the entries read got a fabricated view mode | Field removed |
| SHB-05 | High | `sort_mode` invented the same way against an 8-entry table (**3.1%** random match rate) | Field removed |
| SHB-06 | Medium | `timestamp` labelled "accessed" was the last 8 bytes of the value if they decoded to a year in 2000-2030 — no positional justification for that field | Field removed |
| SHB-07 | Medium | No depth bound on registry recursion | Fixed — bounded at 8 |
| SHB-08 | Low | Navigation failures were indistinguishable from "no shellbags present" | Fixed |
| SHB-09 | Low | `_filetime(-1)` returned a 1601-adjacent date instead of `None`; the same missing guard existed in the Shimcache and MFT parsers | Fixed in all three |

### Why removing the fields was the right call

`view_mode`, `sort_mode` and `timestamp` had **no positional justification**.
They were not decoded from known offsets — they were "the first byte in a
range that happens to be in my table". A tool that emits them is asserting that
a user browsed a folder in Details view, sorted by date, at a specific time,
with no evidence for any of it. The fields are removed rather than retained
with a warning, because a consumer reading JSON would use the value regardless
of any caveat attached to it.

This is the same decision taken for Shimcache's `flags`, applied consistently.

---

## 3. Evidence

### The truncation (SHB-01)

```
input : 'C:\Users\Bob\Desktop'
output: 'C:\Users\Bob\Deskto'
```

UTF-16-LE code units are two bytes. Searching for `b"\x00\x00"` from a moving
offset finds a match at the *second* byte of the final character `p` (`70 00`),
producing an odd-length slice whose last code unit is incomplete. Decoding drops
it silently. The result is a different, entirely plausible path — the worst
failure mode for a forensic path, because it survives a visual check.

### The miss rate (SHB-02)

200 blobs, each a real path preceded by 1-19 arbitrary bytes:

| | old | new |
|---|---|---|
| exact | 0/200 | 200/200 |
| truncated | 1/200 | 0/200 |
| not found | 199/200 | 0/200 |

300 pure-noise blobs yield a path in **0** cases, so the corrected scanner is not
merely more permissive.

### The tree level (SHB-03)

200 keys in the realistic shape (`BagMRU\<N>` holding the entry data):

| shape | old | new |
|-------|-----|-----|
| real (`BagMRU\<N>` holds data) | 0 paths | 200 paths |
| flat (data on `BagMRU` itself) | 0 paths | 200 paths |

### The invented settings (SHB-04/05)

With entry data placed where the old parser looked, 200 keys produced:

```
entries=202  with_path=0  view_mode=47  sort_mode=54
```

No view or sort settings were encoded in any of those keys. 47 view modes and
54 sort modes were invented.

---

## 4. Refuted claims

### 4.1 Partially refuted — "the lookup tables are the problem"

The maps themselves are not wrong as *vocabularies*; Windows really does have
those view and sort modes. The defect is using a small vocabulary table as an
oracle over arbitrary bytes with no positional constraint. Removing the fields
is a consequence of that, not a claim that the vocabularies are fictional.

### 4.2 Rejected — "the old test suite covered this"

The previous test asserted:

```python
assert "Desktop" in path
```

which passes for `"C:\Users\Test\Deskto"`. The truncation bug was invisible
because the assertion was written to accommodate it. Every replacement assertion
in the new file compares the **full string**.

---

## 5. Remaining limitations

1. **No user hive exists in this workspace.** Traversal is tested with a stub
   mimicking the python-registry surface. Selection and extraction logic are
   covered; the on-disk shellbag record layout is not.
2. **The record layout is still not decoded.** Only UTF-16 path strings are
   recovered. Real shellbag entries carry more structure (slot identifiers,
   view settings, item ordering) that this parser ignores. It should be read as
   "folder path strings present in the hive", nothing stronger.
3. **Which tree levels carry data varies** by Windows version and by whether the
   hive is `NTUSER.DAT` or `UsrClass.dat`. Both levels and both locations are
   read, but no claim is made about completeness for any specific build.
4. **Paths are recovered, not resolved.** A recovered string is not proof the
   folder existed; it is evidence Explorer recorded the path. Callers must not
   upgrade it.
5. **`Registry` remains an undeclared dependency.**

---

## 6. Test evidence

20 tests, up from 8. Extraction:

- `test_clean_path_is_extracted_exactly` — SHB-01
- `test_path_is_found_at_either_byte_alignment`
- `test_many_random_prefixes_all_yield_the_exact_path` — SHB-02 (200 cases)
- `test_noise_does_not_yield_a_path` — 300 noise blobs
- `test_all_paths_are_reported_not_just_the_first`
- `test_unc_path_is_extracted`, `test_path_shaped_validation`

Absent-instead-of-invented:

- `test_entry_has_no_invented_view_or_sort_fields` — asserts the exact key set
- `test_summary_reports_only_what_was_recovered`

Traversal (stub hive):

- `test_paths_in_numbered_subkeys_are_found` — SHB-03
- `test_classes_based_shellbags_are_found` — UsrClass.dat location
- `test_bookkeeping_values_are_skipped` — MRUList / NodeSlotCapacity
- `test_missing_hive_is_an_explicit_error`
- `test_hive_without_shellbags_is_an_explicit_error`
- `test_present_keys_without_recoverable_paths_is_reported`
- `test_deep_nesting_does_not_recurse_without_bound` — SHB-07

The three regressions were reproduced with a probe importing only the previous
parser's API (SHB-01/02/03), plus the invented-field counts above.

Suite: **163 passing**.

---

*`C:\Users\Bob\Deskto` is not a typo in a report. It is a fabricated path that
no folder ever had — produced by a parser that reported success.*
