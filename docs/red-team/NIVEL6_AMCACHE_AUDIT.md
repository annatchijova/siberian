# Red-Team Audit — Nivel 6 Amcache Parser

Audit date: 2026-10-05
Scope: `siberian/amcache_parser.py`, `tests/test_amcache_parser.py`,
`siberian/cli.py` (`import-amcache`), plus the new
`tests/test_cli_adapters.py`
Reference implementation used: `regipy` Amcache plugin (installed), cross-read
against `volatility3`

---

## 1. Verdict

The Amcache parser as committed in `c6eb8e3` would **report programs that do not
exist**, and would report a total failure as a successful parse.

The two most serious behaviours, both reproduced:

```
FAIL  missing hive exposes .error
      error=None; failure hidden in raw_values={'error': "Cannot open hive: ..."}
FAIL  missing hive yields no entries        <- returned 1 fake 'entry'
FAIL  arbitrary 64-byte blob NOT decoded as a FILETIME
      _parse_filetime_bytes(blob) -> 3204-10-05 00:31:31.423052+00:00
```

The third line is the core defect: **any** binary value of 8 bytes or more was
decoded as a Windows FILETIME. `bytes(range(64))` — arbitrary data — became the
date **3204-10-05**. Applied to a real hive, every SHA1 hash, PE header blob and
run list in the file becomes a plausible-looking timestamp.

---

## 2. Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| AMC-01 | Critical | Generic recursive scan of the whole hive; any key containing a value named `Name`/`Path`/`Publisher` was reported as an application entry. Amcache.hve is a registry hive containing many unrelated keys | Fixed — only the two documented sections are read |
| AMC-02 | Critical | Every binary value ≥8 bytes decoded as a FILETIME. Arbitrary bytes produced a year-3204 date | Fixed — only the three documented timestamp fields are converted |
| AMC-03 | High | Failure returned as a synthetic "Error" entry whose `.error` was `None`; the CLI printed "Parsed 1 Amcache entries" and **exited 0** | Fixed — failures live in `AmcacheResult.errors`; exit 1 |
| AMC-04 | High | `sha1` / `program_id` / `file_id` carry a 4-byte binary prefix that was never stripped, so the digest was wrong | Fixed |
| AMC-05 | High | Value names are **hexadecimal indices** (`program_id` is `"100"`, `sha1` is `"101"`); the parser looked for `"ProgramId"`/`"Name"`, so real fields were never found | Fixed |
| AMC-06 | Medium | `file_size` is a hex string in Amcache; no hex coercion was applied | Fixed |
| AMC-07 | Medium | `python-registry` is required but `pyproject.toml` declares `dependencies = []`, while the README claims the project is dependency-free | Documented — see §5 |
| AMC-08 | Medium | Timestamp recovery was two-stage fabrication: binary → guessed ISO string → "timestamp" by matching `"T"` and the substring `first`/`last` | Fixed |
| AMC-09 | Low | Docstring described Amcache.hve as "Application TimelineCache"; the Timeline is a different artifact (SRUM) | Fixed |

---

## 3. What the corrected parser actually reads

From the `regipy` plugin, which is a mature implementation:

- Sections: `\Root\File` and `\Root\InventoryApplicationFile`. Nothing else.
- Field names are hexadecimal indices, mapped via a 24-entry table
  (`"100" → program_id`, `"101" → sha1`, `"15" → full_path`, `"6" → file_size`,
  `"11"/"12"/"17" → timestamps`).
- `sha1`, `program_id` and `file_id` carry a **4-byte binary prefix** that must
  be stripped.
- `file_size` is a hex string: `int(size, 16)`.
- Exactly **three** fields are FILETIMEs, plus the subkey header's own
  `last_modified`, which is reported separately as `key_timestamp`.

`regipy` identifies an Amcache hive by filename and by the presence of those two
keys; it does not use a magic hive type. The corrected parser follows the same
rule and reports a hive lacking both sections as *not an Amcache hive* rather
than scanning it for anything program-shaped.

---

## 4. Evidence

Behavioural regressions were demonstrated by running a probe that imports **only
symbols that existed in the previous parser**, so the comparison is not merely an
import error. Before/after:

| Check | Old (`c6eb8e3`) | Now |
|-------|-----------------|-----|
| Missing hive → entries | 1 fake entry | 0 |
| Missing hive → `.error` | `None` (hidden in `raw_values`) | `errors=['Hive not found: ...']` |
| Missing hive → exit code | 0 | 1 |
| `bytes(range(64))` as a value | `3204-10-05 00:31:31` | left as data |
| CLI JSON on failure | list containing a fake entry | `{"entries": [], "errors": [...]}` |

A defect was also introduced and caught during this audit's own work: the
rewritten Amcache handler shipped a typo, `args.amcache_hive` instead of
`args.amcache_hve`. Every parser unit test still passed because none of them
invoked the handler. That prompted `tests/test_cli_adapters.py`, which calls the
handlers directly. It immediately found the **same** exit-0-on-failure defect
still present in `import-shimcache` and `import-shellbags`, which has now been
fixed in all three handlers.

---

## 5. Remaining limitations

1. **No Amcache.hve exists in this workspace.** The field mapping is tested
   against the documented layout and the mature `regipy` implementation, but it
   has **never run on a real hive**. This is the central limitation of this
   audit.
2. **No fixture can be authored.** Neither `python-registry` (open-only) nor
   `regipy` (read-only parser) can create a hive, so a synthetic `.hve` was not
   an option. The pure entry parser was therefore made registry-free and tested
   with plain dictionaries; the thin traversal layer is exercised only by
   failure paths.
3. **`python-registry` is an undeclared dependency** (`dependencies = []`).
   Unlike Prefetch — where `pyscca` at least yields correct values — this
   parser combines an undeclared dependency with structure it cannot validate.
   Declaring it is the honest fix and is left as a follow-up rather than done
   silently here.
4. **`linker_compile_time` and `language_code`** are mapped but not surfaced as
   first-class fields; they remain in `raw_values`.
5. **`\Root\Device` and `\Root\Driver`** sections are not read. They exist in
   Amcache and would need their own field mapping.

---

## 6. Test evidence

- `tests/test_amcache_parser.py`: 17 tests, replacing 8 that covered only a
  helper's existence and the error-entry path. Includes
  `test_unrelated_binary_value_is_not_converted_to_a_timestamp`, which asserts
  that no value anywhere in the entry became a datetime.
- `tests/test_cli_adapters.py`: 24 tests covering the exit-code contract
  (0 / 1 partial / 2 cannot-run) for all five artifact adapters, JSON output
  shape on failure, and the `case_file` positional contract.

Suite: **137 passing**.

---

*Structure that cannot be validated locally should be read narrowly. The
correction here reduces what this parser claims to know, which is the only
honest direction when no real hive is available.*
