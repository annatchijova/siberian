# Red-Team Audit — Nivel 6 Prefetch Parser

Audit date: 2026-10-05
Scope: `siberian/prefetch_parser.py`, `tests/test_prefetch_parser.py`,
`siberian/cli.py` (`import-prefetch`)
Evidence used: **225 real Windows 10 prefetch artifacts** from the OWL 2019
disk image at `vigia-repo/evidence/owl-2019-hd1-windows/prefetch/`

---

## 1. Verdict, and how it changed

The first hypothesis going into this audit was that the parser was broadly
broken, based on reading its SCCA branch. **That hypothesis was wrong and was
withdrawn.**

Cross-checking the MAM path against `pyscca` directly on real files:

```
files cross-checked      : 59
filename mismatches      : 0
run_count mismatches     : 0
last_exec mismatches     : 0
```

The MAM path (Windows 10+, 222 of the 225 real files) was **already
functionally correct**. Reporting it as broken would have been overinterpretation.

The real damage was narrower and is more interesting: a correct code path
carried an **unverifiable SCCA path that fabricated values**, the test suite
**could not fail**, and the artifact digest was **truncated**.

---

## 2. Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| PF-01 | Critical | SCCA fields decoded at invented offsets: version read from a field the code's own comment called "file size"; `last_execution_time` read from offset 72, which lies **inside** the 60-byte filename field, decoding filename characters as a FILETIME | Fixed — hand-decoding removed |
| PF-02 | High | The SCCA test fixture encoded the same invented layout, so the suite confirmed the parser against its own error | Fixed |
| PF-03 | High | `assert record.format_version is not None or record.format_version is None` — a tautology, true for every value, incapable of failing | Fixed |
| PF-04 | Medium | `format_version` hardcoded to `30` for every MAM file instead of read from the artifact, though `pyscca` exposes it | Fixed |
| PF-05 | Medium | `file_hash` was SHA-256 truncated to 16 hex chars (64 bits) and presented as the artifact hash | Fixed — full digest, plus the Windows prefetch hash |
| PF-06 | Medium | Directory parse reported only a count; failures were folded into a success exit code | Fixed — errors on stderr, exit 1 unless `--allow-partial` |
| PF-07 | Low | 3 full-size, entirely zero-filled prefetch files were reported as "unrecognised container", burying a real artifact phenomenon | Fixed — classified `ZERO_FILLED` |
| PF-08 | Info | No test had ever run against a real prefetch file, despite 225 being available in the workspace | Fixed — 6 tests now run against real artifacts |

---

## 3. Evidence

### 3.1 The fabricated SCCA timestamp (PF-01)

A buffer laid out the way the parser expected, with a real path string in the
field the code believed held the filename:

```
DEFECT: 'last_execution_time' is read from offset 72, which lies INSIDE
        the 60-byte filename field (0x14=20 .. 0x50=80).
        bytes actually at 72: 00 00 76 a4 16 c5 da 01
```

The parser decoded UTF-16 characters of a file path as a 64-bit FILETIME and
emitted a confident `last_execution_time`. For a forensic artifact, a fabricated
execution timestamp is worse than a missing one: it looks like evidence of
execution.

The version field had the same shape of defect — read from offset 8, which the
parser's own docstring labelled "File size".

### 3.2 The tautology (PF-03)

```python
assert record.format_version is not None or record.format_version is None
```

Six prefetch tests passed while this line asserted nothing. Any value satisfies
it, including the absence of a value.

### 3.3 The digest (PF-05)

```
full sha256 : 0257965c789cbd367571c5f6a8063c2f93d3f0e42a87c02aecc5793697d80d2f
reported    : 0257965c789cbd36            (64 bits)
```

### 3.4 The zero-filled artifacts (PF-07)

Three real files are full-size but contain no bytes other than zero:

```
CONHOST.EXE-0C6456FB.pf    size= 5338  all_zero=True
TASKHOSTW.EXE-2E5D4B75.pf  size=16376  all_zero=True
WERMGR.EXE-F439C551.pf     size= 7415  all_zero=True
```

`pyscca` cannot open them. They are now reported as `ZERO_FILLED` — the
allocation exists but holds no prefetch structure — which is an observation
about the artifact rather than a parse failure.

### 3.5 What the real corpus settled

Signature survey over all 225 files:

```
b'MAM\x04' ... -> 222 files
b'\x00'*8      ->   3 files   (the zero-filled artifacts)
files containing SCCA or PFSF in the first 8 bytes: NONE
```

So the MAM-at-offset-0 detection is confirmed by real evidence, and **no SCCA
fixture exists anywhere in this workspace.**

A new cross-check was added that the corpus makes possible: the 8-hex suffix in
the `.pf` filename is the Windows prefetch hash, and `pyscca` recovers it from
the file's content. Agreement across the corpus:

```
stem hash == content prefetch_hash : 222
mismatches                         : 0
```

A file whose name disagrees with its own content is now flagged in the summary
line and on stderr.

---

## 4. Refuted and unresolved claims

### 4.1 RETRACTED — "the parser rejects all SCCA files"

The audit initially asserted that `SCCA` belongs at offset 0 and that the
parser's offset-4 check would reject every genuine XP..8.1 file. A probe built
to that layout returned `Invalid signature`.

**This could not be established.** `vigia-repo/vigia/sift/prefetch_analyzer.py`
(lines 293-298) asserts the opposite — signature at offset 4 — and cites its own
audit fix ("P1-B") for having corrected it. Two implementations in the same
workspace disagree, and **zero SCCA samples exist locally to adjudicate**.

The claim is withdrawn rather than asserted in either direction.

### 4.2 Resolution — stop guessing, delegate

Rather than pick a side, the SCCA field decoding was **deleted**. All structural
parsing now goes through `pyscca`, which handles both containers — the same
approach the mature VIGÍA reference already uses (it derives the filename from
the stem and obtains every other field via pyscca, and never hand-decodes SCCA
offsets).

Detection remains deliberately tolerant (SCCA accepted at offset 0 *or* 4) since
detection is cheap and does not risk fabricating values. Field extraction is no
longer speculative.

**Consequence, stated plainly:** if pyscca cannot read a given SCCA file, this
parser now reports that fact instead of returning invented values. That is a
reduction in reported output and an increase in correctness.

### 4.3 Unresolved — SCCA remains unvalidated

SCCA (Windows XP..8.1) support is **untested against real data**. Resolving it
requires a Windows XP/7/8.1 image. Until then the format's support level is
"delegated to libscca", not "validated".

---

## 5. Remaining limitations

1. **No SCCA fixture.** SCCA handling is delegated to libscca and unverified.
2. **pyscca is now a hard requirement for structural fields.** It is installed
   in this workspace. Without it, records are marked `degraded` and carry no
   timing values; nothing is estimated. Verified by
   `test_missing_pyscca_degrades_without_inventing_values`.
3. **`run_count` and `last_execution_time` come from libscca's interpretation.**
   Cross-checked against itself, not against an independent second
   implementation. A shared upstream error would not be detected.
4. **The zero-filled artifacts are unexplained.** Their cause (never populated
   vs. deliberately zeroed) is not determined here and is not inferred.
5. **Windows 11 and MAM version variants are unexamined.** The corpus is a
   single Windows 10 image.

---

## 6. Test evidence

21 tests, up from 6. Six run against real artifacts and skip cleanly when the
evidence path is absent:

- `test_real_mam_file_structure` — content-derived fields vs. known values
- `test_real_filename_hash_agrees_with_content_hash` — 222 files, 0 mismatches
- `test_real_corpus_has_no_invented_values` — no real file lost its timing
- `test_real_directory_stats_account_for_every_file` — parsed + errors + degraded == total
- `test_real_corpus_zero_filled_files_are_classified` — the 3 known artifacts
- `test_summary_line_flags_hash_mismatch` — mismatch is visible in the terminal

Plus non-evidence tests for filename conventions, container detection, digest
length, FILETIME determinism, and pyscca-absent degradation.

Full suite: **104 passing**.

---

*An audit that cannot report "this part was already correct" is not an audit,
it is a hunt for something to blame.*
