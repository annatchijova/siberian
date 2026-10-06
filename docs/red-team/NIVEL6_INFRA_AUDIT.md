# Red-Team Audit — Nivel 6 Infrastructure (final pass)

Audit date: 2026-10-05
Scope: the infrastructure written after the five parser audits —
`siberian/export_seal.py`, `siberian/batch.py`,
`siberian/adapter_provenance.py`, `forensics/verify_siberian.py`, and the CLI
wiring for `batch` and for sealing

The five parsers were audited separately (see `NIVEL6_*_AUDIT.md`). This pass
covers the code that had not been reviewed by anything except its own tests.

---

## 1. Verdict

Four defects, one of which undermines the headline guarantee of the whole
exercise: **the independent verifier implemented a strict subset of the hash
protocol it claimed to implement.** `Fraction` was missing from its
canonicalizer. Both implementations claimed conformance; they disagreed on that
type; and nothing in the suite noticed.

That is precisely the failure mode independence is supposed to prevent, produced
by the independence work itself.

---

## 2. Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| INF-01 | **High** | `verify_siberian.py` could not canonicalize `Fraction`, which canonicalization v2 defines. The producer could. The two implementations therefore implemented different functions while both claiming to implement v2 | Fixed + pinned by 25 cross-implementation tests |
| INF-02 | Medium | `run_batch()` accepted an `allow_partial` argument and never read it. A caller using the module directly would reasonably believe it controlled the outcome | Fixed — parameter removed, reasoning documented |
| INF-03 | Medium | Adapter tracebacks were stored in the **sealed** batch manifest, embedding the analyst's absolute install paths and code layout in an artifact intended for third parties. Once sealed, the leak cannot be scrubbed without breaking the seal | Fixed — frames go to stderr, type and message retained |
| INF-04 | **High** | The sealed **batch manifest carried no provenance**, so the standalone verifier rejected it (`V6 provenance is an object -> got NoneType`). A sealed artifact that the verifier refuses is worse than an unsealed one: the analyst is told their own export is broken. It also meant the batch's index never stated the parser version or its limitations | Fixed — manifest carries full provenance and one source entry per input |
| INF-05 | Low | `batch.py` imported `sys` without using it | Fixed |

---

## 3. INF-01: the verifier implemented a subset

### Why this is the serious one

The entire argument for a separate verifier is that it must not share code with
the producer. That argument only holds if the verifier implements the *documented
protocol*. If it implements a subset, then:

- agreement between the two proves less than it appears to, and
- any input outside the subset is a **false negative**: the verifier reports a
  verification failure for a document that is in fact intact.

A false negative is the dangerous direction. An analyst who sees "FAILED" on an
untampered export learns to distrust the tool, and then a real "FAILED" stops
meaning anything.

### How it was found

Not by reading the verifier. By executing both implementations side by side over
a table of values chosen to hit every rule in the protocol:

```
case               producer         verifier         agree
bool True          a753bb2ce0fd9a97 a753bb2ce0fd9a97 OK
int 1              dd4f6651b9dae1ad dd4f6651b9dae1ad OK
str 'true'         8cf3eab278a1e829 8cf3eab278a1e829 OK
str '1:int'        d0a11ba478691aa1 d0a11ba478691aa1 OK
None               0b160d4bfe0884ef 0b160d4bfe0884ef OK
float 1.5          a296591d3c7a9a43 a296591d3c7a9a43 OK
float -0.0         14abee7d73e89d3e 14abee7d73e89d3e OK
Fraction(1,2)      6360aa29d2fce811 ERR CanonicalizeError <<< DIVERGE
NFC vs NFD         f9c93bc6ab104e2f f9c93bc6ab104e2f OK
CRLF vs LF         f78d40efc3ee9f11 f78d40efc3ee9f11 OK
...
DIVERGENCES: ['Fraction(1,2)']
```

### Reachability

Adapter exports currently contain only strings, integers, booleans and `None`,
so the gap is **not reachable through any shipped command today**. It was
reachable in principle, and would have become reachable the moment an export
carried a rational — which the evidence-matrix side of the project already does.

Stated plainly: latent, not exploited. It is reported as High because the
defect is in the mechanism whose entire purpose is to be trustworthy, and
because the class of bug — two implementations of one specification drifting —
is the one most likely to recur as the protocol evolves.

### Fix and guard

`Fraction` was added to the verifier, and the specification block in its own
docstring was corrected to state the rule it now implements. The docstring had
omitted the rule, which is why the code omitted it too: **the documentation and
the implementation agreed with each other and both were wrong.**

`tests/test_export_seal.py` now pins the two implementations together over 25
values, including every collision the type tags exist to prevent
(`True` vs `"true"`, `1` vs `"1:int"`, `None` vs `"null"`, `Fraction(1,2)` vs
`"1/2:frac"`). The guard compares behaviour, not source text.

---

## 4. INF-04: the sealed manifest could not be verified

Found by running the whole pipeline rather than by reading it. After building a
three-artifact batch and copying it, with SIBERIAN absent, to an empty
directory:

```
Document : siberian-adapter-export   -> RESULT: VERIFIED   (x3)
Document : siberian-batch-manifest   -> RESULT: FAILED
  [FAIL] V6 provenance is an object -> got NoneType
```

The manifest was sealed with the same protocol as an export, but the verifier's
coherence checks require a `provenance` block, and `BatchResult.to_dict()` never
produced one.

Two problems in one, and the second is the more serious:

1. **A sealed artifact that the verifier rejects.** The analyst is told their own
   export is broken. That trains them to distrust the verifier, which is the
   failure mode a tamper-evident seal exists to prevent.
2. **The manifest was not self-describing.** It carried `adapter: "prefetch"` as
   a bare string, but not the parser version, its transformations, or its
   limitations. By this project's own Level 6 criterion — every adapter preserves
   the source, the parser version and the transformations — the batch's citable
   index did not comply.

Fixed by giving the manifest a full provenance block sourced from the adapter's
spec, with one `sources` entry per input. The manifest is now the
chain-of-custody index for the whole run: which parser version ran, what it did,
what it cannot do, and the digest of every artifact covered.

---

## 5. INF-03: analyst paths inside a sealed, shared artifact

A simulated adapter crash was recorded as:

```
manifest detail     : RuntimeError: simulated adapter crash
manifest item_stats : {'traceback': 'Traceback (most recent call last):
                        File "/home/labestiadevigia/siberian/siberian/batch.py", ...'}
leaks analyst paths : True
```

The distinction that decided the fix:

- `provenance.sources[].path` is **evidence provenance**. It must be recorded,
  and it is what lets `--rehash-source` and the no-mixed-cases guard work.
- A traceback's frames are the **analyst's environment** — where their tool is
  installed, how it is laid out, what their home directory is called. That is not
  evidence and no consumer of the manifest needs it.

Because the manifest is sealed, anything written into it is cryptographically
attested and cannot be removed afterwards without re-sealing. Getting this right
at write time is the only chance.

Fixed: the traceback goes to stderr, where the analyst actually needs it; the
manifest retains the exception type and message, which carry the diagnostic
value.

---

## 6. Refuted claims

### 6.1 Refuted — "reordering keys going undetected is a gap"

Key reordering is **not** detected, and must not be. The canonical form sorts
dict keys, so two documents differing only in key order are the same document. A
digest that changed on reordering would measure an incidental serialization
detail rather than the evidence. This is now asserted as a property
(`test_key_order_does_not_affect_verification`) so a future reader does not
"fix" it.

### 6.4 Refuted — "the manifest verified, so the pipeline was fine"

It did not. The three per-input exports verified and the manifest did not, and
the only reason this was caught is that the whole batch was run end to end and
every written artifact was verified in an environment without SIBERIAN. Testing
the seal function in isolation would have passed. The generalisable lesson: a
sealing mechanism must be exercised against every artifact the system writes,
not against the function that produces hashes.

### 6.2 Refuted — "the unused-import sweep found real dead code"

The automated sweep flagged `annotations` in three modules. `from __future__ import
annotations` is a compiler directive, not a symbol; every module uses it. The
only genuine finding was `sys` in `batch.py`.

### 6.3 Corrected — "a lone integer dict key is a divergence"

An int-keyed dict is unusual but both implementations accept it identically, so
it is not a divergence. My first test asserted both should reject it; that
premise was wrong and the test was corrected rather than the code.

---

## 7. Remaining limitations

1. **The verifier implements exactly one canonicalization version.** An export
   sealed under any other version is rejected rather than verified. That is the
   correct conservative behaviour, but it means protocol upgrades require
   shipping a new verifier.
2. **`--rehash-source` trusts the recorded path.** It re-hashes whatever is at
   that path now. If the path has been repointed, V7 verifies the wrong file.
   It proves the artifact at that path is unchanged, not that the path is the
   original.
3. **Batch output names embed an input index.** Adding an input that sorts early
   shifts every later index, so a re-run refuses (correctly — the outputs now
   belong to different sources) but requires a fresh output directory. This is
   the no-mixed-cases guard behaving as designed, not a defect, but it is
   surprising on first encounter.
4. **No export has been verified by a third party.** The verifier is
   self-consistent with the producer across 25 values. That is not the same as an
   independent party having reimplemented the protocol from the documentation.
   The protocol is written out in full in `docs/EXPORT_VERIFICATION.md`
   specifically so that it can be.
5. **The parsers themselves remain unvalidated against real evidence** for MFT,
   Amcache, Shimcache, Shellbags, and Prefetch SCCA. Sealing does not change
   that; it only makes the gap explicit inside every artifact.

---

## 8. Test evidence

Suite: **316 passing**.

New in this pass:

- `test_verifier_and_producer_agree_on_canonicalization` — 25 parametrized cases
- `test_verifier_supports_every_type_the_producer_supports`
- `test_verifier_rejects_unsupported_types_like_the_producer`
- `test_verifier_rejects_fraction_gap_regression` — pins INF-01 directly
- `test_key_order_does_not_affect_verification` — pins §5.1
- `test_crash_details_do_not_leak_analyst_paths_into_the_sealed_manifest` — INF-03
- `test_run_batch_has_no_dead_allow_partial_parameter` — INF-02
- `test_crash_is_still_isolated_and_recorded` — INF-03 fix must not cost the diagnostic
- `test_batch_manifest_carries_provenance_and_verifies` — INF-04
- `test_every_written_batch_artifact_verifies` — every artifact the batch writes

---

*Two implementations of one specification will drift. The only defence is to
compare them on every rule, continuously — which is what was missing here, and
what now exists.*
