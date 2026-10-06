# Verifying an export without SIBERIAN

Level 6 requires that an analyst can compare and verify an exported bundle
without using SIBERIAN. This is the document that makes that possible.

## Why independence matters

A verifier that shares code with the producer proves only that the same bug ran
twice. If both sides call the same canonicalizer, agreement means nothing about
whether the canonicalizer is right — only that it was applied consistently.

So the verifier here is a **single file that imports nothing from SIBERIAN**.
Copy `forensics/verify_siberian.py` onto the machine holding the evidence. That
is the entire installation. SIBERIAN need not be installed, importable, or
present.

The digest protocol is written out in the verifier's own docstring and
reimplemented from that specification, not copied from the producer. Compare it
against `siberian/canonicalize.py` if you want to check the two agree — that
comparison is the point.

## What you need

| File | What it is |
|------|------------|
| `forensics/verify_siberian.py` | The verifier. Stdlib only. Self-contained. |
| `<export>.json` | Produced by `siberian import-* --output` or `siberian batch` |
| the original artifact | Optional. Only needed for `--rehash-source` |

## Usage

```bash
# Verify one export
python3 verify_siberian.py export.json

# Also re-hash the source artifact on disk against the digest in the export
python3 verify_siberian.py export.json --rehash-source

# Machine-readable, several at once
python3 verify_siberian.py out/*.json --json

# Non-zero unless every document verifies
python3 verify_siberian.py out/*.json --strict
```

Exit codes: `0` verified, `1` failed, `2` the document could not be read.

## What the checks mean

| Check | Establishes |
|-------|-------------|
| V1 | The document kind and hash-protocol versions are ones this verifier implements |
| V2 | The integrity block exists and is well formed |
| V3 | `provenance_hash` re-derives — the provenance has not been altered |
| V4 | `payload_hash` re-derives — the records have not been altered |
| V5 | `export_hash` re-derives — the two above are bound to the same document |
| V6 | Provenance is internally coherent: parser name and version declared, transformations declared, limitations declared, every source carries a digest or a stated reason it has none |
| V7 | *(optional)* the recorded source digest still matches the artifact on disk |

### Verified tampering

Each of these was reproduced against the shipped verifier:

```
modified record            -> V4 payload_hash re-derives      FAIL
modified provenance        -> V3 provenance_hash re-derives   FAIL
modified parser name       -> V3 provenance_hash re-derives   FAIL
removed limitations        -> V3 provenance_hash re-derives   FAIL
modified integrity block   -> V5 export_hash re-derives       FAIL
integrity block removed    -> V2 integrity block present      FAIL
source artifact altered    -> V7 recorded sources re-hash     FAIL
```

Note the third and fourth: the seal covers the parser's **identity and its
stated limitations**, not merely the data. An export cannot be re-labelled as
coming from a different, more reputable parser, and its caveats cannot be
quietly deleted.

### Not tampering

Reordering the keys of a JSON object is *not* detected, and should not be. The
canonical form sorts keys, so two documents that differ only in key order are
the same document. A digest that changed on reordering would be measuring an
incidental serialization detail rather than the evidence. This is asserted as a
property in `tests/test_export_seal.py`.

## What verification does NOT establish

- **That the parser was correct.** Sealing proves the document is unmodified
  since production. It says nothing about whether the decode was right.
- **That the source digest belongs to your original evidence.** That requires
  `--rehash-source` against an artifact you acquired and preserved yourself.

Each adapter's own limitations travel inside the sealed provenance and the
verifier prints them. Five adapters shipped in this repository with passing
tests while producing wrong values; read that section of the README before
relying on any output.

## Evidence-matrix bundles are a different document

`siberian seal` produces an evidence-matrix bundle, verified by
`siberian/verify.py` (also stdlib-only, also importing nothing from SIBERIAN).
The two formats are deliberately distinct: an artifact export is a parser
product, an evidence matrix is an analytical claim about absence. Handed the
wrong one, this verifier says so and names the other.

```bash
python3 siberian/verify.py bundle.json --strict
```

## Proven hash protocol

Canonicalization v2, reimplemented in the verifier:

```
bool        -> "true" | "false"
int         -> f"{obj}:int"
float       -> "nan" | "inf" | "-inf" | f"{obj + 0.0:.8f}"
str         -> "s:" + NFC(obj.replace("\r\n","\n").replace("\r","\n"))
None        -> "null"
dict        -> {k: canonicalize(v) for k, v in sorted(obj.items())}
list/tuple  -> [canonicalize(v) for v in obj]
other       -> TypeError

canonical_hash(obj) = SHA256(
    json.dumps(canonicalize(obj), sort_keys=True, ensure_ascii=True).encode("utf-8")
).hexdigest()

provenance_hash = canonical_hash({"provenance": doc["provenance"]})
payload_hash    = canonical_hash(doc without "integrity")
export_hash     = canonical_hash(
    doc without "integrity"
    + {"integrity": {"provenance_hash": ..., "payload_hash": ...}}
)
```

The `"s:"` prefix and the `":int"` / `":frac"` suffixes exist so a boolean, an
integer and a string can never canonicalize to the same bytes — `True`,
`1` and `"true"` are distinct values and stay distinct here.
