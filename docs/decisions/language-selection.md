# Language decision: SIBERIAN analysis core

**Status:** selected by the project owner for the first standalone port

**Date:** 2026-10-03

## Decision

Use Python 3.10+ for the first analysis library. Keep the package dependency-free and serialize the contextual evidence matrix deterministically before hashing it. Do not introduce aggregate suspicion metrics until they have a defensible empirical basis. Reconsider the choice if SIBERIAN begins parsing hostile raw evidence, has a measured throughput or memory constraint, or needs a small native executable as a primary distribution format.

## Problem shape and forces

This component consumes normalized artifact observations and produces a contextual evidence matrix plus a SHA-256 digest. It does not currently parse disk images or other hostile binary inputs, serve concurrent requests, or have measured throughput requirements. The code being ported is Python, and the intended first use is an auditable library that can evolve quickly.

## Candidates

| Candidate | What it buys | Cost / limitation here |
| --- | --- | --- |
| **Python (chosen)** | Direct port; standard library supports deterministic serialization and hashing; no runtime dependency for the core | Dynamic runtime checks still matter at the input boundary; interpreter is required; no memory-safety guarantee for future parsers |
| **Rust** | Ownership rules checked by the compiler provide memory-safety guarantees without a garbage collector; strong fit if parsing hostile forensic formats becomes core | Port and review cost now; exact rationals need an explicit representation or dependency; build/distribution and maintainer learning costs are not justified by current measurements |
| **Go** | Compiled standalone tools and standard-library arbitrary-precision `big.Rat`; suitable if the product becomes a concurrent service or command-line collector | Port and review cost; `big.Rat` is mutable pointer-oriented, so aliasing discipline is needed; the current small normalized-input engine does not need its deployment or concurrency model |

## Guarantees and boundaries

- Deterministic output depends on an explicitly fixed serialization schema, not on Python in general.
- Hash repeatability comes from the explicit sorted JSON encoding in this module, not from a universal guarantee that arbitrary Python objects serialize canonically.
- Python type annotations are not runtime validation. The public methods validate the OS profile, actions, artifact identifiers, and statuses where used.
- The current implementation contains no artifact expectation weights or calibrated scores.

## Reopen conditions

Revisit Rust if raw untrusted evidence parsing moves into this package or a measured memory/performance budget fails. Revisit Go if the main product becomes a concurrent service or a self-contained CLI for teams that do not have Python environments. Keep Python if the scope remains normalized evidence manifests and analyst-reviewed reports.
