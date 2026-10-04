# Language decision: SIBERIAN analysis core

**Status:** accepted for the first standalone port

**Date:** 2026-10-03

## Decision

Use Python 3.10+ for the first analysis library. Keep the package dependency-free and use `fractions.Fraction` for all metrics. Reconsider the choice if SIBERIAN begins parsing hostile raw evidence, has a measured throughput or memory constraint, or needs a small native executable as a primary distribution format.

## Problem shape and forces

This component consumes normalized artifact observations and computes a small set of deterministic ratios and a SHA-256 digest. It does not currently parse disk images or other hostile binary inputs, serve concurrent requests, or have measured throughput requirements. The code being ported is Python, the seed arithmetic is rational, and the intended first use is an auditable library that can evolve quickly.

## Candidates

| Candidate | What it buys | Cost / limitation here |
| --- | --- | --- |
| **Python (chosen)** | Direct port; stdlib `Fraction` gives exact rational arithmetic; no runtime dependency for the core | Dynamic runtime checks still matter at the input boundary; interpreter is required; no memory-safety guarantee for future parsers |
| **Rust** | Ownership rules checked by the compiler provide memory-safety guarantees without a garbage collector; strong fit if parsing hostile forensic formats becomes core | Port and review cost now; exact rationals need an explicit representation or dependency; build/distribution and maintainer learning costs are not justified by current measurements |
| **Go** | Compiled standalone tools and standard-library arbitrary-precision `big.Rat`; suitable if the product becomes a concurrent service or command-line collector | Port and review cost; `big.Rat` is mutable pointer-oriented, so aliasing discipline is needed; the current small normalized-input engine does not need its deployment or concurrency model |

## Guarantees and boundaries

- Exact arithmetic comes from Python's `fractions.Fraction`, not from Python in general.
- Hash repeatability comes from the explicit sorted JSON encoding in this module, not from a universal guarantee that arbitrary Python objects serialize canonically.
- Python type annotations are not runtime validation. The public methods validate the OS profile, actions, artifact identifiers, and statuses where used.
- These choices do not make the artifact expectation weights accurate or empirically calibrated.

## Reopen conditions

Revisit Rust if raw untrusted evidence parsing moves into this package or a measured memory/performance budget fails. Revisit Go if the main product becomes a concurrent service or a self-contained CLI for teams that do not have Python environments. Keep Python if the scope remains normalized evidence manifests and analyst-reviewed reports.
