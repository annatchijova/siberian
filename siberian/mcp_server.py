"""Curated MCP bridge for siberian — read-only analysis commands only.

siberian's own README says: "UNDER CONSTRUCTION — NOT READY FOR
OPERATIONAL USE." This bridge does not change that. It exists so the
command surface is available to an MCP client the moment siberian's own
maturity changes; cuartel's registry keeps it listed as `planned`
(disabled by default), not `ready`, until that happens.

Exposes six of siberian's CLI subcommands: validate, analyze, explain,
seal, verify, rivals. All six only read the case_file given to them and
print a result — no subcommand here writes, mutates, or creates a file.
Deliberately excluded:

- import-plaso and the Level 6 adapters (import-mft/prefetch/amcache/
  shimcache/shellbags, batch) — these write an output file and/or depend
  on optional extras (python-registry, pyscca) not installed here; per
  siberian's own Build Levels table, Level 6 is "Partial," blocked on
  real Windows artifact samples. Out of scope for a read-only bridge.

Each subcommand is invoked as a subprocess, never imported and re-driven
in-process — siberian's own argument parsing and case-file loading
(siberian/cli.py) remain the real boundary. Output is mixed: analyze and
seal print JSON by default, verify only with --json (passed here always,
for a consistent contract), validate/explain/rivals print plain text.
This bridge reports which it got rather than forcing text into a JSON
shape that doesn't exist.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SECONDS = 30

mcp = FastMCP("siberian")


def _run(args: list[str]) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "siberian.cli", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"siberian {' '.join(args)} timed out after {TIMEOUT_SECONDS}s"}
    if proc.returncode != 0:
        return {
            "error": f"siberian {' '.join(args)} exited {proc.returncode}",
            "stderr": proc.stderr.strip(),
        }
    stdout = proc.stdout.strip()
    try:
        return {"json": json.loads(stdout)}
    except json.JSONDecodeError:
        return {"text": stdout}


@mcp.tool()
def siberian_validate(case_file: str) -> dict:
    """Validate a case file without producing a report. Read-only."""
    return _run(["validate", case_file])


@mcp.tool()
def siberian_analyze(case_file: str) -> dict:
    """Produce the deterministic JSON evidence matrix for a case file.
    Read-only."""
    return _run(["analyze", case_file])


@mcp.tool()
def siberian_explain(case_file: str) -> dict:
    """Explain statuses and unresolved conditions in a case file.
    Read-only."""
    return _run(["explain", case_file])


@mcp.tool()
def siberian_seal(case_file: str, engine_attestation: bool = False) -> dict:
    """Produce a tamper-evident sealed bundle from a case file, printed to
    stdout (never written to disk by this bridge). Read-only with respect
    to the case file; does not call siberian's own -o file-write path."""
    args = ["seal", case_file]
    if engine_attestation:
        args.append("--engine-attestation")
    return _run(args)


@mcp.tool()
def siberian_verify(case_file: str, strict: bool = False) -> dict:
    """Verify a sealed case file with siberian's stdlib-only verifier.
    Always requests JSON output for a consistent contract. Read-only."""
    args = ["verify", "--json", case_file]
    if strict:
        args.append("--strict")
    return _run(args)


@mcp.tool()
def siberian_rivals(case_file: str) -> dict:
    """Evaluate rival hypotheses against the analysis result for a case
    file. Read-only."""
    return _run(["rivals", case_file])


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
