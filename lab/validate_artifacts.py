#!/usr/bin/env python3
"""
lab/validate_artifacts.py
==========================
One command that turns acquired Windows artifacts into validation evidence.

WHY THIS EXISTS
    Every artifact parser in this repository shipped with passing tests while
    producing wrong values. The five audits in ``docs/red-team/`` document what
    each one actually got wrong. What none of them could do is prove the parser
    right, because no real artifact was available.

    This script is the handoff. When you bring up the VM, acquire the artifacts,
    run this, and hand it the report. It does not interpret anything; it records
    what each parser produced, re-verifies every sealed export with the
    independent verifier, and states plainly which validations remain open.

    It cannot tell you the parser is correct. Only a reviewer comparing the
    output against a known-good reference for the same volume can. What it can
    do is make the gap visible and machine-checkable instead of remembered.

USAGE
    python3 lab/validate_artifacts.py --artifacts DIR --out REPORT_DIR

    DIR should contain whichever of these you have acquired:

      $MFT, MFT, or *.mft          NTFS file records
      Amcache.hve                 application compatibility cache
      SYSTEM                      shimcache (AppCompatCache)
      NTUSER.DAT, UsrClass.dat    shellbags
      Prefetch/ or *.pf           prefetch (Win10 MAM, or XP-8.1 SCCA)

    Acquire guidance is in docs/CATALOG_REVIEW.md.

WHAT IT DOES AND DOES NOT ESTABLISH
    Establishes: every adapter ran; every export verifies against
    forensics/verify_siberian.py with SIBERIAN absent; every source digest is
    recorded; limits that truncated a run are disclosed.

    Does NOT establish: that any parse is correct. A parser can produce
    well-formed, verifiable, wrong output. Sealing proves integrity, not truth.
    The report prints that distinction at the top so it cannot be quoted out of
    context.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

#: Which adapter to run for which artifact, and how to recognise one.
ADAPTER_FOR = {
    "mft": ("mft", ("$MFT", "MFT"), (".mft",)),
    "amcache": ("amcache", ("Amcache.hve", "amcache.hve"), ()),
    "shimcache": ("shimcache", ("SYSTEM",), ()),
    "shellbags": ("shellbags", ("NTUSER.DAT", "UsrClass.dat", "usrclass.dat"), ()),
    "prefetch": ("prefetch", ("Prefetch",), (".pf",)),
}


def discover(artifacts: Path) -> dict:
    """Map each adapter to the artifacts it should be given."""
    found = {name: [] for name in ADAPTER_FOR}
    if not artifacts.is_dir():
        return found

    for path in sorted(artifacts.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        parent = path.parent.name.lower()
        for adapter, (_, filenames, suffixes) in ADAPTER_FOR.items():
            if name in {f.lower() for f in filenames}:
                found[adapter].append(path)
            elif suffixes and any(name.endswith(s) for s in suffixes):
                found[adapter].append(path)
            elif adapter == "prefetch" and parent == "prefetch":
                found[adapter].append(path)
    return found


def run_export(adapter: str, target: Path, out_dir: Path) -> dict:
    """Run one adapter over one artifact and seal the result."""
    from siberian.batch import run_batch

    result = run_batch(adapter, [target], out_dir)
    return {
        "adapter": adapter,
        "target": str(target),
        "status": "ok" if result.ok else "partial",
        "inputs_available": result.inputs_available,
        "inputs_processed": len(result.outcomes),
        "outcomes": [
            {
                "source": o.source,
                "status": o.status,
                "detail": o.detail,
                "source_digest": o.source_digest,
                "output": o.output,
            }
            for o in result.outcomes
        ],
        "manifest": result.manifest_path,
    }


def independent_verify(out_dir: Path) -> dict:
    """Re-verify every sealed export with the standalone verifier.

    This is the point of the exercise: the check runs in a workspace containing
    only the verifier, so nothing about SIBERIAN can leak into the result.
    """
    verifier = REPO_ROOT / "forensics" / "verify_siberian.py"
    if not verifier.is_file():
        return {"error": f"verifier not found at {verifier}"}

    workspace = out_dir / "independent-check"
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)

    # Exports live in per-adapter subdirectories, so the walk must be recursive.
    # A non-recursive glob yields an empty list here and the verifier is then
    # invoked with no arguments, producing no JSON at all -- which is exactly
    # the silent failure this harness exists to prevent.
    documents = sorted(out_dir.rglob("*.json"))
    if not documents:
        return {"error": "no sealed documents found to verify",
                "siberian_importable": _siberian_importable(workspace)}

    names = []
    for document in documents:
        # Flatten, keeping the adapter directory so names stay unique.
        flat = "_".join(document.relative_to(out_dir).parts)
        shutil.copy2(document, workspace / flat)
        names.append(flat)
    shutil.copy2(verifier, workspace / "verify_siberian.py")

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(workspace),
        "PYTHONPATH": "",          # the repo cannot leak in
        "PYTHONNOUSERSITE": "1",
    }
    proc = subprocess.run(
        [sys.executable, "verify_siberian.py", *names, "--json"],
        cwd=workspace, capture_output=True, text=True, env=env, timeout=600,
    )
    try:
        payload = json.loads(proc.stdout[proc.stdout.index("{"):])
    except (ValueError, IndexError):
        return {"error": "verifier produced no JSON", "stderr": proc.stderr[-2000:]}

    return {
        "siberian_importable": _siberian_importable(workspace),
        "exit_code": proc.returncode,
        "documents": [
            {"path": d["path"], "verified": d["verified"],
             "failed_checks": [c["code"] for c in d["checks"] if not c["passed"]]}
            for d in payload["documents"]
        ],
    }


def _siberian_importable(workspace: Path) -> bool:
    """Confirm the independent check really was independent."""
    env = {"PATH": "/usr/bin:/bin", "HOME": str(workspace), "PYTHONPATH": ""}
    probe = subprocess.run(
        [sys.executable, "-c", "import siberian"],
        cwd=workspace, capture_output=True, text=True, env=env, timeout=60,
    )
    return probe.returncode == 0


def build_report(artifacts: Path, runs: list, verification: dict) -> str:
    lines = []
    add = lines.append

    add("# Artifact validation report")
    add("")
    add("> **This report does not establish that any parse is correct.**")
    add("> A parser can emit well-formed, verifiable, wrong output: that is")
    add("> exactly what happened in all five adapter audits. What is established")
    add("> here is that each adapter ran, that every export verifies against the")
    add("> independent verifier, and that source digests were recorded.")
    add("")

    add("## Environment")
    add("")
    add(f"- artifacts directory : `{artifacts}`")
    add(f"- repository          : `{REPO_ROOT}`")
    add(f"- python              : {sys.version.split()[0]}")
    add(f"- platform            : {sys.platform}")
    add("")

    add("## Adapters run")
    add("")
    if not runs:
        add("No recognised artifact was found. Nothing was validated.")
        add("")
        add("Expected at least one of: `$MFT`/`*.mft`, `Amcache.hve`, `SYSTEM`,")
        add("`NTUSER.DAT`/`UsrClass.dat`, a `Prefetch/` directory or `*.pf`.")
    for run in runs:
        add(f"### {run['adapter']}")
        add("")
        add(f"- target : `{run['target']}`")
        add(f"- inputs : {run['inputs_processed']} of {run['inputs_available']} available")
        add(f"- status : {run['status']}")
        for outcome in run["outcomes"]:
            detail = f" — {outcome['detail']}" if outcome["detail"] else ""
            add(f"  - `{Path(outcome['source']).name}`: {outcome['status']}{detail}")
            if outcome["source_digest"]:
                add(f"    sha256: `{outcome['source_digest']}`")
        add("")

    add("## Independent verification")
    add("")
    if verification.get("error"):
        add(f"Could not run the independent verifier: {verification['error']}")
    else:
        importable = verification.get("siberian_importable")
        add(f"- SIBERIAN importable in the verification workspace: **{importable}**")
        if importable:
            add("  - **This invalidates the independence claim.** Re-run in a clean environment.")
        else:
            add("  - independence confirmed: the verifier ran without the package")
        add(f"- verifier exit code: {verification['exit_code']}")
        add("")
        add("| Document | Verified | Failed checks |")
        add("|---|---|---|")
        for doc in verification.get("documents", []):
            failed = ", ".join(doc["failed_checks"]) or "—"
            add(f"| `{doc['path']}` | {'yes' if doc['verified'] else 'NO'} | {failed} |")
    add("")

    add("## Still open")
    add("")
    add("These remain unvalidated regardless of what this run produced:")
    add("")
    add("- **Correctness of each parse.** Compare against a known-good reference for")
    add("  the same volume. A verified export is not a correct export.")
    add("- **Prefetch SCCA** (XP-8.1) unless you supply such a file; the MAM path is")
    add("  validated against 225 OWL artifacts but SCCA is delegated to libscca.")
    add("- **Level 1 catalog applicability** for the volume's build/edition. Requires")
    add("  observing a running Windows system, not a parsed file.")
    add("- **Level 4 calibration.** Requires a controlled corpus with ground truth.")
    add("")
    add("Record the outcome in `docs/CATALOG_MATRIX.md` (laboratory status column) and")
    add("in `docs/CATALOG_REVIEW.md` with the date.")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("USAGE")[0].strip(),
    )
    parser.add_argument("--artifacts", type=Path, required=True,
                        help="directory containing the acquired artifacts")
    parser.add_argument("--out", type=Path, required=True,
                        help="directory for sealed exports and the report")
    parser.add_argument("--only", action="append", default=None,
                        choices=sorted(ADAPTER_FOR),
                        help="restrict to these adapters (repeatable)")
    args = parser.parse_args(argv)

    artifacts = args.artifacts
    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    found = discover(artifacts)
    wanted = args.only or sorted(ADAPTER_FOR)

    print(f"artifacts: {artifacts}")
    print(f"output   : {out_dir}")
    print()

    runs = []
    for adapter in wanted:
        targets = found.get(adapter) or []
        if not targets:
            print(f"  {adapter:10s} no artifact found -- skipped")
            continue
        for target in targets:
            per_out = out_dir / adapter
            try:
                run = run_export(adapter, target, per_out)
                runs.append(run)
                bad = sum(1 for o in run["outcomes"] if o["status"] != "ok")
                print(f"  {adapter:10s} {target.name:24s} "
                      f"{'ok' if bad == 0 else f'{bad} not ok'}")
            except Exception as exc:
                print(f"  {adapter:10s} {target.name:24s} FAILED: {exc}")
                runs.append({"adapter": adapter, "target": str(target),
                             "status": "failed", "inputs_available": 0,
                             "inputs_processed": 0,
                             "outcomes": [{"source": str(target), "status": "failed",
                                           "detail": f"{type(exc).__name__}: {exc}",
                                           "source_digest": None, "output": None}],
                             "manifest": None})

    print()
    print("independent verification (SIBERIAN absent) ...")
    verification = independent_verify(out_dir)

    report = build_report(artifacts, runs, verification)
    report_path = out_dir / "VALIDATION_REPORT.md"
    report_path.write_text(report, encoding="utf-8")

    print()
    print(f"report: {report_path}")
    print(f"exports: {len(list(out_dir.rglob('*.json')))} sealed document(s)")
    if runs:
        incomplete = sum(
            1 for r in runs for o in r["outcomes"] if o["status"] != "ok"
        )
        if incomplete:
            print(f"WARNING: {incomplete} input(s) did not parse cleanly. "
                  f"See the report.")
    if verification.get("siberian_importable"):
        print("WARNING: SIBERIAN was importable during verification; the "
              "independence claim does not hold for this run.")
        return 1
    print()
    print("Reminders: a verified export is not a correct export, and this run")
    print("establishes nothing about parse correctness. Compare against a")
    print("known-good reference before relying on any value.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
