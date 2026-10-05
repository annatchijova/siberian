#!/usr/bin/env python3
"""
siberian/verify.py
==================
Standalone Verifier for SIBERIAN Evidence Matrix Bundle v1.

TOTAL INDEPENDENCE GUARANTEE:
    This script uses EXCLUSIVELY Python stdlib.
    It imports NO classes from siberian.adversarial_silence, siberian.bundle,
    or any other production module.
    It can run on any machine with Python 3.10+ without installation.
    If the verifier needs to import production code, the system is not
    third-party auditable — violates forensic independence principle.

LOCAL CONSTANTS:
    The standard constants (BUNDLE_VERSION, CATALOG_VERSION) are copied here.
    They are NOT imported from bundle.py. This is intentional: the verifier
    must not depend on production code being available.

VALIDATIONS:
    R1 — Hash integrity (bundle_hash, records_hash, context_hash,
         catalog_hash, and when declared, analysis_fingerprint). The
         bundle_hash identifies a complete custody event; the analysis
         fingerprint allows comparing analytical projections without
         UUID/timestamps. All declared digests are re-derived.
    R2 — Schema structure (required fields, version support, counts present)
    R3 — Count consistency (sum of status counts == expected_count)
    R4 — Engine attestation: PRESENCE + FORMAT only. This verifier is
         stdlib-only and cannot re-derive the engine hash without the
         pinned source tree + dependency manifests; source re-derivation
         lives in the repo (tests/test_attestation_coverage.py). R4 does
         NOT prove the bundle was produced by the attested engine — only
         that the field exists and has SHA-256 form.
    R5 — Tool execution log anchoring (chain_tip_sha256/hmac when present)

CONFORMITY LEVELS:
    Level 0 — Non-compliant:         invalid structure
    Level 1 — Structurally valid:    correct schema
    Level 2 — Cryptographically valid: hashes consistent + counts OK
    Level 3 — Fully compliant v1:     R1-R5 + tool log anchored

USAGE:
    python3 -m siberian.verify bundle.json
    python3 -m siberian.verify bundle.json --verbose
    python3 -m siberian.verify bundle.json --strict   # fails if Level < 3
    python3 -m siberian.verify bundle.json --json     # structured JSON output
    echo $?  # 0=PASS  1=FAIL

HASH PROTOCOL (identical to BundleBuilder.seal):
    records_hash  = SHA256({"records": records_array})
    context_hash  = SHA256(context_dict)
    catalog_hash  = SHA256({"catalog_version": catalog_version})
    analysis_fingerprint = SHA255(analytical projection without UUID/timestamps)
    bundle_hash   = SHA256(bundle_id + version + timestamp +
                           records_hash + context_hash + catalog_hash +
                           records + context + catalog_version + counts +
                           schema_version + analysis_fingerprint)
"""
from __future__ import annotations

# STDLIB ONLY — zero production imports
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Local constants for SIBERIAN Bundle v1
# Copied deliberately — NOT imported from bundle.py
# ---------------------------------------------------------------------------

_BUNDLE_VERSION = "1.0"
_BUNDLE_SUPPORTED_VERSIONS = ["1.0"]
_CATALOG_VERSION = "windows-msdocs-2026-10-04-v3"
_VERIFIER_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Hash helper — local implementation, identical to BundleBuilder._sha256_dict
# ---------------------------------------------------------------------------

import unicodedata as _unicodedata
from fractions import Fraction as _Fraction

_V2_STR_PREFIX = "s:"


def _v2_norm_str(s: str) -> str:
    return _unicodedata.normalize("NFC", s.replace("\r\n", "\n").replace("\r", "\n"))


def _canonicalize_v1(obj: Any) -> Any:
    """Schema v1 (LEGACY — only for verifying historical bundles)."""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:          # NaN
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"
    if isinstance(obj, str):
        return obj
    if obj is None:
        return "null"
    if isinstance(obj, dict):
        return {k: _canonicalize_v1(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize_v1(v) for v in obj]
    return str(obj)


def _canonicalize_v2(obj: Any) -> Any:
    """Schema v2 (DEFAULT). Scalars identical to v1; strings escaped (s: + NFC/CRLF->LF); Fraction explicit."""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"
    if isinstance(obj, str):
        return _V2_STR_PREFIX + _v2_norm_str(obj)
    if obj is None:
        return "null"
    if isinstance(obj, _Fraction):
        return f"{obj.numerator}/{obj.denominator}:frac"
    if isinstance(obj, dict):
        return {k: _canonicalize_v2(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize_v2(v) for v in obj]
    return _V2_STR_PREFIX + _v2_norm_str(str(obj))


def _canonicalize(obj: Any) -> Any:
    """Default canonical form (v2)."""
    return _canonicalize_v2(obj)


# R6-1 — Fields that travel in the bundle but do NOT enter the payload
# hashed by BundleBuilder.seal(). Local copy by design (stdlib-only
# verifier, no production imports) — must stay in lockstep with
# siberian/bundle.PRESENTATION_FIELDS and verified by tests.
_PRESENTATION_FIELDS = ("integrity", "tool_execution_log")

# R6-1: two historical payload schemes — see bundle._sealed_payload.
_LEGACY_HASHED_FIELDS = ("tool_execution_log",)


def _sealed_payload(bundle: Dict, legacy: bool = False) -> Dict:
    excluded = tuple(
        f for f in _PRESENTATION_FIELDS
        if not (legacy and f in _LEGACY_HASHED_FIELDS)
    )
    return {k: v for k, v in bundle.items() if k not in excluded}


def _matching_payload(bundle: Dict, stored: str):
    for legacy in (False, True):
        payload = _sealed_payload(bundle, legacy=legacy)
        if _sha256_dict_matches(payload, stored):
            return payload, ("legacy" if legacy else "modern")
    return None, None


def _sha256_dict_matches(obj: Dict, stored: str) -> bool:
    """True if hash of `obj` recomputes under v2 OR v1 (backward-compat)."""
    return any(
        _sha256_dict(obj, canon=c) == stored
        for c in (_canonicalize_v2, _canonicalize_v1)
    )


def _sha256_dict(obj: Dict, canon=_canonicalize) -> str:
    """SHA-256 deterministic of a dict with strict canonical form."""
    canonical = canon(obj)
    serialized = json.dumps(canonical, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _analysis_projection(bundle_payload: Dict) -> Dict:
    """Mirror BundleBuilder's stable analytical projection."""
    projection = dict(bundle_payload)
    projection.pop("bundle_id", None)
    projection.pop("timestamp", None)
    context = dict(projection.get("context", {}))
    context.pop("interval_start", None)
    context.pop("interval_end", None)
    projection["context"] = context
    return projection


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

class VerificationResult:

    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []
        self.conformity_level: int = 0
        self.passed: bool = False
        self.timestamp: str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def add(
        self,
        rule: str,
        passed: bool,
        message: str,
        severity: str = "ERROR",
        detail: Optional[Any] = None,
    ) -> None:
        self.checks.append({
            "rule": rule,
            "passed": passed,
            "message": message,
            "severity": severity,
            "detail": detail,
        })

    def critical_failures(self) -> List[Dict]:
        return [c for c in self.checks if not c["passed"] and c["severity"] == "ERROR"]

    def to_dict(self) -> Dict[str, Any]:
        labels = {
            0: "Non-compliant",
            1: "Structurally valid",
            2: "Cryptographically valid",
            3: "Fully compliant v1",
        }
        return {
            "verifier_version": _VERIFIER_VERSION,
            "timestamp": self.timestamp,
            "passed": self.passed,
            "conformity_level": self.conformity_level,
            "conformity_label": labels.get(self.conformity_level, "Unknown"),
            "checks": self.checks,
            "summary": {
                "total": len(self.checks),
                "passed": sum(1 for c in self.checks if c["passed"]),
                "failed": sum(1 for c in self.checks if not c["passed"]),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)


# ---------------------------------------------------------------------------
# R1 — Hash integrity
# ---------------------------------------------------------------------------

def _check_records_hash(bundle: Dict) -> Tuple[bool, str]:
    """records_hash = SHA256({"records": records_array})"""
    records = bundle.get("records", [])
    stored = bundle.get("integrity", {}).get("records_hash", "")
    if not stored:
        return False, "records_hash missing in integrity"
    if not _sha256_dict_matches({"records": records}, stored):
        recomputed = _sha256_dict({"records": records})
        return False, f"records_hash mismatch: recomputed={recomputed[:16]}... stored={stored[:16]}..."
    return True, "records_hash intact"


def _check_context_hash(bundle: Dict) -> Tuple[bool, str]:
    context = bundle.get("context", {})
    stored = bundle.get("integrity", {}).get("context_hash", "")
    if not stored:
        return False, "context_hash missing in integrity"
    if not _sha256_dict_matches(context, stored):
        recomputed = _sha256_dict(context)
        return False, f"context_hash mismatch: {recomputed[:16]}... != {stored[:16]}..."
    return True, "context_hash intact"


def _check_catalog_hash(bundle: Dict) -> Tuple[bool, str]:
    catalog_version = bundle.get("catalog_version", "")
    stored = bundle.get("integrity", {}).get("catalog_hash", "")
    if not stored:
        return False, "catalog_hash missing in integrity"
    if not _sha256_dict_matches({"catalog_version": catalog_version}, stored):
        recomputed = _sha256_dict({"catalog_version": catalog_version})
        return False, f"catalog_hash mismatch: {recomputed[:16]}... != {stored[:16]}..."
    return True, "catalog_hash intact"


def _check_analysis_fingerprint(bundle: Dict) -> Tuple[bool, str]:
    """Re-derive optional stable replay identifier."""
    stored = bundle.get("integrity", {}).get("analysis_fingerprint", "")
    if not stored:
        return True, "analysis_fingerprint absent — legacy bundle; not required"
    bundle_stored = bundle.get("integrity", {}).get("bundle_hash", "")
    payload, _scheme = _matching_payload(bundle, bundle_stored)
    if payload is None:
        payload = _sealed_payload(bundle)
    projection = _analysis_projection(payload)
    if not _sha256_dict_matches(projection, stored):
        return False, "analysis_fingerprint mismatch — analytical projection changed"
    return True, "analysis_fingerprint intact (analytical projection reproducible)"


def _check_bundle_hash(bundle: Dict) -> Tuple[bool, str]:
    """bundle_hash = SHA256(entire content including sub-hashes)."""
    stored = bundle.get("integrity", {}).get("bundle_hash", "")
    if not stored:
        return False, "bundle_hash missing in integrity"
    payload, scheme = _matching_payload(bundle, stored)
    if payload is None:
        return False, "bundle_hash mismatch — bundle modified or corrupted"
    return True, f"bundle_hash intact (payload scheme: {scheme})"


# ---------------------------------------------------------------------------
# Level 1 — Structure
# ---------------------------------------------------------------------------

def _check_presentation_fields(bundle: Dict) -> Tuple[bool, str]:
    """R6-1: presentation fields travel with bundle but are NOT covered by
    bundle_hash. Excluding them is correct — but silence is not: a reader
    seeing "bundle_hash intact" would assume the ENTIRE file is sealed.
    This check never fails; it explicitly names what the seal does not
    cover and where each field's authenticity comes from."""
    stored = bundle.get("integrity", {}).get("bundle_hash", "")
    _payload, scheme = _matching_payload(bundle, stored)
    present = [f for f in _PRESENTATION_FIELDS
               if f != "integrity" and f in bundle]
    if scheme == "legacy":
        present = [f for f in present if f not in _LEGACY_HASHED_FIELDS]
    if not present:
        return True, "bundle_hash covers entire file"

    origin = {
        "tool_execution_log": "audit ledger (chain_hash + checkpoint HMAC)",
    }
    parts = []
    for field in present:
        if field == "tool_execution_log":
            if bundle.get("chain_tip_sha256"):
                parts.append("tool_execution_log -> anchored by chain_tip_sha256, "
                             "which IS sealed (verify with verify_tool_log.py)")
            else:
                parts.append("tool_execution_log -> NO ANCHOR: log not covered by "
                             "bundle_hash nor chain_tip_sha256. Seal does not "
                             "back this audit trail")
        else:
            parts.append(f"{field} -> {origin.get(field, 'no declared anchor')}")
    unanchored = ("tool_execution_log" in present
                  and not bundle.get("chain_tip_sha256"))
    return (not unanchored), "NOT covered by bundle_hash: " + "; ".join(parts)


def _check_structure(bundle: Dict) -> Tuple[bool, str]:
    required = [
        "bundle_version", "timestamp", "context",
        "catalog_version", "schema_version", "records",
        "counts", "integrity",
    ]
    missing = [f for f in required if f not in bundle]
    if missing:
        return False, f"Missing fields: {', '.join(missing)}"

    if bundle.get("bundle_version") not in _BUNDLE_SUPPORTED_VERSIONS:
        return False, f"Unsupported version: {bundle.get('bundle_version')}"

    integrity = bundle.get("integrity", {})
    for h in ["bundle_hash", "records_hash", "context_hash", "catalog_hash"]:
        if h not in integrity:
            return False, f"Missing {h} in integrity"

    counts = bundle.get("counts", {})
    for c in ["expected", "present", "confirmed_absent", "unknown", "out_of_scope"]:
        if c not in counts:
            return False, f"Missing count: {c}"

    # Validate schema version
    schema_version = bundle.get("schema_version", "")
    if schema_version != "siberian-evidence-matrix-v3":
        return False, f"Unsupported schema_version: {schema_version}"

    return True, "SIBERIAN bundle v1 structure valid"


def _check_count_consistency(bundle: Dict) -> Tuple[bool, str]:
    """R3 — Sum of status counts must equal expected_count."""
    counts = bundle.get("counts", {})
    expected = counts.get("expected", 0)
    present = counts.get("present", 0)
    confirmed_absent = counts.get("confirmed_absent", 0)
    unknown = counts.get("unknown", 0)
    out_of_scope = counts.get("out_of_scope", 0)

    total = present + confirmed_absent + unknown + out_of_scope
    if total != expected:
        return False, (
            f"Count inconsistency: present({present}) + confirmed_absent({confirmed_absent}) + "
            f"unknown({unknown}) + out_of_scope({out_of_scope}) = {total} != expected({expected})"
        )
    return True, f"Count consistency OK: {present}+{confirmed_absent}+{unknown}+{out_of_scope}={expected}"


# ---------------------------------------------------------------------------
# R4 — Engine attestation
# ---------------------------------------------------------------------------

def _check_engine_attestation(bundle: Dict) -> Tuple[bool, str]:
    """R4 — presence + format ONLY (stdlib-only verifier cannot re-derive
    engine hash without pinned source tree + dependency manifests).
    A plausible-but-fabricated 64-hex value PASSES this check. The
    success message declares this so no report can read R4 as proof
    of origin."""
    att = bundle.get("integrity", {}).get("engine_attestation_hash", "")
    if not att:
        return False, "engine_attestation_hash absent — Level 3 not reachable"
    if len(att) != 64 or not all(c in "0123456789abcdef" for c in att.lower()):
        return False, f"engine_attestation_hash invalid format"
    return True, (
        f"engine_attestation_hash present: {att[:16]}... "
        "[format verified only — origin NOT re-derived in standalone mode; "
        "see test_attestation_coverage.py]"
    )


# ---------------------------------------------------------------------------
# R5 — Tool log anchoring
# ---------------------------------------------------------------------------

def _check_tool_log_anchoring(bundle: Dict) -> Tuple[bool, str]:
    """R5 — chain_tip_sha256/hmac presence when tool_execution_log present."""
    has_log = "tool_execution_log" in bundle
    has_tip = bundle.get("chain_tip_sha256") is not None
    has_tip_hmac = bundle.get("chain_tip_hmac") is not None

    if not has_log:
        return True, "No tool_execution_log — anchoring not applicable"

    if not has_tip:
        return False, "tool_execution_log present but chain_tip_sha256 missing — log can be truncated undetected"

    if len(bundle["chain_tip_sha256"]) != 64:
        return False, "chain_tip_sha256 invalid format"

    if has_tip_hmac and len(bundle["chain_tip_hmac"]) != 64:
        return False, "chain_tip_hmac invalid format"

    return True, f"Tool log anchored: chain_tip_sha256={bundle['chain_tip_sha256'][:16]}... hmac={'yes' if has_tip_hmac else 'no'}"


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

def verify_bundle(
    bundle: Dict,
    strict: bool = False,
    verbose: bool = False,
) -> VerificationResult:

    result = VerificationResult()

    # Level 1: structure
    ok, msg = _check_structure(bundle)
    result.add("L1_STRUCTURE", ok, msg, severity="ERROR" if not ok else "INFO")
    if not ok:
        result.conformity_level = 0
        result.passed = False
        return result

    result.conformity_level = 1

    # Count consistency
    ok_cc, msg_cc = _check_count_consistency(bundle)
    result.add("R3_COUNT_CONSISTENCY", ok_cc, msg_cc, severity="ERROR" if not ok_cc else "INFO")

    # R1: cryptographic integrity
    ok_rh, msg_rh = _check_records_hash(bundle)
    result.add("R1_RECORDS_HASH", ok_rh, msg_rh, severity="ERROR" if not ok_rh else "INFO")

    ok_ch, msg_ch = _check_context_hash(bundle)
    result.add("R1_CONTEXT_HASH", ok_ch, msg_ch, severity="ERROR" if not ok_ch else "INFO")

    ok_ca, msg_ca = _check_catalog_hash(bundle)
    result.add("R1_CATALOG_HASH", ok_ca, msg_ca, severity="ERROR" if not ok_ca else "INFO")

    ok_af, msg_af = _check_analysis_fingerprint(bundle)
    result.add("R1_ANALYSIS_FINGERPRINT", ok_af, msg_af, severity="ERROR" if not ok_af else "INFO")

    ok_bh, msg_bh = _check_bundle_hash(bundle)
    result.add("R1_BUNDLE_HASH", ok_bh, msg_bh, severity="ERROR" if not ok_bh else "INFO")

    # R6-1: seal scope — informational, never fails
    ok_pf, msg_pf = _check_presentation_fields(bundle)
    result.add("R1_SEAL_SCOPE", ok_pf, msg_pf,
               severity="WARNING" if not ok_pf else "INFO")

    hash_ok = ok_rh and ok_ch and ok_ca and ok_af and ok_bh

    # Determine Level 2
    critical = result.critical_failures()
    if not critical and hash_ok and ok_cc:
        result.conformity_level = 2

    # R4 and R5 — WARNING only, don't block Level 2
    ok_att, msg_att = _check_engine_attestation(bundle)
    result.add("R4_ENGINE_ATTESTATION", ok_att, msg_att, severity="WARNING" if not ok_att else "INFO")

    ok_log, msg_log = _check_tool_log_anchoring(bundle)
    result.add("R5_TOOL_LOG_ANCHORING", ok_log, msg_log, severity="WARNING" if not ok_log else "INFO")

    # Determine Level 3
    if not critical and hash_ok and ok_cc and ok_att and ok_log:
        result.conformity_level = 3

    # Final result
    if result.conformity_level >= 2:
        result.passed = True
    elif strict:
        result.passed = False
    else:
        result.passed = result.conformity_level >= 1 and not critical

    if strict and result.conformity_level < 3:
        result.passed = False

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_result(result: VerificationResult, verbose: bool, as_json: bool) -> None:
    if as_json:
        print(result.to_json())
        return

    d = result.to_dict()
    status = "PASS" if result.passed else "FAIL"
    print(f"\n{'='*60}")
    print(f"  SIBERIAN — Independent Verifier v{_VERIFIER_VERSION}")
    print(f"{'='*60}")
    print(f"  Result      : {status}")
    print(f"  Conformity  : Level {result.conformity_level} — {d['conformity_label']}")
    print(f"  Timestamp   : {result.timestamp}")
    s = d["summary"]
    print(f"  Checks      : {s['passed']}/{s['total']} OK")
    print(f"{'='*60}")

    if verbose or not result.passed:
        print()
        for check in result.checks:
            icon = "OK  " if check["passed"] else ("FAIL" if check["severity"] == "ERROR" else "WARN")
            print(f"  [{icon}] {check['rule']}")
            print(f"          {check['message']}")
            if check.get("detail") and verbose:
                for v in (check["detail"] if isinstance(check["detail"], list) else [check["detail"]]):
                    print(f"          > {v}")

    if not result.passed:
        print("\n  CRITICAL FAILURES:")
        for fail in result.critical_failures():
            print(f"    - {fail['rule']}: {fail['message']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SIBERIAN Independent Verifier v1 — stdlib only",
        epilog="Exit: 0=PASS  1=FAIL",
    )
    parser.add_argument("bundle_path", help="Path to SIBERIAN bundle.json")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--strict", "-s", action="store_true", help="Require Level 3")
    parser.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args()

    try:
        with open(args.bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Not found: {args.bundle_path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
        return 1

    result = verify_bundle(bundle, strict=args.strict, verbose=args.verbose)
    _print_result(result, verbose=args.verbose, as_json=args.json)
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())