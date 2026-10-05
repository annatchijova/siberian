"""
siberian/hash_chain.py
======================
Single tamper-evident hash chain primitive for SIBERIAN.

Unifies the chain scheme: entry_hash covers the COMPLETE payload — any
field altered breaks the chain (unlike schemes that only protect
result_summary). Dual hash/HMAC design (deliberate):
  - entry_hash (keyless): third party verifies STRUCTURE with stdlib,
    no key access — Daubert independent verification requirement.
  - entry_hmac (with key): detects insider attacker with write access
    who recomputes the whole chain. Without key, SHA-256 alone is
    recomputable in milliseconds; with HMAC it is not.

Scheme v2:
  entry_hash = SHA-256( canonical( payload ∪ {seq, prev_hash} ) )
  entry_hmac = HMAC-SHA256( key, entry_hash )          [optional, dual]

  - COMPLETE payload enters hash — any altered field breaks chain.
  - seq explicit inside hash prevents reordering.
  - GENESIS_HASH anchors first link.
  - Canonicalization is the canonicalize.py source of truth (v2 default).

Verification: verify_chain accumulates ALL errors by category
(seq discontinuities, broken links, tampered content, HMAC failures) —
the examiner sees the complete damage map, not just the first broken link.

This module is chain-pure: no log I/O, no DB. Only env read is
resolve_hmac_key() (SIBERIAN_HMAC_KEY / SIBERIAN_HMAC_KEY_FILE).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .canonicalize import (
    _canonicalize,       # default v2
    _canonicalize_v1,
    _canonicalize_v2,
)

CHAIN_SCHEMA_VERSION: str = "2"
GENESIS_HASH: str = "0" * 64

# SIBERIAN_HMAC_KEY / SIBERIAN_HMAC_KEY_FILE — same variables pattern as VIGÍA
_HMAC_KEY_ENV = "SIBERIAN_HMAC_KEY"
_HMAC_KEY_FILE_ENV = "SIBERIAN_HMAC_KEY_FILE"


def _content_signature(payload: Dict[str, Any]) -> str:
    """Content signature for duplicate detection — excludes what
    legitimately varies between events (timestamp, event_id) and
    structural fields (already outside payload)."""
    body = {k: v for k, v in payload.items() if k not in ("timestamp", "event_id")}
    return canonical_hash(body)


def canonical_hash(payload: Dict[str, Any], canon=_canonicalize) -> str:
    """SHA-256 of payload in canonical form (canonicalize.py). `canon` chooses
    scheme: default v2 (new seals); v1 only for verifying historical."""
    canonical = json.dumps(
        canon(payload), sort_keys=True, ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_entry_hash(seq: int, prev_hash: str, payload: Dict[str, Any],
                       canon=_canonicalize) -> str:
    """
    Hash of a link: full payload + seq + prev_hash.

    Payload MUST NOT contain 'seq' or 'prev_hash' (added here). If it does,
    they are overwritten — the hash always uses the chain's structural values.

    `canon` = canonicalization scheme: default v2. Verification tries v2 and
    falls back to v1 for links sealed under legacy scheme (backward-compat).
    """
    return canonical_hash({**payload, "seq": seq, "prev_hash": prev_hash}, canon=canon)


def _entry_hash_matches(link: "ChainLink") -> bool:
    """True if stored entry_hash recomputes under v2 OR v1 (backward-compat)."""
    for canon in (_canonicalize_v2, _canonicalize_v1):
        if compute_entry_hash(link.seq, link.prev_hash, link.payload, canon=canon) == link.entry_hash:
            return True
    return False


def compute_entry_hmac(key: bytes, entry_hash: str) -> str:
    """HMAC-SHA256 of entry_hash. Keyed layer of dual design."""
    return _hmac.new(key, entry_hash.encode("utf-8"), "sha256").hexdigest()


def resolve_hmac_key() -> Optional[bytes]:
    """
    Resolves HMAC key from environment (SIBERIAN_HMAC_KEY hex, or
    SIBERIAN_HMAC_KEY_FILE with raw bytes).

    Returns None if no key configured — unlike some systems, does NOT
    generate ephemeral key: a chain signed with unrecoverable key is
    indistinguishable from a tampered chain. Without key, chain operates
    in hash-only mode (documented, not error).
    """
    key_hex = os.getenv(_HMAC_KEY_ENV, "").strip()
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) < 32:
                print(
                    f"[SIBERIAN][hash_chain] WARNING: {_HMAC_KEY_ENV} has "
                    f"{len(key)} bytes — minimum recommended 32.",
                    file=sys.stderr, flush=True,
                )
            return key
        except ValueError:
            print(
                f"[SIBERIAN][hash_chain] WARNING: {_HMAC_KEY_ENV} not valid "
                "hex. Trying SIBERIAN_HMAC_KEY_FILE.",
                file=sys.stderr, flush=True,
            )

    key_file = os.getenv(_HMAC_KEY_FILE_ENV, "").strip()
    if key_file:
        try:
            key_path = Path(key_file)
            if key_path.is_file():
                key = key_path.read_bytes().strip()
                if len(key) >= 32:
                    return key
                print(
                    f"[SIBERIAN][hash_chain] WARNING: {key_file} contains only "
                    f"{len(key)} bytes — minimum 32. Ignored.",
                    file=sys.stderr, flush=True,
                )
        except OSError as exc:
            print(
                f"[SIBERIAN][hash_chain] WARNING: could not read {key_file}: {exc}",
                file=sys.stderr, flush=True,
            )
    return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainLink:
    """A stored link, ready for verification."""
    seq: int
    prev_hash: str
    entry_hash: str
    payload: Dict[str, Any]  # payload WITHOUT seq/prev_hash (added during verify)
    entry_hmac: Optional[str] = None


@dataclass
class ChainVerification:
    """
    Verification result with full error accumulation.

    valid is True only if ALL categories are empty.
    first_invalid_seq points to the first link with any error —
    the earliest tamper point.
    """
    valid: bool
    length: int
    first_invalid_seq: Optional[int] = None
    seq_discontinuities: List[Dict[str, Any]] = field(default_factory=list)
    broken_links: List[Dict[str, Any]] = field(default_factory=list)
    tampered_content: List[Dict[str, Any]] = field(default_factory=list)
    hmac_failures: List[Dict[str, Any]] = field(default_factory=list)
    hmac_checked: bool = False
    # R3-5 (tail-truncation anchor): deleting or appending entries AFTER
    # the last verified link leaves the remaining chain internally
    # consistent — nothing downstream notices. expected_tip
    # (chain_tip_sha256) is an externally-recorded anchor for the last
    # entry_hash; a mismatch means the tail was altered after sealing.
    tip_checked: bool = False
    tip_mismatch: bool = False
    expected_tip: Optional[str] = None
    actual_tip: Optional[str] = None
    # Keyed sibling of tip_checked — closes the residual gap where an
    # attacker with write access recomputes chain_tip_sha256 to match a
    # truncated tail (same limit as entry_hmac).
    tip_hmac_checked: bool = False
    tip_hmac_mismatch: bool = False
    # Timeline plausibility (separate axis, does NOT affect `valid` which
    # is cryptographic integrity): a causally impossible timeline seals
    # and verifies perfectly; this only warns that the recorded timeline
    # is implausible (non-monotonic, out of range, duplicate event).
    timeline_plausible: bool = True
    temporal_anomalies: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "length": self.length,
            "first_invalid_seq": self.first_invalid_seq,
            "seq_discontinuities": self.seq_discontinuities,
            "broken_links": self.broken_links,
            "tampered_content": self.tampered_content,
            "hmac_failures": self.hmac_failures,
            "hmac_checked": self.hmac_checked,
            "tip_checked": self.tip_checked,
            "tip_mismatch": self.tip_mismatch,
            "expected_tip": self.expected_tip,
            "actual_tip": self.actual_tip,
            "tip_hmac_checked": self.tip_hmac_checked,
            "tip_hmac_mismatch": self.tip_hmac_mismatch,
            "timeline_plausible": self.timeline_plausible,
            "temporal_anomalies": self.temporal_anomalies,
            "summary": {
                "seq_discontinuities": len(self.seq_discontinuities),
                "broken_links": len(self.broken_links),
                "tampered_content": len(self.tampered_content),
                "hmac_failures": len(self.hmac_failures),
                "temporal_anomalies": len(self.temporal_anomalies),
            },
        }


# ---------------------------------------------------------------------------
# Pure appender
# ---------------------------------------------------------------------------

def build_link(
    seq: int,
    prev_hash: str,
    payload: Dict[str, Any],
    hmac_key: Optional[bytes] = None,
) -> ChainLink:
    """Builds the next link (pure — caller persists)."""
    entry_hash = compute_entry_hash(seq, prev_hash, payload)
    entry_hmac = compute_entry_hmac(hmac_key, entry_hash) if hmac_key else None
    return ChainLink(
        seq=seq, prev_hash=prev_hash, entry_hash=entry_hash,
        payload=payload, entry_hmac=entry_hmac,
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_chain(
    links: Sequence[ChainLink],
    *,
    first_seq: int = 1,
    hmac_key: Optional[bytes] = None,
    expected_tip: Optional[str] = None,
    expected_tip_hmac: Optional[str] = None,
) -> ChainVerification:
    """
    Verifies a complete chain, ordered by ascending seq.

    Accumulates ALL errors (style of ChainOfCustody.verify):
      - seq_discontinuities : links deleted/inserted in middle
      - broken_links        : prev_hash != previous entry_hash
      - tampered_content    : entry_hash does not recompute from content
      - hmac_failures       : entry_hmac missing or does not recompute (if key)

    R3-5 — tail anchor (optional, passed by caller):
      - expected_tip      : declared entry_hash of last link (e.g.
        bundle["chain_tip_sha256"]), anchored OUTSIDE the `links` list
        that an attacker would truncate. If it doesn't match the
        recomputed tip, the tail was altered after sealing — deleting
        or inserting ONLY at the end leaves the rest of the chain
        internally consistent (see ChainOfCustody.checkpoint / RFC 3161
        for same problem in ledger).
      - expected_tip_hmac : HMAC-SHA256(hmac_key, expected_tip) declared.
        Closes expected_tip residual limit: pure SHA-256 is recomputable
        by anyone with write access (same as entry_hmac A3); tip HMAC
        only recomputable by key holder. Without hmac_key, not verified
        (documented, not error).
    """
    result = ChainVerification(
        valid=True, length=len(links), hmac_checked=hmac_key is not None,
    )
    expected_prev = GENESIS_HASH
    expected_seq = first_seq

    def _flag(seq: int) -> None:
        result.valid = False
        if result.first_invalid_seq is None or seq < result.first_invalid_seq:
            result.first_invalid_seq = seq

    for link in links:
        if link.seq != expected_seq:
            result.seq_discontinuities.append({
                "expected_seq": expected_seq,
                "found_seq": link.seq,
                "note": f"discontinuity: expected seq={expected_seq}, "
                        f"found seq={link.seq} — link deleted or inserted",
            })
            _flag(link.seq)
            expected_seq = link.seq  # continue verifying the rest

        if link.prev_hash != expected_prev:
            result.broken_links.append({
                "seq": link.seq,
                "stored_prev": link.prev_hash[:16] + "...",
                "expected_prev": expected_prev[:16] + "...",
                "note": "prev_hash does not match previous link's entry_hash",
            })
            _flag(link.seq)

        if not _entry_hash_matches(link):
            recomputed = compute_entry_hash(link.seq, link.prev_hash, link.payload)
            result.tampered_content.append({
                "seq": link.seq,
                "stored": link.entry_hash[:16] + "...",
                "recomputed": recomputed[:16] + "...",
                "note": "entry_hash does not recompute from content (neither v2 nor v1) — entry modified",
            })
            _flag(link.seq)

        if hmac_key is not None:
            if not link.entry_hmac:
                result.hmac_failures.append({
                    "seq": link.seq,
                    "note": "entry_hmac missing — link written without key or field deleted",
                })
                _flag(link.seq)
            elif not _hmac.compare_digest(
                link.entry_hmac, compute_entry_hmac(hmac_key, link.entry_hash)
            ):
                result.hmac_failures.append({
                    "seq": link.seq,
                    "note": "entry_hmac does not recompute — chain recomputed without key",
                })
                _flag(link.seq)

        expected_prev = link.entry_hash
        expected_seq = link.seq + 1

    # R3-5: tail anchor — expected_prev already holds recomputed tip
    # (entry_hash of last processed link, or GENESIS_HASH if no links)
    if expected_tip is not None:
        result.tip_checked = True
        result.expected_tip = expected_tip
        result.actual_tip = expected_prev
        if expected_prev != expected_tip:
            result.tip_mismatch = True
            _flag(links[-1].seq if links else first_seq)

        if hmac_key is not None and expected_tip_hmac is not None:
            result.tip_hmac_checked = True
            if not _hmac.compare_digest(
                expected_tip_hmac, compute_entry_hmac(hmac_key, expected_prev)
            ):
                result.tip_hmac_mismatch = True
                _flag(links[-1].seq if links else first_seq)

    # Timeline plausibility (separate axis, does NOT affect `valid`)
    _check_timeline_plausibility(links, result)
    return result


def _check_timeline_plausibility(
    links: Sequence[ChainLink], result: "ChainVerification"
) -> None:
    """
    Validates CAUSAL ORDER of recorded timeline — separate from
    cryptographic integrity. Detects:
      - NON_MONOTONIC_TIMESTAMP : a link with timestamp BEFORE previous
        (effect before cause in insertion order).
      - OUT_OF_RANGE_TIMESTAMP  : outside plausible forensic window.
      - DUPLICATE_CONTENT        : identical content to a previous link
        (same event re-recorded).
    Missing/unparseable timestamp does NOT mark implausible (cannot judge);
    logged as MISSING/UNPARSEABLE only if accompanied by another anomaly.
    `timeline_plausible` = no hard anomalies. This is plausibility, not
    a tampering verdict.
    """
    _PLAUSIBLE_MIN = datetime(2000, 1, 1, tzinfo=timezone.utc)
    _PLAUSIBLE_MAX = datetime(2038, 1, 19, 3, 14, 7, tzinfo=timezone.utc)

    def _parse_iso_ts(ts):
        if not isinstance(ts, str) or not ts.strip():
            return None
        try:
            dt = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

    prev_ts = None
    prev_seq = None
    seen_sig: Dict[str, int] = {}
    for link in links:
        ts_raw = link.payload.get("timestamp")
        dt = _parse_iso_ts(ts_raw)
        if dt is not None:
            if not (_PLAUSIBLE_MIN <= dt < _PLAUSIBLE_MAX):
                result.temporal_anomalies.append({
                    "seq": link.seq,
                    "type": "OUT_OF_RANGE_TIMESTAMP",
                    "timestamp": str(ts_raw),
                    "note": f"timestamp outside plausible forensic window "
                            f"[{_PLAUSIBLE_MIN.date()}, {_PLAUSIBLE_MAX.date()}) "
                            f"— epoch/overflow sentinel, not a real instant",
                })
            if prev_ts is not None and dt < prev_ts:
                result.temporal_anomalies.append({
                    "seq": link.seq,
                    "type": "NON_MONOTONIC_TIMESTAMP",
                    "timestamp": str(ts_raw),
                    "note": f"timestamp before link seq={prev_seq} "
                            f"— causally impossible order (effect before cause)",
                })
            prev_ts, prev_seq = dt, link.seq

        sig = _content_signature(link.payload)
        if sig in seen_sig:
            result.temporal_anomalies.append({
                "seq": link.seq,
                "type": "DUPLICATE_CONTENT",
                "note": f"identical content to link seq={seen_sig[sig]} "
                        f"— event re-recorded (chain proves insertion, "
                        f"not causal uniqueness)",
            })
        else:
            seen_sig[sig] = link.seq

    result.timeline_plausible = not result.temporal_anomalies


# ---------------------------------------------------------------------------
# ToolExecutionLogChain — appender for tool_execution_log v2
# ---------------------------------------------------------------------------

# Schema CLAUDE.md: result_summary truncated to 120 chars
RESULT_SUMMARY_MAX = 120

# Structural fields of the chain — everything else goes into the hash
_STRUCTURAL_FIELDS = frozenset({"seq", "prev_hash", "entry_hash", "entry_hmac"})


def _hashed_payload(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Content payload of an entry (without structural fields)."""
    return {k: v for k, v in entry.items() if k not in _STRUCTURAL_FIELDS}


class ToolExecutionLogChain:
    """
    Appender for tool_execution_log v2.

    Usage (agent / pipeline):
        chain = ToolExecutionLogChain(mode="cli")
        entry = chain.append(
            tool="analyze",
            target="case.json",
            result_summary="PASS: 5 present, 2 absent",
            arguments={"command": "analyze", "case": "case.json"},
        )
        bundle["tool_execution_log"].append(entry)

    HMAC key resolved once at construction (SIBERIAN_HMAC_KEY /
    SIBERIAN_HMAC_KEY_FILE). No key → hash-only mode, documented in
    each entry as hmac: absent.
    """

    def __init__(self, mode: str = "cli",
                 hmac_key: Optional[bytes] = None,
                 use_env_key: bool = True) -> None:
        self.mode = mode
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._hmac_key = hmac_key if hmac_key is not None else (
            resolve_hmac_key() if use_env_key else None
        )

    @property
    def tip_hash(self) -> str:
        """entry_hash of last link — for tip checkpoints."""
        return self._prev_hash

    @property
    def tip_hmac(self) -> Optional[str]:
        """HMAC-SHA256(key, tip_hash) — None if no key configured."""
        if not self._hmac_key:
            return None
        return compute_entry_hmac(self._hmac_key, self._prev_hash)

    @property
    def length(self) -> int:
        return self._seq

    def bundle_fields(self) -> Dict[str, Any]:
        """
        Bundle-level fields that anchor the chain tail (R3-5):
        chain_tip_sha256 (always) and chain_tip_hmac (if HMAC key).

        Caller writes them as SIBLINGS of tool_execution_log, OUTSIDE
        the array an attacker would truncate:

            bundle["tool_execution_log"] = log
            bundle.update(chain.bundle_fields())

        Without this, deleting the last N entries of tool_execution_log
        leaves the rest of the chain internally valid — nothing notices
        (see module docstring). chain_tip_sha256 detects this unless the
        attacker also recomputes it; chain_tip_hmac closes that residual
        (requires the key, same as entry_hmac for the rest of the chain).
        """
        fields: Dict[str, Any] = {"chain_tip_sha256": self.tip_hash}
        tip_hmac = self.tip_hmac
        if tip_hmac is not None:
            fields["chain_tip_hmac"] = tip_hmac
        return fields

    def append(
        self,
        tool: str,
        target: str,
        result_summary: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generates the next chained log entry.

        event_id/timestamp injectable for deterministic evaluation runs;
        in production generated here (uuid4 / UTC now).
        input_hash = SHA-256 of sanitized arguments as canonical JSON
        (sort_keys) — same as v1 scheme.
        """
        import uuid

        self._seq += 1
        args_json = json.dumps(arguments or {}, sort_keys=True,
                               ensure_ascii=True, default=str)
        entry: Dict[str, Any] = {
            "seq": self._seq,
            "event_id": event_id or str(uuid.uuid4()),
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "mode": self.mode,
            "tool": tool,
            "target": target,
            "result_summary": result_summary[:RESULT_SUMMARY_MAX],
            "input_hash": hashlib.sha256(args_json.encode("utf-8")).hexdigest(),
            "chain_version": CHAIN_SCHEMA_VERSION,
            "prev_hash": self._prev_hash,
        }
        entry_hash = compute_entry_hash(
            self._seq, self._prev_hash, _hashed_payload(entry)
        )
        entry["entry_hash"] = entry_hash
        if self._hmac_key:
            entry["entry_hmac"] = compute_entry_hmac(self._hmac_key, entry_hash)

        self._prev_hash = entry_hash
        return entry


# ---------------------------------------------------------------------------
# Dual v1/v2 verification (v1 legacy only protects result_summary)
# ---------------------------------------------------------------------------

def detect_chain_version(
    log: Sequence[Dict[str, Any]], *, expected_tip: Optional[str] = None,
    expected_tip_hmac: Optional[str] = None,
) -> str:
    """Detect v2 from any non-removable marker, never just entry zero.

    A v2 chain cannot be downgraded by deleting `entry_hash` from its
    first entry: any v2 marker elsewhere (including bundle-level tail
    anchor) keeps it on the v2 verifier, where a missing structural
    field fails.
    """
    if expected_tip is not None or expected_tip_hmac is not None:
        return "2"
    for entry in log:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("chain_version", "")) == "2":
            return "2"
        if "entry_hash" in entry or "entry_hmac" in entry:
            return "2"
    return "1"


def verify_tool_execution_log(
    log: Sequence[Dict[str, Any]],
    *,
    hmac_key: Optional[bytes] = None,
    expected_tip: Optional[str] = None,
    expected_tip_hmac: Optional[str] = None,
) -> ChainVerification:
    """
    Verifies a complete tool_execution_log, auto-detecting scheme.

    v2 → full verification via hash_chain.verify_chain (full content +
    linkage + seq + HMAC if key).
    v1 → legacy verification: only result_summary linkage. Result
    marks hmac_checked=False and does NOT guarantee integrity of other
    fields (structural weakness of v1). expected_tip/expected_tip_hmac
    (R3-5) ignored under v1 — chain_tip_sha256 is a v2 concept.
    """
    if detect_chain_version(
        log, expected_tip=expected_tip, expected_tip_hmac=expected_tip_hmac,
    ) == "2":
        links = [
            ChainLink(
                seq=e.get("seq", 0),
                prev_hash=e.get("prev_hash", ""),
                entry_hash=e.get("entry_hash", ""),
                payload=_hashed_payload(e),
                entry_hmac=e.get("entry_hmac"),
            )
            for e in log
        ]
        return verify_chain(
            links, first_seq=1, hmac_key=hmac_key,
            expected_tip=expected_tip, expected_tip_hmac=expected_tip_hmac,
        )

    # v1 legacy
    result = ChainVerification(valid=True, length=len(log), hmac_checked=False)
    prev_summary: Optional[str] = None
    expected_seq = 1
    for e in log:
        seq = e.get("seq", 0)
        if seq != expected_seq:
            result.seq_discontinuities.append({
                "expected_seq": expected_seq, "found_seq": seq,
                "note": "seq discontinuity (v1 scheme)",
            })
            result.valid = False
            if result.first_invalid_seq is None:
                result.first_invalid_seq = seq
            expected_seq = seq
        prev_hash = e.get("prev_hash", "")
        if seq == 1:
            ok = prev_hash == "GENESIS"
        else:
            expected = (
                hashlib.sha256(prev_summary.encode("utf-8")).hexdigest()
                if prev_summary is not None else ""
            )
            ok = prev_hash == expected
        if not ok:
            result.broken_links.append({
                "seq": seq,
                "note": "v1 prev_hash does not match SHA-256(previous result_summary)",
            })
            result.valid = False
            if result.first_invalid_seq is None or seq < result.first_invalid_seq:
                result.first_invalid_seq = seq
        prev_summary = e.get("result_summary", "")
        expected_seq = seq + 1
    return result


def verify_bundle_tool_log(
    bundle: Dict[str, Any],
    *,
    hmac_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Convenience: verifies bundle["tool_execution_log"] and returns
    reportable dict (for amicus curiae / reports).

    R3-5: if bundle has chain_tip_sha256 (and optionally chain_tip_hmac),
    they are used to anchor the log tail — see ToolExecutionLogChain.bundle_fields
    and verify_chain docstring. Only applies under v2.
    """
    log: List[Dict[str, Any]] = bundle.get("tool_execution_log", [])
    version = detect_chain_version(log)
    expected_tip = bundle.get("chain_tip_sha256") if version == "2" else None
    expected_tip_hmac = bundle.get("chain_tip_hmac") if version == "2" else None
    verification = verify_tool_execution_log(
        log, hmac_key=hmac_key,
        expected_tip=expected_tip, expected_tip_hmac=expected_tip_hmac,
    )
    report = verification.to_dict()
    report["chain_version"] = version
    if version == "1":
        report["v1_caveat"] = (
            "Legacy v1 scheme: only result_summary protected by chain. "
            "timestamp/tool/target/input_hash not tamper-evident, and "
            "last entry's result_summary editable. Structural verification, "
            "not full content integrity."
        )
    elif expected_tip is None:
        report["chain_tip_caveat"] = (
            "chain_tip_sha256 missing from bundle: tool_execution_log "
            "tail can be truncated (last entries deleted) without internal "
            "chain detecting it — linkage only proves consistency of what "
            "remains, not completeness."
        )
    return report