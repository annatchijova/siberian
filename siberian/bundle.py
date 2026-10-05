"""
siberian/bundle.py
==================
Evidence Matrix Bundle Specification v1 — Pure Data Models + External Attestation.

ARCHITECTURE: Layer 0 — Data & Contracts (IMMUTABLE) + Layer 5 — External Attestation.

ABSOLUTE RULE: This module contains DATA MODELS + BUILDER.
    - Data models: pure data, no hashing, no sealing
    - BundleBuilder: external attestation process, independent of the analysis engine
    - Sealing is performed by BundleBuilder.seal() as an external process

RATIONALE:
    A bundle that hashes itself allows a compromised engine to seal its own
    lie. Sealing must be an external attestation process, independent of the
    inference engine that produced the data. The analyzer produces data; the
    builder attests to it.

INVARIANTS:
    I1 Determinism:          same analytical input → same analysis_fingerprint
    I2 Chained integrity:    bundle_hash covers ALL content
    I3 Verifiable policy:    catalog_version independent of runtime
    I4 Explicit observations: no implicit side effects
    I5 Explainable result:   counts and records ALWAYS present

COMPATIBILITY:
    Python 3.10+
    No external dependencies (stdlib only for data models)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .adversarial_silence import (
    ActionEvidence,
    AnalysisContext,
    ArtifactStatus,
    ANALYSIS_SCHEMA_VERSION,
    ConditionEvidence,
    ExpectedArtifact,
    Observation,
    ObservationReason,
    SilenceAnalysisResult,
    SilenceRecord,
)
from .canonicalize import _canonicalize, _canonicalize_v1, _canonicalize_v2

# ---------------------------------------------------------------------------
# Standard constants
# NOTE: verify.py replicates these locally — it does not import from here.
# ---------------------------------------------------------------------------

BUNDLE_VERSION: str = "1.0"
BUNDLE_SUPPORTED_VERSIONS: List[str] = ["1.0"]

CATALOG_VERSION: str = "windows-msdocs-2026-10-04-v3"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ===========================================================================
# IntegrityBlock — Chained SHA-256 hashes
# ===========================================================================

class IntegrityBlock:
    """
    Chained SHA-256 hashes plus an optional stable analytical replay
    fingerprint. bundle_hash remains the identity of a concrete,
    timestamped custody event.

    Produced by BundleBuilder.seal() — never by EvidenceMatrixBundle itself.
    """

    def __init__(
        self,
        bundle_hash: str = "",
        records_hash: str = "",
        context_hash: str = "",
        catalog_hash: str = "",
        analysis_fingerprint: str = "",
        engine_attestation_hash: str = "",
        sealed_at: Optional[str] = None,
    ) -> None:
        self.bundle_hash = bundle_hash
        self.records_hash = records_hash
        self.context_hash = context_hash
        self.catalog_hash = catalog_hash
        self.analysis_fingerprint = analysis_fingerprint
        self.engine_attestation_hash = engine_attestation_hash
        self.sealed_at = sealed_at or _now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_hash": self.bundle_hash,
            "records_hash": self.records_hash,
            "context_hash": self.context_hash,
            "catalog_hash": self.catalog_hash,
            "analysis_fingerprint": self.analysis_fingerprint,
            "engine_attestation_hash": self.engine_attestation_hash,
            "sealed_at": self.sealed_at,
        }


# ===========================================================================
# EvidenceMatrixBundle — PURE DATA STRUCTURE
# No seal(), no hashing, no quick_verify()
# Sealing is the exclusive responsibility of BundleBuilder
# ===========================================================================

class EvidenceMatrixBundle:
    """
    SIBERIAN Evidence Matrix Bundle v1 — pure data container.

    REFACTORED: This object does NOT seal itself.
    Sealing is performed by BundleBuilder as an external
    attestation process. This guarantees a compromised engine cannot seal
    its own lie.

    Correct flow:
        bundle = EvidenceMatrixBundle(...)           # pure data
        sealed_dict = BundleBuilder.seal(bundle)     # external attestation
        BundleBuilder.save(sealed_dict, path)
        # => python3 -m siberian.verify path  (stdlib only, no production imports)
    """

    VERSION = BUNDLE_VERSION

    def __init__(
        self,
        context: AnalysisContext,
        catalog_version: str,
        records: Tuple[SilenceRecord, ...],
        expected_count: int,
        present_count: int,
        confirmed_absent_count: int,
        unknown_count: int,
        out_of_scope_count: int,
        schema_version: str = ANALYSIS_SCHEMA_VERSION,
    ) -> None:
        self.bundle_id: str = _new_uuid()
        self.bundle_version: str = self.VERSION
        self.timestamp: str = _now_iso()
        self.context: AnalysisContext = context
        self.catalog_version: str = catalog_version
        self.schema_version: str = schema_version
        self.records: Tuple[SilenceRecord, ...] = records
        self.expected_count: int = expected_count
        self.present_count: int = present_count
        self.confirmed_absent_count: int = confirmed_absent_count
        self.unknown_count: int = unknown_count
        self.out_of_scope_count: int = out_of_scope_count
        # integrity: assigned externally by BundleBuilder.seal()
        self.integrity: Optional[IntegrityBlock] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize bundle contents (without integrity — BundleBuilder appends it).
        """
        return {
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "timestamp": self.timestamp,
            "context": self._context_to_dict(self.context),
            "catalog_version": self.catalog_version,
            "schema_version": self.schema_version,
            "records": [self._record_to_dict(r) for r in self.records],
            "counts": {
                "expected": self.expected_count,
                "present": self.present_count,
                "confirmed_absent": self.confirmed_absent_count,
                "unknown": self.unknown_count,
                "out_of_scope": self.out_of_scope_count,
            },
        }

    @staticmethod
    def _context_to_dict(ctx: AnalysisContext) -> Dict[str, Any]:
        return {
            "os_profile": ctx.os_profile,
            "os_release": ctx.os_release,
            "system_build": ctx.system_build,
            "os_edition": ctx.os_edition,
            "architecture": ctx.architecture,
            "build_revision": ctx.build_revision,
            "servicing_channel": ctx.servicing_channel,
            "scope": ctx.scope,
            "interval_start": ctx.interval_start.isoformat(timespec="microseconds"),
            "interval_end": ctx.interval_end.isoformat(timespec="microseconds"),
            "acquisition_ref": ctx.acquisition_ref,
        }

    @staticmethod
    def _record_to_dict(record: SilenceRecord) -> Dict[str, Any]:
        entry = record.expected_artifact
        obs = record.observation
        return {
            "action": record.action,
            "artifact_type": entry.artifact_type,
            "description": entry.description,
            "scope": entry.scope,
            "required_conditions": list(entry.required_conditions),
            "retention": entry.retention,
            "interpretation_limit": entry.interpretation_limit,
            "source_refs": [
                {"title": title, "url": url} for title, url in entry.source_refs
            ],
            "status": obs.status.value,
            "reason": obs.reason.value if obs.reason else None,
            "evidence_ref": obs.evidence_ref,
            "primary_action_evidence": (
                {
                    "evidence_ref": record.action_evidence.evidence_ref,
                    "observed_at": record.action_evidence.observed_at.isoformat(timespec="microseconds"),
                }
                if record.action_evidence
                else None
            ),
            "condition_evidence": [
                {
                    "condition": name,
                    "evidence_ref": evidence.evidence_ref,
                    "valid_from": evidence.valid_from.isoformat(timespec="microseconds"),
                    "valid_until": evidence.valid_until.isoformat(timespec="microseconds"),
                }
                for name, evidence in obs.condition_evidence
            ],
        }

    def __repr__(self) -> str:
        sealed = self.integrity is not None
        return (
            f"<EvidenceMatrixBundle id={self.bundle_id[:8]} "
            f"records={len(self.records)} "
            f"sealed={'YES' if sealed else 'NO'}>"
        )


# ===========================================================================
# BundleBuilder — external attestation process
# ===========================================================================

# R6-1 — Fields that travel in the bundle but are NOT part of the
# payload hashed by seal(). seal() excludes them by construction (builds
# bundle_payload from a fixed list), so ANY verifier that recomposes the
# payload as "everything except integrity" must also exclude them, or it
# will declare invalid a bundle that SIBERIAN correctly produced.
#
#   integrity            — written by seal(): contains the bundle_hash
#   tool_execution_log   — attached by the agent: anchored by
#                          chain_tip_sha256, which IS inside the sealed payload
#
# These fields are NOT covered by bundle_hash. Their authenticity comes from
# elsewhere (the ledger, the chain of verify_tool_log.py respectively) and
# verifiers must report this, not silently assume coverage.
PRESENTATION_FIELDS = ("integrity", "tool_execution_log")

# R6-1: historically there may be multiple payload schemas. Modern bundles
# carry tool_execution_log as presentation field (anchored by chain_tip_sha256,
# which IS inside the seal); historical ones might hash it. A verifier that
# assumes only one scheme declares the other invalid.
_LEGACY_HASHED_FIELDS = ("tool_execution_log",)


def _sealed_payload(sealed_dict: Dict, legacy: bool = False) -> Dict:
    """Payload hashed by a sealed bundle: everything except presentation fields.

    `legacy=True` reincorporates fields that the historical scheme hashed.
    """
    excluded = tuple(
        f for f in PRESENTATION_FIELDS
        if not (legacy and f in _LEGACY_HASHED_FIELDS)
    )
    return {k: v for k, v in sealed_dict.items() if k not in excluded}


def _matching_payload(sealed_dict: Dict, stored: str):
    """Return (payload, scheme) whose hash matches `stored`, or (None, None).

    Tries modern scheme first: if both match (bundle without tool_execution_log),
    they are the same payload and it doesn't matter.
    """
    for legacy in (False, True):
        payload = _sealed_payload(sealed_dict, legacy=legacy)
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
    """
    SHA-256 deterministic of a dict with strict canonical form.

    Uses _canonicalize() before serializing to guarantee that
    int(1) and float(1.0) produce distinct, reproducible hashes
    across architectures and Python versions.
    """
    import hashlib

    canonical = canon(obj)
    serialized = json.dumps(canonical, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _analysis_projection(bundle_payload: Dict) -> Dict:
    """Return the stable analytical content of a full bundle payload.

    bundle_hash is intentionally an identity for a specific custody event:
    it includes the newly assigned bundle_id and timestamps. Those fields
    must remain sealed, but cannot identify a deterministic replay. This
    projection removes ONLY that operational identity metadata; all
    analytical content, configuration attestation, records, and catalog
    remain in scope.

    The helper is local and pure so quick_verify and the standalone
    verifier can independently re-derive the same contract.
    """
    projection = dict(bundle_payload)
    projection.pop("bundle_id", None)
    projection.pop("timestamp", None)

    # Also strip timestamps from nested structures if present
    context = dict(projection.get("context", {}))
    context.pop("interval_start", None)
    context.pop("interval_end", None)
    projection["context"] = context

    return projection


class BundleBuilder:
    """
    External cryptographic attestation process for EvidenceMatrixBundle.

    Usage:
        bundle = EvidenceMatrixBundle(...)
        sealed = BundleBuilder.seal(bundle)
        path = BundleBuilder.save(sealed, "output/bundle.json")
        # => python3 -m siberian.verify output/bundle.json
    """

    @staticmethod
    def seal(
        bundle: EvidenceMatrixBundle,
        engine_attestation_hash: str = "",
        tool_log_tip: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Seals the bundle producing a complete JSON dict with chained hashes.

        PROTOCOL (identical to what verify.py implements):

        Step 1: records_hash over sorted records
        Step 2: context_hash over context
        Step 3: catalog_hash over catalog_version
        Step 4: bundle_hash over complete snapshot (includes all above hashes)

        Returns a serializable dict ready for storage.
        Does not modify the original EvidenceMatrixBundle object.
        """
        # Immutable snapshot of content at this moment
        bundle_dict = bundle.to_dict()

        # Step 1: records_hash over the records array (deterministic order already)
        records_for_hash = bundle_dict["records"]
        records_hash = _sha256_dict({"records": records_for_hash})

        # Step 2: context_hash over context
        context_hash = _sha256_dict(bundle_dict["context"])

        # Step 3: catalog_hash over catalog_version
        catalog_hash = _sha256_dict({"catalog_version": bundle_dict["catalog_version"]})

        # Step 4: bundle_hash over EVERYTHING (I2)
        bundle_payload = dict(bundle_dict)
        bundle_payload["records_hash"] = records_hash
        bundle_payload["context_hash"] = context_hash
        bundle_payload["catalog_hash"] = catalog_hash

        # R6-2 — Anchor tool_execution_log tip INSIDE the seal. The log array
        # travels as presentation field (cannot hash a sibling without breaking
        # the seal: seal() builds payload from a fixed list), but its TIP
        # enters the bundle_hash. Result: truncating or rewriting the log
        # breaks verify_tool_log.py comparison against the tip, and rewriting
        # the tip to cover it up breaks bundle_hash — which is itself anchored
        # in the custody ledger with checkpoint HMAC.
        if tool_log_tip:
            for field in ("chain_tip_sha256", "chain_tip_hmac"):
                value = tool_log_tip.get(field)
                if value:
                    bundle_payload[field] = value

        analysis_fingerprint = _sha256_dict(_analysis_projection(bundle_payload))
        bundle_hash = _sha256_dict(bundle_payload)

        integrity = IntegrityBlock(
            bundle_hash=bundle_hash,
            records_hash=records_hash,
            context_hash=context_hash,
            catalog_hash=catalog_hash,
            analysis_fingerprint=analysis_fingerprint,
            engine_attestation_hash=engine_attestation_hash,
        )

        # Assign to original object for in-memory reference
        bundle.integrity = integrity

        # Produce complete sealed dict
        sealed = dict(bundle_payload)
        sealed["integrity"] = integrity.to_dict()

        return sealed

    @staticmethod
    def save(sealed_dict: Dict[str, Any], path: str) -> str:
        """
        Saves sealed bundle to disk with atomic write.
        Returns file hash for transport verification.

        L-023 FIX: ATOMIC WRITE — mkstemp in same dir + fsync + os.replace.
        Before: written directly to `path` without fsync or atomic rename —
        between write and hash computation (from memory, not disk) the file
        could be swapped (symlink attack / concurrent writer) — chain of
        custody break under Daubert. Now:
          1. content written to tempfile on same filesystem
          2. fsync guarantees it reached disk
          3. os.replace publishes atomically (never a half-written bundle at `path`)
          4. returned hash computed FROM DISK post-replace and verified against
             in-memory hash — divergence = RuntimeError.
        """
        import hashlib
        import tempfile
        import os

        abs_path = os.path.abspath(path)
        content = json.dumps(sealed_dict, sort_keys=True, indent=2, default=str)
        target_dir = os.path.dirname(abs_path)
        os.makedirs(target_dir, exist_ok=True)

        mem_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        fd, tmp_path = tempfile.mkstemp(
            dir=target_dir, prefix=".bundle_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, abs_path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        # Hash from disk: what gets verified is what got written,
        # not what was in memory.
        with open(abs_path, "rb") as f:
            disk_hash = hashlib.sha256(f.read()).hexdigest()
        if disk_hash != mem_hash:
            raise RuntimeError(
                f"L-023: disk hash differs from memory hash after atomic "
                f"write ({disk_hash[:16]} != {mem_hash[:16]}) — "
                f"possible filesystem corruption or concurrent tampering."
            )
        return disk_hash

    @staticmethod
    def quick_verify(sealed_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Quick internal verification (does not replace verify.py).
        Reimplements hashing logic without calling external verifier.

        Returns: (is_valid: bool, message: str)
        """
        try:
            integrity = sealed_dict.get("integrity", {})
            stored_bundle_hash = integrity.get("bundle_hash", "")
            stored_records_hash = integrity.get("records_hash", "")
            stored_context_hash = integrity.get("context_hash", "")
            stored_catalog_hash = integrity.get("catalog_hash", "")
            stored_analysis_fingerprint = integrity.get("analysis_fingerprint", "")

            # Verify records_hash
            records = sealed_dict.get("records", [])
            if not _sha256_dict_matches({"records": records}, stored_records_hash):
                recomputed = _sha256_dict({"records": records})
                return False, f"records_hash invalid: {recomputed[:8]}!={stored_records_hash[:8]}"

            # Verify context_hash
            context = sealed_dict.get("context", {})
            if not _sha256_dict_matches(context, stored_context_hash):
                recomputed = _sha256_dict(context)
                return False, f"context_hash invalid: {recomputed[:8]}!={stored_context_hash[:8]}"

            # Verify catalog_hash
            catalog_version = sealed_dict.get("catalog_version", "")
            if not _sha256_dict_matches({"catalog_version": catalog_version}, stored_catalog_hash):
                recomputed = _sha256_dict({"catalog_version": catalog_version})
                return False, f"catalog_hash invalid: {recomputed[:8]}!={stored_catalog_hash[:8]}"

            # Verify bundle_hash (tries v2 then v1 — backward-compat)
            payload, _scheme = _matching_payload(sealed_dict, stored_bundle_hash)
            if payload is None:
                payload = _sealed_payload(sealed_dict)
                recomputed = _sha256_dict(payload)
                return False, f"bundle_hash invalid: {recomputed[:8]}!={stored_bundle_hash[:8]}"

            # Verify analysis_fingerprint if present
            if stored_analysis_fingerprint and not _sha256_dict_matches(
                _analysis_projection(payload), stored_analysis_fingerprint
            ):
                recomputed = _sha256_dict(_analysis_projection(payload))
                return False, f"analysis_fingerprint invalid: {recomputed[:8]}!={stored_analysis_fingerprint[:8]}"

            return True, "OK — bundle intact"

        except Exception as e:
            return False, f"Error in quick_verify: {e}"

    @staticmethod
    def compute_engine_attestation(
        source_dirs: Optional[List[str]] = None,
        dep_files: Optional[List[str]] = None,
    ) -> str:
        """
        Computes engine_attestation_hash over source code + dependency versions.

        hash(source_code + requirements.txt + pyproject.toml)

        H32: The engine is the code + its libraries. If someone changes the
        version of a dependency, the results can differ with the same code.
        The attestation must capture both dimensions to be Daubert-valid.

        Only includes .py source files. Excludes:
        - __pycache__/ and any .pyc / .pyo
        - OS temporary files (*.tmp, *.swp, *~, .DS_Store)
        - Logs and coverage files (*.log, .coverage)
        """
        import os

        _EXCLUDED_DIRS = {"__pycache__", ".git", ".mypy_cache", ".ruff_cache", "node_modules"}
        _EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tmp", ".swp", ".log", ".coverage"}
        _EXCLUDED_NAMES = {".DS_Store", "Thumbs.db"}

        # Decision modules at repo root (outside _ROOT=<repo>/siberian).
        # Authoritative set = the --cov of pyproject.toml.
        _ROOT_DECISION_MODULES = (
            "siberian/cli.py",
            "siberian/adversarial_silence.py",
            "siberian/bundle.py",
        )

        _DEFAULT_DEP_FILES = ["requirements.txt", "pyproject.toml"]

        try:
            import hashlib

            _ROOT = os.path.dirname(os.path.abspath(__file__))
            _REPO_ROOT = os.path.dirname(_ROOT)

            dirs = source_dirs or [_ROOT]
            sources = []

            # 1. Source code .py
            for d in dirs:
                for root, subdirs, files in os.walk(d):
                    subdirs[:] = sorted(
                        s for s in subdirs if s not in _EXCLUDED_DIRS
                    )
                    for fname in sorted(files):
                        if not fname.endswith(".py"):
                            continue
                        if fname in _EXCLUDED_NAMES:
                            continue
                        if any(fname.endswith(suf) for suf in _EXCLUDED_SUFFIXES):
                            continue
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "rb") as f:
                                sources.append(f.read())
                        except OSError as exc:
                            # Honest degradation: in-scope source file that
                            # cannot be read must PERTURB the attestation, never
                            # vanish silently.
                            marker = f"UNREADABLE_SOURCE:{os.path.relpath(fpath, d)}\n"
                            sources.append(marker.encode("utf-8"))

            # 1b. Decision modules at repo root (only in default mode)
            if source_dirs is None:
                for mod_name in _ROOT_DECISION_MODULES:
                    mpath = os.path.join(_REPO_ROOT, mod_name)
                    if not os.path.isfile(mpath):
                        marker = f"MISSING_ROOT_MODULE:{mod_name}\n"
                        sources.append(marker.encode("utf-8"))
                        continue
                    try:
                        with open(mpath, "rb") as f:
                            sources.append(
                                f"ROOT:{mod_name}\n".encode("utf-8") + f.read()
                            )
                    except OSError as exc:
                        marker = f"UNREADABLE_ROOT_MODULE:{mod_name}\n"
                        sources.append(marker.encode("utf-8"))

            # 2. Dependency files
            dep_paths = dep_files if dep_files is not None else _DEFAULT_DEP_FILES
            for dep_name in dep_paths:
                candidates = [
                    os.path.join(_ROOT, dep_name),
                    os.path.join(_REPO_ROOT, dep_name),
                ]
                for candidate in candidates:
                    if os.path.isfile(candidate):
                        try:
                            with open(candidate, "rb") as f:
                                dep_content = f.read()
                            sources.append(f"DEP:{dep_name}\n".encode("utf-8") + dep_content)
                        except OSError as exc:
                            sources.append(f"UNREADABLE_DEP:{dep_name}\n".encode("utf-8"))
                        break

            combined = b"".join(sources)
            return hashlib.sha256(combined).hexdigest()
        except Exception:
            # Total attestation failure must not be silent: "" downstream reads
            # as "attestation unavailable", which is the honest outcome.
            return ""

    @staticmethod
    def build_from_analysis(result: SilenceAnalysisResult) -> EvidenceMatrixBundle:
        """Convenience: build bundle directly from SilenceAnalysisResult."""
        return EvidenceMatrixBundle(
            context=result.context,
            catalog_version=result.catalog_version,
            records=result.records,
            expected_count=result.expected_count,
            present_count=result.present_count,
            confirmed_absent_count=result.confirmed_absent_count,
            unknown_count=result.unknown_count,
            out_of_scope_count=result.out_of_scope_count,
            schema_version=result.schema_version,
        )


# Re-export for convenience
from .adversarial_silence import CATALOG_VERSION  # noqa: E402,F401