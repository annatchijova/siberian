"""
siberian/hypotheses.py
======================
Versioned hypothesis models for rival explanation analysis.

Each hypothesis is a data structure (not generated prose) with explicit
assumptions, predictions, and discriminating criteria. This enables
automated comparison against observations and transparent reporting.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from .adversarial_silence import (
    ArtifactStatus,
    ObservationReason,
    SilenceAnalysisResult,
    SilenceRecord,
)


class HypothesisType(str, Enum):
    """Categories of rival explanations for observed silence patterns."""
    BENIGN_LOSS = "benign_loss"           # retention, rollover, config, acquisition gap
    SELECTIVE_DELETION = "selective_deletion"  # deliberate selective erasure
    SENSOR_FAILURE = "sensor_failure"     # tool/parser/collection failure
    CONFIGURATION_GAP = "configuration_gap"    # audit policy not enabled, etc.
    NON_APPLICABLE = "non_applicable"     # artifact doesn't apply to this platform/config


@dataclass(frozen=True)
class HypothesisAssumption:
    """Single assumption a hypothesis depends on."""
    name: str
    description: str
    # If this assumption is falsified, the hypothesis loses support
    falsifiable_by: str  # What observation would falsify this assumption
    # Confidence in this assumption (0.0-1.0) based on available evidence
    confidence: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")


@dataclass(frozen=True)
class DiscriminatingPrediction:
    """A testable prediction that would favor or disfavor this hypothesis."""
    description: str
    # Expected observation status if hypothesis is true
    expected_status: ArtifactStatus
    # For which (action, artifact_type) this prediction applies
    applies_to: Tuple[str, str]
    # How strongly this prediction discriminates (0.0-1.0)
    discriminative_power: float
    # If observed, this would falsify the hypothesis
    falsifies_if: Optional[ArtifactStatus] = None

    def __post_init__(self) -> None:
        if not (0.0 <= self.discriminative_power <= 1.0):
            raise ValueError(f"discriminative_power must be in [0.0, 1.0], got {self.discriminative_power}")


@dataclass(frozen=True)
class EvidencePivot:
    """An observation that would discriminate between competing hypotheses."""
    description: str
    # The (action, artifact_type) to observe
    target: Tuple[str, str]
    # Which hypotheses would be favored/disfavored by each outcome
    # Map from hypothesis_id -> {status: "favors"|"disfavors"|"neutral"}
    hypothesis_impact: Dict[str, Dict[ArtifactStatus, str]]
    # Current status (if already observed)
    current_status: Optional[ArtifactStatus] = None
    current_reason: Optional[ObservationReason] = None

    def __post_init__(self) -> None:
        valid_impacts = {"favors", "disfavors", "neutral"}
        for h_id, impact_map in self.hypothesis_impact.items():
            for status, impact in impact_map.items():
                if impact not in valid_impacts:
                    raise ValueError(
                        f"hypothesis_impact[{h_id}][{status.value}] = {impact!r} "
                        f"must be one of {valid_impacts}"
                    )


@dataclass(frozen=True)
class Hypothesis:
    """
    A versioned, testable hypothesis explaining observed silence patterns.
    
    NOT generated prose — explicit data structure with assumptions,
    predictions, and falsification criteria.
    """
    hypothesis_id: str
    hypothesis_type: HypothesisType
    version: str
    created_at: str
    name: str
    description: str
    # Explicit assumptions this hypothesis rests on
    assumptions: Tuple[HypothesisAssumption, ...] = ()
    # Testable predictions
    predictions: Tuple[DiscriminatingPrediction, ...] = ()
    # Evidence pivots that would discriminate this from rivals
    evidence_pivots: Tuple[EvidencePivot, ...] = ()
    # Which artifact-status combinations this hypothesis explains
    explained_observations: Tuple[Tuple[str, str, ArtifactStatus], ...] = ()
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, hypothesis_type: HypothesisType, name: str, description: str,
               version: str = "1.0", hypothesis_id: Optional[str] = None) -> "Hypothesis":
        """Factory for new hypotheses with stable ID and timestamp.
        
        If hypothesis_id is not provided, generates a stable ID from name and type.
        """
        if hypothesis_id is None:
            # Stable ID: lowercase name with underscores + type prefix
            base = name.lower().replace(" ", "_").replace("-", "_")
            type_prefix = hypothesis_type.value.split("_")[0][:3]
            hypothesis_id = f"{type_prefix}_{base}"
        return cls(
            hypothesis_id=hypothesis_id,
            hypothesis_type=hypothesis_type,
            version=version,
            created_at=datetime.now(timezone.utc).isoformat(),
            name=name,
            description=description,
        )


# ---------------------------------------------------------------------------
# Built-in hypothesis templates for SIBERIAN
# ---------------------------------------------------------------------------

def benign_loss_hypothesis() -> Hypothesis:
    """Ordinary loss: retention, rollover, config, acquisition gap."""
    h = Hypothesis.create(
        HypothesisType.BENIGN_LOSS,
        "Benign Loss",
        "Observed absences are explained by ordinary operational factors: "
        "log retention limits, rollover, disabled audit policy, incomplete "
        "acquisition, or parser limitations. No deliberate deletion required.",
        hypothesis_id="benign_loss",
    )
    return replace(h,
        assumptions=(
            HypothesisAssumption(
                name="retention_limits",
                description="Security logs have finite retention and may rollover",
                falsifiable_by="USN journal shows entries for the interval but Security log does not",
                confidence=0.8,
            ),
            HypothesisAssumption(
                name="audit_policy_disabled",
                description="Required audit subcategories were not enabled",
                falsifiable_by="AuditPol shows success auditing enabled for relevant subcategories",
                confidence=0.7,
            ),
            HypothesisAssumption(
                name="acquisition_incomplete",
                description="Evidence collection did not cover the full interval",
                falsifiable_by="Acquisition manifest shows continuous coverage",
                confidence=0.6,
            ),
        ),
        predictions=(
            DiscriminatingPrediction(
                description="If retention limit reached, oldest entries missing first",
                expected_status=ArtifactStatus.UNKNOWN,
                applies_to=("any", "any"),
                discriminative_power=0.3,
                falsifies_if=ArtifactStatus.CONFIRMED_ABSENT,  # Confirmed absence with full conditions
            ),
            DiscriminatingPrediction(
                description="If audit policy disabled, all events of that type absent",
                expected_status=ArtifactStatus.UNKNOWN,
                applies_to=("any", "security_event_4688"),
                discriminative_power=0.4,
                falsifies_if=ArtifactStatus.PRESENT,
            ),
        ),
        evidence_pivots=(
            EvidencePivot(
                description="AuditPol configuration for the interval",
                target=("process_execution", "security_event_4688"),
                hypothesis_impact={
                    "benign_loss": {ArtifactStatus.CONFIRMED_ABSENT: "disfavors", ArtifactStatus.UNKNOWN: "favors"},
                    "selective_deletion": {ArtifactStatus.CONFIRMED_ABSENT: "favors", ArtifactStatus.UNKNOWN: "neutral"},
                },
            ),
            EvidencePivot(
                description="USN journal coverage for the interval",
                target=("file_change", "ntfs_usn_change_journal"),
                hypothesis_impact={
                    "benign_loss": {ArtifactStatus.CONFIRMED_ABSENT: "disfavors", ArtifactStatus.UNKNOWN: "favors"},
                    "selective_deletion": {ArtifactStatus.CONFIRMED_ABSENT: "favors", ArtifactStatus.UNKNOWN: "neutral"},
                },
            ),
        ),
        explained_observations=(
            ("process_execution", "security_event_4688", ArtifactStatus.UNKNOWN),
            ("permitted_network_connection", "security_event_5156", ArtifactStatus.UNKNOWN),
            ("successful_logon", "security_event_4624", ArtifactStatus.UNKNOWN),
            ("session_termination", "security_event_4634", ArtifactStatus.UNKNOWN),
            ("file_change", "ntfs_usn_change_journal", ArtifactStatus.UNKNOWN),
        ),
    )


def selective_deletion_hypothesis() -> Hypothesis:
    """Deliberate selective erasure: attacker removed specific artifacts."""
    h = Hypothesis.create(
        HypothesisType.SELECTIVE_DELETION,
        "Selective Deletion",
        "An attacker with sufficient privileges selectively deleted specific "
        "forensic artifacts to impede investigation. Absence pattern shows "
        "preference for hard-to-erase artifacts (high erasure difficulty).",
        hypothesis_id="selective_deletion",
    )
    return replace(h,
        assumptions=(
            HypothesisAssumption(
                name="attacker_privileges",
                description="Attacker had admin/SYSTEM privileges to delete artifacts",
                falsifiable_by="No evidence of privilege escalation in event logs",
                confidence=0.6,
            ),
            HypothesisAssumption(
                name="selective_targeting",
                description="Attacker knew which artifacts are forensically valuable",
                falsifiable_by="Absence pattern correlates with forensic value, not ease of deletion",
                confidence=0.7,
            ),
            HypothesisAssumption(
                name="deletion_tools_available",
                description="Tools capable of selective artifact deletion were available",
                falsifiable_by="No traces of anti-forensic tools (e.g., timestomp, clearlogs)",
                confidence=0.5,
            ),
        ),
        predictions=(
            DiscriminatingPrediction(
                description="Hard-to-erase artifacts absent while easy-to-erase present",
                expected_status=ArtifactStatus.CONFIRMED_ABSENT,
                applies_to=("file_change", "ntfs_usn_change_journal"),
                discriminative_power=0.8,
                falsifies_if=ArtifactStatus.PRESENT,
            ),
            DiscriminatingPrediction(
                description="Pattern shows selectivity — not all artifacts absent",
                expected_status=ArtifactStatus.CONFIRMED_ABSENT,
                applies_to=("process_execution", "security_event_4688"),
                discriminative_power=0.6,
                falsifies_if=ArtifactStatus.PRESENT,
            ),
            DiscriminatingPrediction(
                description="Easy-to-erase artifacts (Security 4688) present if attacker missed them",
                expected_status=ArtifactStatus.PRESENT,
                applies_to=("process_execution", "security_event_4688"),
                discriminative_power=0.4,
            ),
        ),
        evidence_pivots=(
            EvidencePivot(
                description="Prefetch/Amcache/Shimcache presence for same process",
                target=("process_execution", "security_event_4688"),
                hypothesis_impact={
                    "selective_deletion": {ArtifactStatus.CONFIRMED_ABSENT: "favors", ArtifactStatus.PRESENT: "disfavors"},
                    "benign_loss": {ArtifactStatus.CONFIRMED_ABSENT: "neutral", ArtifactStatus.PRESENT: "favors"},
                },
            ),
        ),
        explained_observations=(
            ("process_execution", "security_event_4688", ArtifactStatus.CONFIRMED_ABSENT),
            ("file_change", "ntfs_usn_change_journal", ArtifactStatus.CONFIRMED_ABSENT),
        ),
    )


def sensor_failure_hypothesis() -> Hypothesis:
    """Collection/parser failure: sensor didn't capture or parser missed events."""
    h = Hypothesis.create(
        HypothesisType.SENSOR_FAILURE,
        "Sensor/Parser Failure",
        "The collection system failed to capture events, or the parser failed "
        "to extract them. This includes agent crashes, buffer overflows, "
        "parser version mismatches, or format changes.",
        hypothesis_id="sensor_failure",
    )
    return replace(h,
        assumptions=(
            HypothesisAssumption(
                name="collector_uptime",
                description="Collection agent was running continuously",
                falsifiable_by="Collector logs show gaps or restarts",
                confidence=0.7,
            ),
            HypothesisAssumption(
                name="parser_compatibility",
                description="Parser version matches event log format",
                falsifiable_by="Parser version and OS build are compatible; test parse succeeds",
                confidence=0.8,
            ),
            HypothesisAssumption(
                name="no_buffer_overflow",
                description="Event log buffer did not overflow",
                falsifiable_by="Event log shows no 'Event log was cleared' or overflow events",
                confidence=0.6,
            ),
        ),
        predictions=(
            DiscriminatingPrediction(
                description="If parser failed, all events of that type absent",
                expected_status=ArtifactStatus.UNKNOWN,
                applies_to=("any", "any"),
                discriminative_power=0.5,
                falsifies_if=ArtifactStatus.CONFIRMED_ABSENT,
            ),
        ),
        evidence_pivots=(
            EvidencePivot(
                description="Collector/parser logs and version",
                target=("any", "any"),
                hypothesis_impact={
                    "sensor_failure": {ArtifactStatus.UNKNOWN: "favors"},
                    "benign_loss": {ArtifactStatus.UNKNOWN: "neutral"},
                },
            ),
        ),
        explained_observations=(
            ("process_execution", "security_event_4688", ArtifactStatus.UNKNOWN),
        ),
    )


def configuration_gap_hypothesis() -> Hypothesis:
    """Audit policy not enabled or misconfigured."""
    h = Hypothesis.create(
        HypothesisType.CONFIGURATION_GAP,
        "Configuration Gap",
        "Required audit policy subcategories were not enabled, or were "
        "enabled but with insufficient scope (e.g., failure auditing only, "
        "not success). Events were never generated, not deleted.",
        hypothesis_id="configuration_gap",
    )
    return replace(h,
        assumptions=(
            HypothesisAssumption(
                name="audit_policy_scope",
                description="Audit policy was configured but with wrong scope",
                falsifiable_by="AuditPol shows success auditing enabled for required subcategories",
                confidence=0.8,
            ),
            HypothesisAssumption(
                name="gpo_consistency",
                description="GPO applied consistently across interval",
                falsifiable_by="GPO history shows no changes during interval",
                confidence=0.6,
            ),
        ),
        predictions=(
            DiscriminatingPrediction(
                description="If success auditing disabled, all success events absent",
                expected_status=ArtifactStatus.OUT_OF_SCOPE,  # or UNKNOWN with reason
                applies_to=("permitted_network_connection", "security_event_5156"),
                discriminative_power=0.7,
                falsifies_if=ArtifactStatus.PRESENT,
            ),
        ),
        evidence_pivots=(
            EvidencePivot(
                description="AuditPol / GPO for success auditing subcategories",
                target=("permitted_network_connection", "security_event_5156"),
                hypothesis_impact={
                    "configuration_gap": {ArtifactStatus.UNKNOWN: "favors", ArtifactStatus.PRESENT: "disfavors"},
                    "benign_loss": {ArtifactStatus.UNKNOWN: "neutral"},
                },
            ),
        ),
        explained_observations=(
            ("permitted_network_connection", "security_event_5156", ArtifactStatus.UNKNOWN),
        ),
    )


def non_applicable_hypothesis() -> Hypothesis:
    """Artifact doesn't apply to this platform/build/configuration."""
    h = Hypothesis.create(
        HypothesisType.NON_APPLICABLE,
        "Non-Applicable",
        "The artifact type is not generated on this platform version, "
        "edition, or configuration. E.g., USN journal on non-NTFS volume, "
        "or event ID not implemented in this Windows build.",
        hypothesis_id="non_applicable",
    )
    return replace(h,
        assumptions=(
            HypothesisAssumption(
                name="platform_mismatch",
                description="OS build/edition doesn't generate this artifact",
                falsifiable_by="Microsoft documentation confirms artifact for this build",
                confidence=0.7,
            ),
        ),
        predictions=(
            DiscriminatingPrediction(
                description="Artifact never generated on this platform",
                expected_status=ArtifactStatus.OUT_OF_SCOPE,
                applies_to=("any", "any"),
                discriminative_power=0.9,
                falsifies_if=ArtifactStatus.PRESENT,
            ),
        ),
        evidence_pivots=(
            EvidencePivot(
                description="Microsoft documentation for this OS build",
                target=("any", "any"),
                hypothesis_impact={
                    "non_applicable": {ArtifactStatus.OUT_OF_SCOPE: "favors", ArtifactStatus.PRESENT: "disfavors"},
                    "benign_loss": {ArtifactStatus.OUT_OF_SCOPE: "disfavors"},
                },
            ),
        ),
        explained_observations=(
            ("file_change", "ntfs_usn_change_journal", ArtifactStatus.OUT_OF_SCOPE),
        ),
    )


# ---------------------------------------------------------------------------
# Registry of all built-in hypotheses
# ---------------------------------------------------------------------------

BUILTIN_HYPOTHESES: Tuple[Hypothesis, ...] = (
    benign_loss_hypothesis(),
    selective_deletion_hypothesis(),
    sensor_failure_hypothesis(),
    configuration_gap_hypothesis(),
    non_applicable_hypothesis(),
)

HYPOTHESIS_REGISTRY: Dict[str, Hypothesis] = {
    h.hypothesis_id: h for h in BUILTIN_HYPOTHESES
}


def get_hypothesis(hypothesis_id: str) -> Optional[Hypothesis]:
    return HYPOTHESIS_REGISTRY.get(hypothesis_id)


def list_hypotheses() -> List[Hypothesis]:
    return list(BUILTIN_HYPOTHESES)


# ---------------------------------------------------------------------------
# Rival analysis result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HypothesisEvaluation:
    """Evaluation of one hypothesis against observations."""
    hypothesis: Hypothesis
    # Per (action, artifact_type): favors / disfavors / neutral / untested
    observation_support: Dict[Tuple[str, str], str] = field(default_factory=dict)
    # Assumptions that were validated/falsified
    # NOTE: Currently always "untested" - assumption validation requires external evidence
    assumption_status: Dict[str, str] = field(default_factory=dict)  # validated|falsified|untested
    # Evidence pivots and their current status
    pivot_status: Dict[str, str] = field(default_factory=dict)  # resolved|pending
    # Overall support level
    support_level: str = "untested"  # untested|weak|moderate|strong|falsified
    # Narrative summary
    summary: str = ""


@dataclass(frozen=True)
class RivalAnalysisResult:
    """Complete rival hypothesis analysis for one case."""
    analysis_id: str
    created_at: str
    source_analysis: SilenceAnalysisResult
    # All hypotheses evaluated
    evaluations: Tuple[HypothesisEvaluation, ...]
    # Evidence pivots that would most discriminate
    top_pivots: Tuple[EvidencePivot, ...]
    # Discriminatory power summary
    discriminatory_summary: str
    # Can any hypothesis be discriminated?
    any_discriminated: bool = False

    @classmethod
    def create(cls, source_analysis: SilenceAnalysisResult) -> "RivalAnalysisResult":
        return cls(
            analysis_id=str(uuid4())[:8],
            created_at=datetime.now(timezone.utc).isoformat(),
            source_analysis=source_analysis,
            evaluations=(),
            top_pivots=(),
            discriminatory_summary="",
        )