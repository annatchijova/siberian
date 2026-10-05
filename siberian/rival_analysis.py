"""
siberian/rival_analysis.py
==========================
Engine for evaluating rival hypotheses against SIBERIAN observations.

Implements the comparison logic: given a SilenceAnalysisResult and a set
of hypotheses, evaluates each hypothesis against the observations,
identifies which observations favor/disfavor each hypothesis, and
identifies evidence pivots that would discriminate between them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from .adversarial_silence import (
    ArtifactStatus,
    ObservationReason,
    SilenceAnalysisResult,
    SilenceRecord,
)
from .hypotheses import (
    DiscriminatingPrediction,
    EvidencePivot,
    Hypothesis,
    HypothesisEvaluation,
    HypothesisType,
    RivalAnalysisResult,
    get_hypothesis,
    list_hypotheses,
)


# ---------------------------------------------------------------------------
# Evaluation logic
# ---------------------------------------------------------------------------

def evaluate_hypothesis(
    hypothesis: Hypothesis,
    result: SilenceAnalysisResult,
) -> "HypothesisEvaluation":
    """
    Evaluate a single hypothesis against the analysis result.
    
    Returns a HypothesisEvaluation with per-observation support,
    assumption status, and overall support level.
    """
    # Build observation map for quick lookup
    obs_map: Dict[Tuple[str, str], SilenceRecord] = {
        (r.action, r.expected_artifact.artifact_type): r
        for r in result.records
    }

    observation_support: Dict[Tuple[str, str], str] = {}
    assumption_status: Dict[str, str] = {}
    pivot_status: Dict[str, str] = {}

    # Evaluate predictions against actual observations
    for prediction in hypothesis.predictions:
        action, artifact_type = prediction.applies_to
        record = obs_map.get((action, artifact_type))

        if record is None:
            # This artifact wasn't in the analysis — untested
            observation_support[(action, artifact_type)] = "untested"
        else:
            actual_status = record.observation.status
            if actual_status == prediction.expected_status:
                observation_support[(action, artifact_type)] = "favors"
            elif prediction.falsifies_if is not None and actual_status == prediction.falsifies_if:
                observation_support[(action, artifact_type)] = "disfavors"
            elif actual_status == ArtifactStatus.CONFIRMED_ABSENT and prediction.expected_status == ArtifactStatus.PRESENT:
                observation_support[(action, artifact_type)] = "disfavors"
            elif actual_status == ArtifactStatus.PRESENT and prediction.expected_status == ArtifactStatus.UNKNOWN:
                observation_support[(action, artifact_type)] = "disfavors"
            elif actual_status == ArtifactStatus.OUT_OF_SCOPE and prediction.expected_status in (ArtifactStatus.UNKNOWN, ArtifactStatus.CONFIRMED_ABSENT):
                observation_support[(action, artifact_type)] = "disfavors"
            else:
                observation_support[(action, artifact_type)] = "neutral"

    # Evaluate assumptions (untested unless we have evidence)
    for assumption in hypothesis.assumptions:
        # In a full implementation, we'd check evidence against the assumption
        # For now, mark as untested
        assumption_status[assumption.name] = "untested"

    # Evaluate evidence pivots
    for pivot in hypothesis.evidence_pivots:
        action, artifact_type = pivot.target
        record = obs_map.get((action, artifact_type))
        if record is not None and record.observation.status != ArtifactStatus.UNKNOWN:
            pivot_status[f"{action}/{artifact_type}"] = "resolved"
        else:
            pivot_status[f"{action}/{artifact_type}"] = "pending"

    # Determine overall support level - principled calculation
    # Weight predictions by discriminative_power
    weighted_favors = sum(
        p.discriminative_power
        for p in hypothesis.predictions
        if p.applies_to in observation_support and observation_support[p.applies_to] == "favors"
    )
    weighted_disfavors = sum(
        p.discriminative_power
        for p in hypothesis.predictions
        if p.applies_to in observation_support and observation_support[p.applies_to] == "disfavors"
    )
    weighted_neutral = sum(
        p.discriminative_power
        for p in hypothesis.predictions
        if p.applies_to in observation_support and observation_support[p.applies_to] == "neutral"
    )
    weighted_untested = sum(
        p.discriminative_power
        for p in hypothesis.predictions
        if p.applies_to in observation_support and observation_support[p.applies_to] == "untested"
    )

    total_weight = weighted_favors + weighted_disfavors + weighted_neutral + weighted_untested

    if total_weight == 0:
        support_level = "untested"
    elif weighted_disfavors > weighted_favors:
        support_level = "falsified"
    elif weighted_favors == 0:
        support_level = "weak"
    elif weighted_favors >= weighted_disfavors * 2 and weighted_favors / total_weight > 0.5:
        support_level = "strong"
    elif weighted_favors > weighted_disfavors and weighted_favors / total_weight > 0.3:
        support_level = "moderate"
    else:
        support_level = "weak"

    # Build summary
    summary_parts = []
    if support_level == "falsified":
        summary_parts.append("Hypothesis falsified by observations")
    elif support_level == "strong":
        summary_parts.append(f"Strong support: {weighted_favors:.1f} weighted favors, {weighted_disfavors:.1f} disfavors")
    elif support_level == "moderate":
        summary_parts.append(f"Moderate support: {weighted_favors:.1f} weighted favors, {weighted_disfavors:.1f} disfavors")
    elif support_level == "weak":
        summary_parts.append(f"Weak support: {weighted_favors:.1f} weighted favors, {weighted_disfavors:.1f} disfavors")
    else:
        summary_parts.append("Insufficient evidence to evaluate")

    if weighted_untested > 0:
        summary_parts.append(f"{weighted_untested:.1f} weighted predictions untested")

    summary = "; ".join(summary_parts)

    return HypothesisEvaluation(
        hypothesis=hypothesis,
        observation_support=observation_support,
        assumption_status=assumption_status,
        pivot_status=pivot_status,
        support_level=support_level,
        summary=summary,
    )


def analyze_rivals(
    result: "SilenceAnalysisResult",
    hypotheses: Optional[List[Hypothesis]] = None,
) -> RivalAnalysisResult:
    """
    Evaluate all hypotheses against the analysis result.
    
    Args:
        result: The SilenceAnalysisResult from adversarial_silence.analyze()
        hypotheses: List of hypotheses to evaluate (defaults to all built-in)
    
    Returns:
        RivalAnalysisResult with evaluations and discriminatory analysis.
    """
    if hypotheses is None:
        hypotheses = list_hypotheses()

    evaluations = []
    for h in hypotheses:
        eval_result = evaluate_hypothesis(h, result)
        evaluations.append(eval_result)

    # Find top discriminating pivots
    all_pivots: List[EvidencePivot] = []
    for h in hypotheses:
        all_pivots.extend(h.evidence_pivots)

    # Rank pivots by how many hypotheses they discriminate
    def pivot_discriminatory_power(pivot: EvidencePivot) -> int:
        # Count hypotheses that would be affected differently by different outcomes
        impacts = pivot.hypothesis_impact
        if not impacts:
            return 0
        # Count unique impact patterns across hypotheses
        patterns = set()
        for h_id, impact_map in impacts.items():
            pattern = tuple(sorted((s, v) for s, v in impact_map.items()))
            patterns.add(pattern)
        return len(patterns)

    ranked_pivots = sorted(all_pivots, key=pivot_discriminatory_power, reverse=True)
    top_pivots = tuple(ranked_pivots[:10])  # Top 10

    # Determine if any hypothesis is discriminated
    any_discriminated = any(e.support_level in ("moderate", "strong", "falsified") for e in evaluations)

    # Build discriminatory summary
    support_levels = [e.support_level for e in evaluations]
    if "falsified" in support_levels:
        discriminatory_summary = "At least one hypothesis falsified; remaining hypotheses should be re-evaluated."
    elif "strong" in support_levels:
        discriminatory_summary = "One or more hypotheses strongly supported; check pivots to discriminate further."
    elif "moderate" in support_levels:
        discriminatory_summary = "Moderate support for some hypotheses; additional evidence needed for discrimination."
    elif "weak" in support_levels:
        discriminatory_summary = "Weak support across hypotheses; more evidence needed."
    else:
        discriminatory_summary = "All hypotheses untested; no discriminating evidence available."

    return RivalAnalysisResult(
        analysis_id=str(uuid4())[:8],
        created_at=datetime.now(timezone.utc).isoformat(),
        source_analysis=result,
        evaluations=tuple(evaluations),
        top_pivots=top_pivots,
        discriminatory_summary=discriminatory_summary,
        any_discriminated=any_discriminated,
    )


def format_rival_report(result: RivalAnalysisResult) -> str:
    """Format a human-readable rival analysis report."""
    lines = [
        "SIBERIAN Rival Hypothesis Analysis",
        "=" * 60,
        f"Analysis ID: {result.analysis_id}",
        f"Timestamp: {result.created_at}",
        f"Case scope: {result.source_analysis.context.scope if result.source_analysis else 'N/A'}",
        f"Interval: {result.source_analysis.context.interval_start if result.source_analysis else 'N/A'} to {result.source_analysis.context.interval_end if result.source_analysis else 'N/A'}",
        "",
        "HYPOTHESIS EVALUATIONS",
        "-" * 60,
    ]

    for eval_result in result.evaluations:
        h = eval_result.hypothesis
        lines.extend([
            "",
            f"[{h.hypothesis_id}] {h.name} ({h.hypothesis_type.value})",
            f"  Version: {h.version}",
            f"  Support: {eval_result.support_level.upper()}",
            f"  Summary: {eval_result.summary}",
            "  Observation Support:",
        ])
        for (action, artifact_type), support in eval_result.observation_support.items():
            lines.append(f"    {action}/{artifact_type}: {support}")

        if eval_result.assumption_status:
            lines.append("  Assumptions:")
            for name, status in eval_result.assumption_status.items():
                lines.append(f"    {name}: {status}")

        if eval_result.pivot_status:
            lines.append("  Evidence Pivots:")
            for pivot, status in eval_result.pivot_status.items():
                lines.append(f"    {pivot}: {status}")

    lines.extend([
        "",
        "TOP DISCRIMINATING PIVOTS",
        "-" * 60,
    ])

    for i, pivot in enumerate(result.top_pivots, 1):
        lines.extend([
            f"{i}. {pivot.description}",
            f"   Target: {pivot.target[0]}/{pivot.target[1]}",
            f"   Current: {pivot.current_status.value if pivot.current_status else 'unknown'} ({pivot.current_reason.value if pivot.current_reason else 'n/a'})",
            "   Impact by hypothesis:",
        ])
        for h_id, impacts in pivot.hypothesis_impact.items():
            lines.append(f"     {h_id}: {dict(impacts)}")

    lines.extend([
        "",
        "DISCRIMINATORY SUMMARY",
        "-" * 60,
        result.discriminatory_summary,
        "",
        f"Any hypothesis discriminated: {'YES' if result.any_discriminated else 'NO'}",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Counterfactual scenario generation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CounterfactualScenario:
    """A counterfactual: what would observations look like if hypothesis were true."""
    hypothesis_id: str
    # Expected status for each (action, artifact_type)
    expected_observations: Dict[Tuple[str, str], ArtifactStatus]
    # Which pivots would resolve
    resolved_pivots: Tuple[str, ...]
    # Narrative description
    description: str


def generate_counterfactuals(
    hypotheses: List[Hypothesis],
    result: "SilenceAnalysisResult",
) -> List[CounterfactualScenario]:
    """Generate counterfactual scenarios for each hypothesis.

    Only includes artifacts for which the hypothesis makes an explicit prediction.
    Artifacts without explicit predictions are omitted from the counterfactual.
    """
    obs_map: Dict[Tuple[str, str], SilenceRecord] = {
        (r.action, r.expected_artifact.artifact_type): r
        for r in result.records
    }

    scenarios = []
    for h in hypotheses:
        expected = {}
        for action, artifact_type in obs_map.keys():
            # Find prediction for this artifact
            pred = next((p for p in h.predictions if p.applies_to == (action, artifact_type)), None)
            if pred:
                expected[(action, artifact_type)] = pred.expected_status
            # No default: hypothesis doesn't make a prediction for this artifact
            # Omit from counterfactual — silence is not a prediction

        resolved = tuple(
            f"{p.target[0]}/{p.target[1]}"
            for p in h.evidence_pivots
            if f"{p.target[0]}/{p.target[1]}" in expected
        )

        scenarios.append(CounterfactualScenario(
            hypothesis_id=h.hypothesis_id,
            expected_observations=expected,
            resolved_pivots=resolved,
            description=f"If {h.name} is true, we would expect: " +
                        ", ".join(f"{a}/{at}={s.value}" for (a, at), s in expected.items()),
        ))

    return scenarios