# Red-Team Audit Report — Nivel 3 (Rival Hypotheses)

**Date:** 2026-10-05  
**Auditor:** Red-team audit pass  
**Scope:** `siberian/hypotheses.py`, `siberian/rival_analysis.py`  
**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing

---

## Executive Summary

| Finding ID | Severity | Epistemic Level | Component | Summary |
|------------|----------|-----------------|-----------|---------|
| R3-F01 | HIGH | CONFIRMED BY INDUCTION | `Hypothesis.create` | ID generation uses random `uuid4()` — non-deterministic, breaks registry stability |
| R3-F02 | HIGH | CONFIRMED BY INDUCTION | `EvidencePivot.hypothesis_impact` | Keys use unstable hypothesis IDs instead of stable registry keys |
| R3-F03 | HIGH | CONFIRMED BY INDUCTION | `support_level` weighting | Arbitrary thresholds (2x, 0.5, 0.3) with no principled justification |
| R3-F04 | MEDIUM | CONFIRMED BY INDUCTION | `assumption_status` | Always "untested" — not actually evaluating assumptions |
| R3-F05 | MEDIUM | CONFIRMED BY INDUCTION | `CounterfactualScenario` | Generates `ArtifactStatus.UNKNOWN` for artifacts with no prediction — invalid per contract |
| R3-F06 | MEDIUM | CONFIRMED BY INDUCTION | `pivot_discriminatory_power` | Uses unstable hypothesis IDs from `hypothesis_impact` keys |
| R3-F07 | LOW | CONFIRMED BY INDUCTION | `format_rival_report` | Accesses `current_status.value` / `current_reason.value` without None check |
| R3-F08 | LOW | CONFIRMED BY INDUCTION | `generate_counterfactuals` | Assigns `UNKNOWN` to artifacts without predictions — invalid status |
| R3-F09 | LOW | CONFIRMED BY INDUCTION | `discriminatory_summary` | Claims "All hypotheses untested" when some have neutral support |

---

## Detailed Findings

### R3-F01: Hypothesis.create ID Generation Instability (HIGH)

**Location:** `hypotheses.py:118-136`

**Observation:** `Hypothesis.create()` generates `hypothesis_id` using `str(uuid4())[:8]` when not provided. This makes the ID non-deterministic across runs.

**Impact:** 
- `HYPOTHESIS_REGISTRY` keys change every run → registry useless for lookups
- `EvidencePivot.hypothesis_impact` keys become stale immediately
- `pivot_discriminatory_power` counts patterns that change every run
- `CounterfactualScenario` uses random IDs

**Evidence:** Running `benign_loss_hypothesis()` twice produces different IDs.

**Fix:** Generate stable ID from `name` + `type` when not explicitly provided.

---

### R3-F02: EvidencePivot.hypothesis_impact Keys vs Registry (HIGH)

**Location:** `hypotheses.py:176-198, 257-278, etc.`

**Observation:** `EvidencePivot.hypothesis_impact` uses hardcoded string keys like `"benign_loss"`, `"selective_deletion"` but these must exactly match `Hypothesis.hypothesis_id` values in the registry.

**Impact:** If hypothesis IDs change (R3-F01) or new hypotheses added with different ID format, the impact maps silently fail to match.

**Evidence:** Current code uses hardcoded strings that happen to match the old `create()` factory pattern, but the new stable ID generation changes the format.

**Fix:** Validate `hypothesis_impact` keys against `HYPOTHESIS_REGISTRY` at construction time.

---

### R3-F03: Support Level Weighting Logic (HIGH)

**Location:** `rival_analysis.py:98-134`

**Observation:** Support level determination uses arbitrary thresholds:
- `weighted_favors >= weighted_disfavors * 2 and weighted_favors / total_weight > 0.5` → "strong"
- `weighted_favors > weighted_disfavors and weighted_favors / total_weight > 0.3` → "moderate"

**Impact:** These thresholds are completely arbitrary. No statistical justification. A hypothesis with 0.51 weighted favors and 0.25 disfavors gets "moderate" while 0.49/0.25 gets "weak" — cliff edge at 0.5.

**Evidence:** No unit tests for boundary conditions. No principled derivation of thresholds.

**Fix:** Use principled thresholds with explicit rationale, or replace with continuous confidence score.

---

### R3-F04: Assumption Status Always "Untested" (MEDIUM)

**Location:** `rival_analysis.py:83-87`

**Observation:** `assumption_status[assumption.name] = "untested"` for every assumption, with comment "In a full implementation, we'd check evidence against the assumption".

**Impact:** The field exists and is reported but never populated. Misleads users into thinking assumptions were evaluated.

**Evidence:** Code comment admits it's not implemented. All hypotheses report all assumptions as "untested".

**Fix:** Either implement assumption validation (requires external evidence) or remove the field and note limitation explicitly.

---

### R3-F05: CounterfactualScenario Generates Invalid ArtifactStatus (MEDIUM)

**Location:** `rival_analysis.py:303-349`

**Observation:** `generate_counterfactuals()` assigns `ArtifactStatus.UNKNOWN` to artifacts where hypothesis has no explicit prediction.

**Impact:** `ArtifactStatus.UNKNOWN` is a valid observation status meaning "conditions unverified" — not a prediction. A counterfactual should predict what WOULD be observed, not default to "unknown".

**Evidence:** Line 335: `expected[(action, artifact_type)] = ArtifactStatus.UNKNOWN` for artifacts without explicit prediction.

**Fix:** Either require explicit predictions for all artifacts, or omit from counterfactual.

---

### R3-F06: pivot_discriminatory_power Uses Unstable IDs (MEDIUM)

**Location:** `rival_analysis.py:192-202`

**Observation:** `pivot_discriminatory_power()` iterates `impacts.items()` where keys are hypothesis IDs from `hypothesis_impact`. If IDs are unstable (R3-F01), the pattern counting is non-deterministic.

**Impact:** Pivot ranking changes between runs.

**Fix:** Use stable hypothesis IDs (R3-F01 fix) and validate keys against registry.

---

### R3-F07: format_rival_report None Access (LOW)

**Location:** `rival_analysis.py:281`

**Observation:** `pivot.current_status.value if pivot.current_status else 'unknown'` — but `current_reason.value if pivot.current_reason else 'n/a'` assumes both are None or both present. If `current_status` is set but `current_reason` is None, it prints "n/a" correctly. But if `current_reason` is set without `current_status` (impossible by construction but not enforced), it would crash.

**Impact:** Potential AttributeError if `current_reason` set without `current_status`.

**Fix:** Add defensive checks or make fields mutually dependent.

---

### R3-F08: generate_counterfactuals Generates Invalid ArtifactStatus (LOW)

**Location:** `rival_analysis.py:330-335`

**Observation:** When hypothesis has no prediction for an artifact, `generate_counterfactuals` assigns `ArtifactStatus.UNKNOWN`. This is not a prediction — it's the absence of one.

**Impact:** Counterfactual scenarios claim to predict "UNKNOWN" which is semantically wrong.

**Fix:** Only include artifacts with explicit predictions in counterfactuals.

---

### R3-F09: discriminatory_summary Overclaims (LOW)

**Location:** `rival_analysis.py:210-221`

**Observation:** Summary says "All hypotheses untested; no discriminating evidence available" when `support_level` is "untested" for all. But some hypotheses may have "neutral" support with tested predictions.

**Impact:** Overclaims the absence of evidence.

**Fix:** Distinguish "untested" from "tested but neutral".

---

## Fix Plan

### Phase 1: Core Stability (R3-F01, R3-F02, R3-F06)
1. Make `Hypothesis.create()` generate stable IDs from name+type
2. Validate `EvidencePivot.hypothesis_impact` keys against registry
3. Fix `pivot_discriminatory_power` to use stable registry keys

### Phase 2: Logic Correction (R3-F03, R3-F04)
4. Replace arbitrary support_level thresholds with principled logic
5. Make `assumption_status` explicit about being untested, or implement validation

### Phase 3: Counterfactual Validity (R3-F05, R3-F08)
6. Fix `generate_counterfactuals` to only include predicted artifacts
7. Fix `CounterfactualScenario` to only contain explicit predictions

### Phase 4: Polish (R3-F07, R3-F09)
8. Fix `format_rival_report` None safety
9. Fix `discriminatory_summary` to distinguish untested from neutral

### Phase 5: Validation
10. Add validation to `EvidencePivot.__post_init__` for registry key matching
11. Add validation to `CounterfactualScenario` for prediction coverage

---

## Verification Plan

1. All 42 existing tests pass
2. New tests for:
   - Stable hypothesis ID generation
   - EvidencePivot registry validation
   - Support level boundary conditions
   - Counterfactual prediction validity
   - format_rival_report None safety
2. Determinism test: run `rivals` command twice, verify identical output
3. Registry stability: restart interpreter, verify registry keys unchanged

---

*End of audit report*