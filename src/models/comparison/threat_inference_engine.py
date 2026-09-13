"""
NexThreat Phase 4.5 — Deterministic Tri-Model Threat Inference Engine.

Implements:
1. Deterministic mapping function T: {0, 1}^3 -> {S0 .. S7}
2. Strict decoupled availability from threat-state eligibility:
   - Ineligible windows receive threat_state = null, is_eligible_for_threat_state = false
   - Zero 9th state (no S8, no LSTM_UNAVAILABLE state)
3. Dynamic Sample Conservation (Check K):
   - Scope A: sum(Count(S_i)) == 45
   - Scope B: sum(Count(S_i)) == N_eligible and N_eligible + N_ineligible == N_master
4. Eligibility-Contiguity Rule:
   - State transitions and dwell times are computed exclusively across contiguous sequences of eligible windows.
   - An ineligible window breaks transition and dwell continuity; zero transitions bridge across gaps.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

from src.models.comparison.config import (
    CANONICAL_THREAT_STATES,
    INPUT_TUPLE_TO_STATE,
    INPUT_TUPLE_TO_CODE,
    ALL_CANONICAL_STATE_NAMES,
    ALL_CANONICAL_STATE_CODES,
)


def map_tuple_to_state(b_ae: int, b_xgb: int, b_lstm: int) -> Dict[str, Any]:
    """
    Map complete binary triplet (b_ae, b_xgb, b_lstm) to canonical state.
    """
    tuple_key = (int(b_ae), int(b_xgb), int(b_lstm))
    if tuple_key not in INPUT_TUPLE_TO_STATE:
        raise ValueError(f"Invalid binary decision tuple: {tuple_key}. Expected values in {{0, 1}}^3.")

    state_name = INPUT_TUPLE_TO_STATE[tuple_key]
    state_code = INPUT_TUPLE_TO_CODE[tuple_key]
    meta = CANONICAL_THREAT_STATES[state_code]

    return {
        "code": state_code,
        "name": state_name,
        "priority": meta["priority"],
        "triage_tier": meta["triage_tier"],
        "meaning": meta["meaning"],
    }


def compute_state_distribution(
    states: List[Optional[str]],
    expected_eligible_count: int,
) -> Tuple[Dict[str, int], Dict[str, float], bool]:
    """
    Compute count and percentage distribution over canonical states S0..S7 for eligible windows.
    Verifies that sum(Count(S_i)) == expected_eligible_count.
    """
    counts = {name: 0 for name in ALL_CANONICAL_STATE_NAMES}
    eligible_count = 0

    for st in states:
        if st is not None:
            if st in counts:
                counts[st] += 1
                eligible_count += 1
            else:
                raise ValueError(f"Encountered non-canonical threat state: {st}")

    percentages = {}
    for name, cnt in counts.items():
        percentages[name] = float(cnt / eligible_count) if eligible_count > 0 else 0.0

    conservation_verified = bool(eligible_count == expected_eligible_count)
    return counts, percentages, conservation_verified


def compute_empirical_transition_matrix(
    master_df: pd.DataFrame,
) -> Dict[str, Any]:
    """
    Compute 8x8 empirical transition probability matrix P(S_j(t) | S_i(t-1))
    strictly enforcing the Eligibility-Contiguity Rule:
    - Transitions are evaluated strictly across contiguous sequences of eligible windows.
    - If window t is ineligible, any active sequence terminates; no transition is inferred across gaps.
    """
    matrix_counts = {src: {dst: 0 for dst in ALL_CANONICAL_STATE_NAMES} for src in ALL_CANONICAL_STATE_NAMES}
    total_transitions_evaluated = 0

    n = len(master_df)
    for idx in range(1, n):
        prev_eligible = bool(master_df.at[idx - 1, "is_eligible_for_threat_state"])
        curr_eligible = bool(master_df.at[idx, "is_eligible_for_threat_state"])

        # Both windows must be eligible to record an empirical transition
        if prev_eligible and curr_eligible:
            src_state = master_df.at[idx - 1, "threat_state"]
            dst_state = master_df.at[idx, "threat_state"]
            if src_state in matrix_counts and dst_state in matrix_counts[src_state]:
                matrix_counts[src_state][dst_state] += 1
                total_transitions_evaluated += 1

    # Normalize counts to transition probabilities
    probability_matrix = {}
    for src in ALL_CANONICAL_STATE_NAMES:
        row_sum = sum(matrix_counts[src].values())
        probability_matrix[src] = {}
        for dst in ALL_CANONICAL_STATE_NAMES:
            cnt = matrix_counts[src][dst]
            prob = float(cnt / row_sum) if row_sum > 0 else 0.0
            probability_matrix[src][dst] = round(prob, 6)

    return {
        "transition_counts": matrix_counts,
        "transition_probabilities": probability_matrix,
        "total_transitions_evaluated": total_transitions_evaluated,
        "contiguity_rule_enforced": True,
    }


def compute_dwell_time_statistics(
    master_df: pd.DataFrame,
) -> Dict[str, Any]:
    """
    Compute dwell-time statistics (mean and max consecutive window runs per state)
    strictly enforcing the Eligibility-Contiguity Rule:
    - An ineligible window terminates the current dwell run.
    """
    dwell_runs: Dict[str, List[int]] = {name: [] for name in ALL_CANONICAL_STATE_NAMES}

    current_state: Optional[str] = None
    current_run_len = 0

    for idx, row in master_df.iterrows():
        is_eligible = bool(row["is_eligible_for_threat_state"])
        st = row["threat_state"]

        if is_eligible and st in dwell_runs:
            if st == current_state:
                current_run_len += 1
            else:
                if current_state is not None and current_run_len > 0:
                    dwell_runs[current_state].append(current_run_len)
                current_state = st
                current_run_len = 1
        else:
            # Ineligible window terminates active run immediately
            if current_state is not None and current_run_len > 0:
                dwell_runs[current_state].append(current_run_len)
            current_state = None
            current_run_len = 0

    # Record final run if active
    if current_state is not None and current_run_len > 0:
        dwell_runs[current_state].append(current_run_len)

    dwell_stats = {}
    for name, runs in dwell_runs.items():
        if runs:
            dwell_stats[name] = {
                "total_occurrences": int(sum(runs)),
                "run_count": len(runs),
                "mean_dwell_minutes": round(float(np.mean(runs)), 2),
                "median_dwell_minutes": float(np.median(runs)),
                "max_dwell_minutes": int(np.max(runs)),
            }
        else:
            dwell_stats[name] = {
                "total_occurrences": 0,
                "run_count": 0,
                "mean_dwell_minutes": 0.0,
                "median_dwell_minutes": 0.0,
                "max_dwell_minutes": 0,
            }

    return dwell_stats


def evaluate_threat_matrix(synchronized_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate the authoritative tri_model_threat_matrix deliverable dictionary.
    """
    master_df: pd.DataFrame = synchronized_data["master_df"]
    scope_a_df: pd.DataFrame = synchronized_data["scope_a_df"]

    n_master = synchronized_data["n_master"]
    n_eligible = synchronized_data["n_eligible"]
    n_ineligible = synchronized_data["n_ineligible"]

    # 1. Scope A Evaluation (N=45)
    sa_states = scope_a_df["threat_state"].tolist()
    sa_counts, sa_pcts, sa_conservation = compute_state_distribution(sa_states, len(scope_a_df))

    # 2. Scope B Evaluation (N_master = N_eligible + N_ineligible)
    sb_eligible_df = master_df[master_df["is_eligible_for_threat_state"] == True]
    sb_states = sb_eligible_df["threat_state"].tolist()
    sb_counts, sb_pcts, sb_conservation = compute_state_distribution(sb_states, n_eligible)

    # Master-timeline accounting conservation: sum(Count(S_i)) + N_ineligible == N_master
    total_classified_eligible = sum(sb_counts.values())
    master_conservation = bool(
        (total_classified_eligible == n_eligible)
        and (n_eligible + n_ineligible == n_master)
    )

    # Ineligibility breakdown (authoritative partition where sum equals n_ineligible)
    ineligible_df = master_df[master_df["is_eligible_for_threat_state"] == False]
    reason_counts = {str(k): int(v) for k, v in ineligible_df["ineligibility_reason"].value_counts().items()}

    # 3. Transitions & Dwell Times (strictly adhering to Eligibility-Contiguity Rule)
    transition_data = compute_empirical_transition_matrix(master_df)
    dwell_stats = compute_dwell_time_statistics(master_df)

    return {
        "phase": "4.5",
        "report_name": "Tri-Model Threat Inference Matrix Report",
        "timestamp": pd.Timestamp.now().isoformat(),
        "scope_a_synchronized_test_intersection": {
            "sample_count": len(scope_a_df),
            "state_distribution": sb_counts if False else sa_counts,
            "state_percentages": sa_pcts,
            "conservation_verified": sa_conservation,
            "sample_conservation_equation": f"sum(Count(S_i)) == {len(scope_a_df)}",
        },
        "scope_b_operational_replay": {
            "total_master_timeline_windows": n_master,
            "eligible_windows_count": n_eligible,
            "ineligible_windows_count": n_ineligible,
            "ineligibility_breakdown": reason_counts,
            "state_distribution": sb_counts,
            "state_percentages": sb_pcts,
            "conservation_verified": master_conservation,
            "sample_conservation_equations": {
                "scope_b_eligible_conservation": f"sum(Count(S_i)) == {total_classified_eligible} == N_eligible ({n_eligible})",
                "master_timeline_partition_conservation": f"N_eligible ({n_eligible}) + N_ineligible ({n_ineligible}) == N_master ({n_master})",
            },
        },
        "state_transition_matrix": transition_data["transition_probabilities"],
        "dwell_time_statistics": dwell_stats,
    }
