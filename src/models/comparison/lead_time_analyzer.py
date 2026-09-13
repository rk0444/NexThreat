"""
NexThreat Phase 4.5 — Attack Forecasting Lead-Time Analysis Engine.

Evaluates operational early-warning horizons across all 81 attack campaigns
physically materialized in data/model_inputs/metadata/attack_segments.csv.

Rules:
1. Dynamic iteration over all 81 attack campaign segments.
2. Campaign onset T_onset is global_start_position.
3. Sequence boundaries and midnight day boundaries strictly enforced:
   - Lookback sequences cannot cross day boundaries.
   - Lookbacks within windows 1..10 of a day serialize as "unavailable", never fake 0.
4. Lead time formulation:
   - Delta_t_lead = T_onset - T_first_forecast
   - Traced backward through contiguous run of positive LSTM forecasts leading directly into T_onset.
   - If forecast targeting T_onset is benign (0), campaign is unwarned (Delta_t_lead = 0).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd

from src.models.comparison.config import (
    ATTACK_SEGMENTS_PATH,
    EXPECTED_VERIFICATION_COUNTS,
)


def analyze_lead_time(synchronized_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate early-warning lead time across all 81 attack campaigns in attack_segments.csv.
    """
    master_df: pd.DataFrame = synchronized_data["master_df"]
    n_master = len(master_df)

    # Load ground-truth attack campaigns
    if not ATTACK_SEGMENTS_PATH.is_file():
        raise FileNotFoundError(f"Authoritative attack segments file missing: {ATTACK_SEGMENTS_PATH}")

    campaigns_df = pd.read_csv(ATTACK_SEGMENTS_PATH)
    total_campaigns = len(campaigns_df)

    campaign_evaluations: List[Dict[str, Any]] = []

    pre_warned_count = 0
    unwarned_count = 0
    unavailable_count = 0

    lead_times_numeric: List[int] = []

    dist_1_min = 0
    dist_2_5_min = 0
    dist_6_10_min = 0
    dist_gt_10_min = 0
    dist_unpred_or_unavail = 0

    # Index master_df by global_position for fast lookups (1-indexed)
    pos_to_idx = {pos: idx for idx, pos in enumerate(master_df["global_position"].values)}

    for _, camp in campaigns_df.iterrows():
        seg_id = str(camp["segment_id"])
        day = str(camp["dataset_day"])
        category = str(camp["attack_category"])
        t_onset = int(camp["global_start_position"])
        t_end = int(camp["global_end_position"])
        w_count = int(camp["window_count"])

        # Target window is t_onset. Its forecast was generated at t_onset - 1
        onset_idx = pos_to_idx.get(t_onset)
        if onset_idx is None:
            # Position not in master timeline
            campaign_evaluations.append({
                "segment_id": seg_id,
                "dataset_day": day,
                "attack_category": category,
                "onset_global_position": t_onset,
                "end_global_position": t_end,
                "window_count": w_count,
                "lead_time_minutes": "unavailable",
                "pre_warning_status": "unavailable",
                "reason": "onset_position_not_in_timeline",
            })
            unavailable_count += 1
            dist_unpred_or_unavail += 1
            continue

        # Check LSTM prediction for the onset window
        onset_lstm_pred = master_df.at[onset_idx, "lstm_prediction"]
        onset_eligible = bool(master_df.at[onset_idx, "is_eligible_for_threat_state"])

        if not onset_eligible or onset_lstm_pred == "unavailable":
            # Preceding lookback was unavailable (e.g. day boundary cold start)
            campaign_evaluations.append({
                "segment_id": seg_id,
                "dataset_day": day,
                "attack_category": category,
                "onset_global_position": t_onset,
                "end_global_position": t_end,
                "window_count": w_count,
                "first_forecast_window": None,
                "lead_time_minutes": "unavailable",
                "pre_warning_status": "unavailable",
                "reason": "lookback_cold_start_or_boundary",
            })
            unavailable_count += 1
            dist_unpred_or_unavail += 1

        elif int(onset_lstm_pred) == 0:
            # Forecast targeting onset was benign: campaign was unwarned
            campaign_evaluations.append({
                "segment_id": seg_id,
                "dataset_day": day,
                "attack_category": category,
                "onset_global_position": t_onset,
                "end_global_position": t_end,
                "window_count": w_count,
                "first_forecast_window": None,
                "lead_time_minutes": 0,
                "pre_warning_status": "unwarned",
                "reason": "target_window_forecast_benign",
            })
            unwarned_count += 1
            dist_unpred_or_unavail += 1

        else:
            # Positive forecast targeting t_onset! Pre-warning established!
            # Forecast was formulated at window t_onset - 1 (offset 1 minute)
            # Trace backward to find the earliest consecutive positive forecast
            contiguous_run_length = 1
            earliest_gen_pos = t_onset - 1  # generated at t_onset - 1

            # Check previous target windows (t_onset - 1, t_onset - 2, ...)
            curr_target_pos = t_onset - 1
            while curr_target_pos in pos_to_idx:
                curr_idx = pos_to_idx[curr_target_pos]
                # Verify same day
                if master_df.at[curr_idx, "dataset_day"] != day:
                    break
                # Verify eligible and positive forecast
                if not master_df.at[curr_idx, "is_eligible_for_threat_state"]:
                    break
                if master_df.at[curr_idx, "lstm_prediction"] == "unavailable":
                    break
                if int(master_df.at[curr_idx, "lstm_prediction"]) != 1:
                    break

                # Continuous positive alert run extends backward
                contiguous_run_length += 1
                earliest_gen_pos = curr_target_pos - 1
                curr_target_pos -= 1

            lead_time = t_onset - earliest_gen_pos
            lead_times_numeric.append(lead_time)
            pre_warned_count += 1

            # Distribution buckets
            if lead_time == 1:
                dist_1_min += 1
            elif 2 <= lead_time <= 5:
                dist_2_5_min += 1
            elif 6 <= lead_time <= 10:
                dist_6_10_min += 1
            else:
                dist_gt_10_min += 1

            campaign_evaluations.append({
                "segment_id": seg_id,
                "dataset_day": day,
                "attack_category": category,
                "onset_global_position": t_onset,
                "end_global_position": t_end,
                "window_count": w_count,
                "first_forecast_window": earliest_gen_pos,
                "lead_time_minutes": lead_time,
                "pre_warning_status": "pre_warned",
                "reason": "continuous_positive_forecast_chain",
            })

    pre_warned_pct = float(pre_warned_count / total_campaigns) if total_campaigns > 0 else 0.0

    mean_lead = round(float(np.mean(lead_times_numeric)), 2) if lead_times_numeric else 0.0
    median_lead = float(np.median(lead_times_numeric)) if lead_times_numeric else 0.0

    return {
        "phase": "4.5",
        "report_name": "Temporal Lead-Time & Attack Forecasting Report",
        "timestamp": pd.Timestamp.now().isoformat(),
        "total_campaigns_analyzed": total_campaigns,
        "lead_time_summary": {
            "pre_warned_campaigns_count": pre_warned_count,
            "unwarned_campaigns_count": unwarned_count,
            "unavailable_campaigns_count": unavailable_count,
            "pre_warned_percentage": pre_warned_pct,
            "mean_lead_time_pre_warned_minutes": mean_lead,
            "median_lead_time_pre_warned_minutes": median_lead,
            "lead_time_distribution": {
                "1_min": dist_1_min,
                "2_5_min": dist_2_5_min,
                "6_10_min": dist_6_10_min,
                "greater_than_10_min": dist_gt_10_min,
                "unavailable_or_unpredicted": dist_unpred_or_unavail,
            },
        },
        "campaign_evaluations": campaign_evaluations,
    }
