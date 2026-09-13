"""
NexThreat Phase 5.3 — SOC Alert Dispatcher & Threat Telemetry Exporter.

Applies the Phase 5.3 Operational Alert Priority Policy layered on top of the
immutable S0-S7 threat-state taxonomy without altering model evidence, states,
or computing numerical score fusion.
Exports structured JSON alerts and Syslog RFC 5424 formatted strings for SOC triage.
Zero autonomous remediation (strictly logs and dispatches alerts).
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from src.application.schemas import ApplicationOutputRecord

# ============================================================
# PHASE 5.3 OPERATIONAL ALERT PRIORITY POLICY
# (Layered on top of canonical S0-S7 taxonomy; does NOT modify threat states)
# ============================================================

STATE_TO_OPERATIONAL_TIER: Dict[str, str] = {
    "S7": "Priority 1 (Immediate SOC Triage)",
    "S3": "Priority 2 (Priority Investigation)",
    "S5": "Priority 2 (Priority Investigation)",
    "S6": "Priority 2 (Priority Investigation)",
    "S1": "Priority 3 (Monitored Anomalies & Warnings)",
    "S2": "Priority 3 (Monitored Anomalies & Warnings)",
    "S4": "Priority 3 (Monitored Anomalies & Warnings)",
    "S0": "Priority 4 (Baseline Operations)",
}

STATE_SUMMARIES: Dict[str, str] = {
    "S7": "Full agreement: forecasted, anomalous, classified.",
    "S6": "Unpredicted sudden attack confirmed by AE + XGB.",
    "S5": "Forecasted novel anomaly active.",
    "S3": "Forecasted signature attack active; low AE error.",
    "S4": "Statistical deviation without signature match.",
    "S2": "Known signature matched without AE anomaly.",
    "S1": "Forward-looking warning; current window clean.",
    "S0": "Normal baseline; all models concordant benign.",
}

# RFC 5424 Severity Codes:
# Facility 1 (user-level): PRI = 1 * 8 + Severity
# Critical: 2 -> PRI = 10
# Error: 3 -> PRI = 11
# Warning: 4 -> PRI = 12
# Informational: 6 -> PRI = 14
STATE_TO_SYSLOG_PRI: Dict[str, int] = {
    "S7": 10,  # Critical
    "S3": 11,  # Error
    "S5": 11,  # Error
    "S6": 11,  # Error
    "S1": 12,  # Warning
    "S2": 12,  # Warning
    "S4": 12,  # Warning
    "S0": 14,  # Informational
}


class SOCAlertDispatcher:
    """
    Dispatcher that converts ApplicationOutputRecord instances into operational
    SOC alert objects and standard RFC 5424 syslog messages.
    """

    def __init__(self, hostname: str = "nexthreat-app", app_name: str = "NexThreat"):
        self.hostname = hostname
        self.app_name = app_name

    def format_json_alert(self, record: ApplicationOutputRecord) -> Dict[str, Any]:
        """
        Format an ApplicationOutputRecord into a structured SOC alert JSON record.
        """
        state_code = record.threat_inference.threat_state_code
        state_name = record.threat_inference.threat_state_name
        is_eligible = record.threat_inference.is_eligible

        if not is_eligible or state_code is None:
            tier = "Quarantined (Lookback Cold-Start / Discontinuity)"
            summary = "Temporal lookback unavailable; threat state evaluation quarantined."
            alert_id = f"AUDIT_{record.window_id}_COLDSTART"
        else:
            tier = STATE_TO_OPERATIONAL_TIER.get(state_code, "Unknown Priority")
            summary = STATE_SUMMARIES.get(state_code, "Unclassified threat event.")
            alert_id = f"ALERT_{record.window_id}_{state_code}"

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        alert: Dict[str, Any] = {
            "alert_id": alert_id,
            "window_id": record.window_id,
            "timestamp": record.timestamp,
            "operational_priority_tier": tier,
            "threat_state_code": state_code,
            "threat_state_name": state_name,
            "operational_summary": summary,
            "model_evidence": {
                "autoencoder": {
                    "is_anomaly": record.autoencoder.is_anomaly,
                    "reconstruction_mse": record.autoencoder.reconstruction_mse,
                    "threshold": record.autoencoder.threshold,
                },
                "xgboost": {
                    "is_attack": record.xgboost.is_attack,
                    "predicted_class_index": record.xgboost.predicted_class_index,
                    "predicted_class_name": record.xgboost.predicted_class_name,
                },
                "lstm": {
                    "is_eligible": record.lstm.is_eligible,
                    "forecast_decision": record.lstm.forecast_decision,
                    "forecast_probability": record.lstm.forecast_probability,
                    "threshold": record.lstm.threshold,
                },
            },
            "decision_tuple": record.threat_inference.decision_tuple,
            "dispatched_at_utc": now_utc,
        }
        return alert

    def format_rfc5424_syslog(self, record: ApplicationOutputRecord) -> str:
        """
        Format an ApplicationOutputRecord into a standard RFC 5424 syslog string.
        Format: <{PRI}>1 {TIMESTAMP} {HOSTNAME} {APP-NAME} {PROCID} {MSGID} [{STRUCTURED-DATA}] {MSG}
        """
        state_code = record.threat_inference.threat_state_code or "COLDSTART"
        pri = STATE_TO_SYSLOG_PRI.get(state_code, 14)
        ts_rfc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        proc_id = "-"
        msg_id = state_code

        tier = STATE_TO_OPERATIONAL_TIER.get(state_code, "Quarantined")
        tier_clean = tier.split(" (")[0]  # e.g. "Priority 1"

        xgb_class = record.xgboost.predicted_class_name
        # Escape RFC 5424 structured data special chars: ", \, ]
        def escape_sd(val: str) -> str:
            return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")

        sd_element = (
            f'[threatAlert@5424 windowId="{escape_sd(record.window_id)}" '
            f'state="{escape_sd(state_code)}" tier="{escape_sd(tier_clean)}" '
            f'ae="{record.autoencoder.is_anomaly}" xgb="{record.xgboost.is_attack}" '
            f'lstm="{escape_sd(str(record.lstm.forecast_decision))}" xgbClass="{escape_sd(xgb_class)}"]'
        )

        msg = STATE_SUMMARIES.get(state_code, "Temporal lookback unavailable; window quarantined.")
        return f"<{pri}>1 {ts_rfc} {self.hostname} {self.app_name} {proc_id} {msg_id} {sd_element} {msg}"

    def dispatch_record(self, record: ApplicationOutputRecord) -> Dict[str, Any]:
        """
        Route an ApplicationOutputRecord and return a combined dispatch packet.
        """
        return {
            "json_alert": self.format_json_alert(record),
            "syslog_rfc5424": self.format_rfc5424_syslog(record),
            "is_actionable": bool(
                record.threat_inference.threat_state_code in ("S1", "S2", "S3", "S4", "S5", "S6", "S7")
            ),
        }
