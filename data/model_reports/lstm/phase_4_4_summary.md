# NexThreat Phase 4.4 — LSTM Attack Forecasting Summary

- **Status**: COMPLETED
- **Timestamp**: 2026-09-12T17:30:00.465943
- **Selected Model**: Candidate C (Compact LSTM-32) (`Candidate_C`)
- **Decision Threshold**: `0.3000`
- **Feature Contract**: 13 engineered sequential features (`flow_count` ... `syn_packet_ratio`)
- **Input Tensor Shape**: `(N, 10, 13)`
- **Lookback Windows**: 10 (windows $t-9 \dots t$)
- **Forecast Horizon**: 1 (window $t+1$)

## Performance Summary

| Split | Metric | Value |
|---|---|---|
| **Validation** | Optimal Threshold | `0.3000` |
| **Validation** | Attack Recall | `0.9813` |
| **Validation** | Attack F1 | `0.4636` |
| **Validation** | FPR | `0.8764` |
| **Validation** | Accuracy | `0.3639` |
| **Test** | Accuracy | `0.2552` |
| **Test** | Attack Recall | `1.0000` |
| **Test** | Attack Precision | `0.0897` |
| **Test** | Attack F1 | `0.1647` |
| **Test** | FPR | `0.8038` |
| **Test** | FNR | `0.0000` |
| **Test** | ROC-AUC | `0.8176` |
| **Test** | PR-AUC | `0.1724` |
