# B4: Wingarz et al. (CNS 2024) reproduced

Data: Friday-02-03-2018_TrafficForML_CICFlowMeter.csv, Friday-16-02-2018_TrafficForML_CICFlowMeter.csv, Friday-23-02-2018_TrafficForML_CICFlowMeter.csv, Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv, Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv, Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv, Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv; 16,137,183 rows after cleaning; 46 features; split 80/10/10; CKKS N = 16384, q = [60, 5x40, 60], scale 2^40 (TenSEAL).

| Model | Acc | Prec | Rec | F1 | Server s / batch | MB / batch | µs / vector |
|---|---|---|---|---|---|---|---|
| Baseline50 (ours) | 0.9400 | 0.7577 | 0.9520 | 0.8438 | | | |
| CKKS50 (ours) | 0.9412 | 0.7640 | 0.9545 | 0.8487 | 1.66 | 54.9 | 203 |
| Baseline50 (paper) | 0.9872 | 0.9981 | 0.9264 | 0.961 | | | |
| CKKS50 (paper) | 0.9871 | 0.9983 | 0.9257 | 0.9607 | 1.35 | 59.6 | 165 |

A batch costs the same time whether full or not (3 of 3 batches were full); per-vector cost assumes full batches of 8,192.

Total time 848s
