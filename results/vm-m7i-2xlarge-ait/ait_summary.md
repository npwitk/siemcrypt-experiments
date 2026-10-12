# AIT-LDSv2 results (ip-172-31-8-110, Linux-6.17.0-1017-aws-x86_64-with-glibc2.39)

Development: russellmitchell, santos, fox; test: harrison, wardbeck, shaw, wheeler, wilson; full scenarios; alert budget 2 benign alerts per class per day.


## E3: leakage on days 2-4 (prior: day 1 of the same scenario)

| System | δ | U tokens | U volume | R tokens | R volume | Decoy AUC | Linkage | Chance |
|---|---|---|---|---|---|---|---|---|
| S | 0.000 ± 0.000 | 0.049 ± 0.007 | 0.285 ± 0.024 | 0.035 ± 0.006 | 0.367 ± 0.075 | n/a | 0.278 ± 0.035 | 0.036 ± 0.005 |
| SD | 1.315 ± 0.263 | 0.052 ± 0.012 | 0.296 ± 0.047 | 0.034 ± 0.004 | 0.357 ± 0.073 | 0.973 ± 0.010 | 0.272 ± 0.034 | 0.003 ± 0.002 |
| A4 | 0.000 ± 0.000 | 0.158 ± 0.034 | 0.535 ± 0.131 | 0.128 ± 0.030 | 0.503 ± 0.042 | n/a | 1.000 ± 0.000 | 0.036 ± 0.005 |
| SD+A4 | 1.315 ± 0.263 | 0.155 ± 0.018 | 0.515 ± 0.099 | 0.099 ± 0.029 | 0.459 ± 0.099 | 0.973 ± 0.010 | 1.000 ± 0.000 | 0.003 ± 0.002 |

## E2: 2048-bit throughput on harrison (105,984 events, 8 workers)

| System | δ | Online ev/s | Sustained ev/s | Offline s | Bytes / event | Phase 3+4+5 s |
|---|---|---|---|---|---|---|
| S | 0.00 | 18,307 | 155.2 | 674 | 1,981 | 1.40 |
| SD | 1.20 | 7,947 | 70.5 | 1485 | 4,359 | 2.13 |

Total time 11213s
