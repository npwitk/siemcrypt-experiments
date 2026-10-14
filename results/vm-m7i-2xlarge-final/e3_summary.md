# E3 results (synthetic data)

Seeds [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]; mean ± sd.

## Token attacks (a)-(c)

| System | δ | U tokens recovered | U volume recovered | R tokens recovered | R volume recovered | Decoy AUC | Linkage acc. | Linkage chance |
|---|---|---|---|---|---|---|---|---|
| S | 0.000 ± 0.000 | 0.089 ± 0.011 | 0.467 ± 0.034 | 0.030 ± 0.008 | 0.025 ± 0.010 | n/a | 0.081 ± 0.010 | 0.014 ± 0.000 |
| SD | 0.647 ± 0.042 | 0.083 ± 0.011 | 0.461 ± 0.027 | 0.027 ± 0.009 | 0.028 ± 0.012 | 0.994 ± 0.002 | 0.073 ± 0.008 | 0.003 ± 0.000 |
| A4 | 0.000 ± 0.000 | 0.135 ± 0.010 | 0.564 ± 0.016 | 0.034 ± 0.014 | 0.033 ± 0.016 | n/a | 1.000 ± 0.000 | 0.014 ± 0.000 |
| SD+A4 | 0.647 ± 0.042 | 0.125 ± 0.014 | 0.549 ± 0.025 | 0.033 ± 0.012 | 0.035 ± 0.016 | 0.994 ± 0.002 | 1.000 ± 0.000 | 0.003 ± 0.000 |

## Release attacks (d), per run

| System | Per-entity releases | Single-record VALUE releases | Downgraded to DECISION | Repeated request refused | Differencing recovered (epochs) |
|---|---|---|---|---|---|
| S | 640 | 0.000 ± 0.000 | 618.400 ± 1.647 | 10/10 | 8.000 ± 0.000 of 8 |
| A5 | 640 | 56.900 ± 5.065 | 0.000 ± 0.000 | 10/10 | 8.000 ± 0.000 of 8 |

Total time 72s
