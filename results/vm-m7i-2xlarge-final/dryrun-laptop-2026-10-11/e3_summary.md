# E3 results (synthetic data)

Seeds [1, 2]; mean ± sd.

## Token attacks (a)-(c)

| System | δ | U tokens recovered | U volume recovered | R tokens recovered | R volume recovered | Decoy AUC | Linkage acc. | Linkage chance |
|---|---|---|---|---|---|---|---|---|
| S | 0.617 ± 0.009 | 0.071 ± 0.008 | 0.434 ± 0.029 | 0.021 ± 0.001 | 0.021 ± 0.001 | 0.994 ± 0.001 | 0.062 ± 0.007 | 0.003 ± 0.000 |
| A1 | 0.000 ± 0.000 | 0.077 ± 0.007 | 0.432 ± 0.031 | 0.037 ± 0.002 | 0.033 ± 0.001 | n/a | 0.078 ± 0.003 | 0.014 ± 0.000 |
| A4 | 0.617 ± 0.009 | 0.114 ± 0.002 | 0.540 ± 0.002 | 0.030 ± 0.007 | 0.030 ± 0.001 | 0.994 ± 0.001 | 1.000 ± 0.000 | 0.003 ± 0.000 |
| static | 0.000 ± 0.000 | 0.127 ± 0.003 | 0.558 ± 0.007 | 0.029 ± 0.006 | 0.025 ± 0.000 | n/a | 1.000 ± 0.000 | 0.014 ± 0.000 |

## Release attacks (d), per run

| System | Per-entity releases | Single-record VALUE releases | Downgraded to DECISION | Repeated request refused | Differencing recovered (epochs) |
|---|---|---|---|---|---|
| S | 640 | 0.000 ± 0.000 | 620.000 ± 1.414 | 2/2 | 8.000 ± 0.000 of 8 |
| A5 | 640 | 50.000 ± 0.000 | 0.000 ± 0.000 | 2/2 | 8.000 ± 0.000 of 8 |

Total time 12s
