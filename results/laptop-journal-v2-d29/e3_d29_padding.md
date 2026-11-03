# D29 cohort-aligned padding vs LAPH-E (synthetic data)

Seeds [1, 2, 3, 4, 5]; mean. Lower is better for every attack column (decoy AUC: 0.5 ideal).

## Part A: volume attacks

| System | δ | HE enc/event | U recovery | high-exposure U | high-exposure U (bucket tie-break) | U recovery (decoy-aware) | R recovery | linkage | linkage high | decoy AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| NP | 0.000 | 3.000 | 0.091 | 0.410 | 0.426 | 0.084 | 0.033 | 0.082 | 0.413 | - |
| LAPH-E | 0.602 | 4.807 | 0.069 | 0.283 | 0.287 | 0.061 | 0.035 | 0.066 | 0.265 | 0.750 |
| CPt-5 | 0.700 | 5.101 | 0.048 | 0.096 | 0.140 | 0.074 | 0.025 | 0.060 | 0.248 | 0.870 |
| CP-5 | 1.323 | 6.968 | 0.041 | 0.111 | 0.112 | 0.077 | 0.030 | 0.075 | 0.359 | 0.829 |

## Part B: detection (E1 test stream)

| System | macro F1 | macro AUC | cred_access p | cred_access r | cred_access auc | exfil p | exfil r | exfil auc | multi_source p | multi_source r | multi_source auc |
|---|---|---|---|---|---|---|---|---|---|---|---|
| NP | 0.637 | 0.982 | 0.700 | 0.600 | 0.951 | 0.383 | 1.000 | 1.000 | 0.567 | 1.000 | 0.996 |
| LAPH-E | 0.618 | 0.985 | 0.710 | 0.950 | 0.959 | 0.197 | 1.000 | 1.000 | 0.567 | 1.000 | 0.997 |
| CPt-5 | 0.524 | 0.981 | 0.633 | 0.450 | 0.949 | 0.197 | 1.000 | 0.998 | 0.567 | 1.000 | 0.996 |
| CP-5 | 0.418 | 0.995 | 0.549 | 0.600 | 0.987 | 0.100 | 1.000 | 0.999 | 0.348 | 1.000 | 0.997 |
