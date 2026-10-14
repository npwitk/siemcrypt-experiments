# E2: SG-HEF (S) vs. full-HE SIEM (B3)

Synthetic test stream, seeds [1, 2, 3]; K = number of correlation contexts. Releases are identical (tested); only cost differs. 2048-bit times are predicted from E2's T_rand and T_Add.

| System | K | HE enc / event | Bytes / event | Offline ms / event @2048 | HE additions / epoch | Phase 3 ms / epoch @2048 |
|---|---|---|---|---|---|---|
| S | 3 | 3.000 ± 0.000 | 678.042 ± 0.020 | 28.050 ± 0.000 | 212.556 ± 1.953 | 1.078 ± 0.010 |
| B3 | 3 | 10.000 ± 0.000 | 1574.042 ± 0.020 | 93.500 ± 0.000 | 3716.000 ± 0.000 | 18.844 ± 0.000 |
| S | 12 | 3.000 ± 0.000 | 680.678 ± 0.020 | 28.050 ± 0.000 | 887.472 ± 3.555 | 4.500 ± 0.018 |
| B3 | 12 | 37.000 ± 0.000 | 5032.678 ± 0.020 | 345.950 ± 0.000 | 20438.000 ± 0.000 | 103.641 ± 0.000 |
| S | 48 | 3.000 ± 0.000 | 691.274 ± 0.020 | 28.050 ± 0.000 | 3239.972 ± 10.002 | 16.430 ± 0.051 |
| B3 | 48 | 145.000 ± 0.000 | 18867.274 ± 0.020 | 1355.749 ± 0.000 | 87326.000 ± 0.000 | 442.830 ± 0.000 |

Total time 298s
