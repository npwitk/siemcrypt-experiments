# E2: SG-HEF (S) vs. full-HE SIEM (B3)

Synthetic test stream, seeds [1, 2, 3]; K = number of correlation contexts. Releases are identical (tested); only cost differs. 2048-bit times are predicted from E2's T_rand and T_Add.

| System | K | HE enc / event | Bytes / event | HE additions / epoch |
|---|---|---|---|---|
| S | 3 | 3.000 ± 0.000 | 678.094 ± 0.020 | 212.556 ± 1.953 |
| B3 | 3 | 10.000 ± 0.000 | 1574.094 ± 0.020 | 3716.000 ± 0.000 |
| S | 12 | 3.000 ± 0.000 | 680.729 ± 0.020 | 887.472 ± 3.555 |
| B3 | 12 | 37.000 ± 0.000 | 5032.729 ± 0.020 | 20438.000 ± 0.000 |
| S | 48 | 3.000 ± 0.000 | 691.326 ± 0.020 | 3239.972 ± 10.002 |
| B3 | 48 | 145.000 ± 0.000 | 18867.326 ± 0.020 | 87326.000 ± 0.000 |

Total time 280s
