# B6: Ogawa et al. (COMPSAC 2025) reproduced on Kyoto 2016

Years 2015; 3 seeds; balanced 10,000 train / 10,000 test sessions per year; LightGBM.

| Features | Acc | Prec | Rec | F1 | F1 / original | Unique benign | Unique malicious | k>=5 benign | Paper F1 |
|---|---|---|---|---|---|---|---|---|---|
| original | 0.970 ± 0.002 | 0.969 ± 0.004 | 0.971 ± 0.002 | 0.970 ± 0.002 | 100.00% | 0.978 ± 0.000 | 0.909 ± 0.005 | 0.009 ± 0.001 | 0.9867 |
| proposed | 0.935 ± 0.004 | 0.945 ± 0.008 | 0.924 ± 0.001 | 0.935 ± 0.004 | 96.33% | 0.894 ± 0.002 | 0.864 ± 0.011 | 0.021 ± 0.002 | 0.977 |
| minus1 | 0.907 ± 0.003 | 0.918 ± 0.007 | 0.895 ± 0.004 | 0.906 ± 0.003 | 93.39% | 0.875 ± 0.002 | 0.844 ± 0.014 | 0.028 ± 0.001 | 0.9603 |
| proposed+uniqueness | 0.934 ± 0.004 | 0.945 ± 0.007 | 0.922 ± 0.001 | 0.934 ± 0.004 | 96.23% | n/a | n/a | n/a |  |

Paper (Section IV-C): unique sessions 89.91% benign / 96.41% malicious before, 7.40% / 10.62% after anonymization (NII-SOCS); k >= 5 for 78.41% of benign sessions.

Total time 147s
