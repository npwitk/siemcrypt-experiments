# Journal Experiment 5: deviations against ACL (synthetic data)

Trials [1, 2, 3, 4, 5]; the deviation happens in the last epoch. Released = KA releases in that epoch (out of 3 contexts per trial).

| Injected deviation | Detection stage | Detected | Contexts rejected | Updates rejected / omitted | Released |
|---|---|---|---|---|---|
| Omit queried posting entry | Authenticated EPII | 5/5 | 15 | 0 / 0 | 0 |
| Substitute posting entry | Authenticated EPII | 5/5 | 15 | 0 / 0 | 0 |
| Replay stale index state | Checkpoint/EPII root | 5/5 | 15 | 0 / 0 | 0 |
| Bind to stale checkpoint | Context commitment | 5/5 | 15 | 0 / 0 | 0 |
| Omit valid candidate | Candidate recomputation | 5/5 | 15 | 0 / 0 | 0 |
| Add invalid candidate | Candidate recomputation | 5/5 | 15 | 0 / 0 | 0 |
| Modify HE aggregate | ACL recomputation | 5/5 | 15 | 0 / 0 | 0 |
| Aggregate wrong candidate set | ACL recomputation | 5/5 | 15 | 0 / 0 | 0 |
| Modify contracted relation | Graph-lineage verification | 5/5 | 0 | 7 / 0 | 15 |
| Omit contributing graph evidence | Graph-lineage verification | 5/5 | 0 | 5 / 2 | 15 |
| Modify graph evidence/features | C_G/recomputation | 5/5 | 0 | 5 / 0 | 15 |
| Suppress an entity update | Graph-lineage verification | 5/5 | 0 | 0 / 5 | 15 |
| Modify drift D_e | Graph-lineage verification | 5/5 | 0 | 0 / 0 | 15 |

Honest runs: 0 false rejections over 100 verifications (5 runs).

Total time 12s
