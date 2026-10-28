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
| Swap prescribed HE feature | ACL recomputation (C_spec) | 5/5 | 15 | 0 / 0 | 0 |
| Modify contracted relation | Graph-lineage verification | 5/5 | 0 | 7 / 0 | 15 |
| Omit contributing graph evidence | Graph-lineage verification | 5/5 | 0 | 5 / 2 | 15 |
| Modify graph evidence/features | C_G/recomputation | 5/5 | 0 | 5 / 0 | 15 |
| Suppress an entity update | Graph-lineage verification | 5/5 | 0 | 0 / 5 | 15 |
| Modify drift D_e | Graph-lineage verification | 5/5 | 0 | 0 / 0 | 15 |

Detection by verification level (journal v2: No-ACL / Retrieval-Only / ACL):

| Injected deviation | ACL | Retrieval-Only | No-ACL |
|---|---|---|---|
| Omit queried posting entry | 5/5 | 5/5 | 0/5 |
| Substitute posting entry | 5/5 | 5/5 | 0/5 |
| Replay stale index state | 5/5 | 5/5 | 0/5 |
| Bind to stale checkpoint | 5/5 | 5/5 | 0/5 |
| Omit valid candidate | 5/5 | 5/5 | 0/5 |
| Add invalid candidate | 5/5 | 5/5 | 0/5 |
| Modify HE aggregate | 5/5 | 0/5 | 0/5 |
| Aggregate wrong candidate set | 5/5 | 0/5 | 0/5 |
| Swap prescribed HE feature | 5/5 | 0/5 | 0/5 |
| Modify contracted relation | 5/5 | 0/5 | 0/5 |
| Omit contributing graph evidence | 5/5 | 0/5 | 0/5 |
| Modify graph evidence/features | 5/5 | 0/5 | 0/5 |
| Suppress an entity update | 5/5 | 0/5 | 0/5 |
| Modify drift D_e | 5/5 | 0/5 | 0/5 |

Honest runs: 0 false rejections over 100 verifications (5 runs).

Total time 58s
