# E5 results (synthetic data, variant J2)

## Part A: manipulation detection

| Manipulation | Detected | Affected record decrypted | Clean run verified |
|---|---|---|---|
| modify payload ciphertext | 5/5 | 0/5 | 5/5 |
| modify HE feature | 5/5 | 0/5 | 5/5 |
| modify index entry | 5/5 | 0/5 | 5/5 |
| substitute record | 5/5 | 0/5 | 5/5 |
| reorder records | 5/5 | 0/5 | 5/5 |
| cross-epoch splice | 5/5 | 0/5 | 5/5 |
| rollback checkpoint (replay) | 5/5 | 0/5 | 5/5 |
| forge checkpoint root | 5/5 | 0/5 | 5/5 |
| truncate MMR size | 5/5 | 0/5 | 5/5 |
| forge MMR node | 5/5 | 0/5 | 5/5 |
| omit requested record | 5/5 | 0/5 | 5/5 |
| omit search result | 5/5 | 0/5 | 5/5 |
| replay stale index state | 5/5 | 0/5 | 5/5 |

Omitted search results: 5/5 detected by the authenticated EPII; plaintexts of the affected epochs withheld: 347.


## Part C: investigation latency (2048-bit keys)

| Attack | Window | Verified records | Plaintexts | Identity | Latency (ms) | EPII (ms) | Checkpoint (ms) | MMR (ms) | Bytes |
|---|---|---|---|---|---|---|---|---|---|
| multi_source | 2 | 26 | 8 | yes | 35.0 | 0.35 | 0.23 | 0.65 | 63,114 |
| multi_source | 2 | 19 | 19 | yes | 2.1 | 0.39 | 0.23 | 0.50 | 48,039 |
| cred_access | 3 | 136 | 60 | yes | 24.9 | 0.35 | 0.31 | 2.74 | 275,078 |
| cred_access | 3 | 40 | 4 | yes | 3.3 | 0.42 | 0.30 | 1.02 | 93,041 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.46 | 0.36 | 2.85 | 298,089 |
| multi_source | 3 | 40 | 4 | yes | 3.4 | 0.51 | 0.31 | 0.93 | 95,185 |
| multi_source | 3 | 26 | 26 | yes | 3.0 | 0.57 | 0.29 | 0.65 | 68,611 |
| cred_access | 4 | 45 | 5 | yes | 20.7 | 0.55 | 0.40 | 1.07 | 107,250 |
| exfil | 4 | 28 | 24 | yes | 2.8 | 0.27 | 0.40 | 0.71 | 68,266 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.72 | 0.43 | 0.94 | 95,722 |

Total time 65s
