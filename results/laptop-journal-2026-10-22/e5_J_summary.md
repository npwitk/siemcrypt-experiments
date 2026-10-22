# E5 results (synthetic data, variant J)

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
| multi_source | 2 | 8 | 8 | yes | 12.0 | 0.12 | 0.11 | 0.15 | 22,822 |
| multi_source | 2 | 19 | 19 | yes | 1.1 | 0.16 | 0.09 | 0.29 | 46,711 |
| cred_access | 3 | 60 | 60 | yes | 8.0 | 0.11 | 0.13 | 0.63 | 120,638 |
| multi_source | 3 | 65 | 65 | yes | 1.9 | 0.15 | 0.12 | 0.67 | 131,663 |
| multi_source | 3 | 26 | 26 | yes | 1.5 | 0.24 | 0.12 | 0.40 | 65,899 |
| multi_source | 4 | 37 | 37 | yes | 7.6 | 0.32 | 0.16 | 0.55 | 92,506 |
| cred_access | 5 | 61 | 61 | yes | 7.6 | 0.16 | 0.21 | 0.64 | 126,103 |
| exfil | 5 | 36 | 36 | yes | 1.8 | 0.14 | 0.20 | 0.53 | 85,128 |
| multi_source | 5 | 41 | 41 | yes | 2.6 | 0.39 | 0.21 | 0.79 | 104,726 |
| cred_access | 6 | 60 | 60 | yes | 8.2 | 0.21 | 0.26 | 0.63 | 125,649 |

Total time 19s
