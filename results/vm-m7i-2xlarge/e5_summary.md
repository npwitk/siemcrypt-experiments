# E5 results (synthetic data)

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
| omit search result (limitation) | 0/5 | 0/5 | 5/5 |

Omitted search results: 46 plaintexts silently lost over 5 trials (inclusion proofs cannot detect omission).

## Part B: multiproof vs. separate paths

| n | k | Multiproof hashes | Separate hashes | Multiverify (ms) | Separate (ms) |
|---|---|---|---|---|---|
| 1,000 | 1 | 12 | 12 | 0.02 | 0.02 |
| 1,000 | 10 | 61 | 130 | 0.14 | 0.18 |
| 1,000 | 100 | 264 | 1,294 | 0.73 | 1.81 |
| 1,000 | 1000 | 0 | 13,120 | 2.97 | 18.05 |
| 10,000 | 1 | 17 | 17 | 0.03 | 0.03 |
| 10,000 | 10 | 99 | 164 | 0.16 | 0.25 |
| 10,000 | 100 | 586 | 1,642 | 1.31 | 2.51 |
| 10,000 | 1000 | 2,603 | 16,372 | 7.65 | 25.47 |
| 100,000 | 1 | 20 | 20 | 0.03 | 0.03 |
| 100,000 | 10 | 131 | 204 | 0.20 | 0.31 |
| 100,000 | 100 | 904 | 2,051 | 1.81 | 3.09 |
| 100,000 | 1000 | 5,794 | 20,521 | 15.22 | 31.44 |
| 1,000,000 | 1 | 25 | 25 | 0.04 | 0.04 |
| 1,000,000 | 10 | 159 | 240 | 0.33 | 0.36 |
| 1,000,000 | 100 | 1,254 | 2,427 | 3.07 | 3.74 |
| 1,000,000 | 1000 | 9,102 | 24,199 | 26.35 | 37.40 |

## Part C: investigation latency (2048-bit keys)

| Attack | Window | Verified records | Plaintexts | Identity | Latency (ms) | Bytes |
|---|---|---|---|---|---|---|
| multi_source | 1 | 12 | 9 | yes | 14.8 | 25,245 |
| multi_source | 2 | 27 | 19 | yes | 19.2 | 57,431 |
| multi_source | 2 | 10 | 8 | yes | 1.0 | 23,037 |
| cred_access | 3 | 62 | 60 | yes | 22.1 | 121,141 |
| cred_access | 3 | 23 | 13 | yes | 1.8 | 51,072 |
| multi_source | 3 | 68 | 65 | yes | 2.8 | 132,530 |
| multi_source | 3 | 43 | 26 | yes | 2.6 | 91,868 |
| cred_access | 4 | 27 | 17 | yes | 17.6 | 60,424 |
| exfil | 4 | 41 | 27 | yes | 2.7 | 89,415 |
| exfil | 4 | 24 | 24 | yes | 1.7 | 52,858 |

Total time 63s
