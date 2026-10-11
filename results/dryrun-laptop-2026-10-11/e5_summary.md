# E5 results (synthetic data)

## Part A: manipulation detection

| Manipulation | Detected | Affected record decrypted | Clean run verified |
|---|---|---|---|
| modify payload ciphertext | 2/2 | 0/2 | 2/2 |
| modify HE feature | 2/2 | 0/2 | 2/2 |
| modify index entry | 2/2 | 0/2 | 2/2 |
| substitute record | 2/2 | 0/2 | 2/2 |
| reorder records | 2/2 | 0/2 | 2/2 |
| cross-epoch splice | 2/2 | 0/2 | 2/2 |
| rollback checkpoint (replay) | 2/2 | 0/2 | 2/2 |
| forge checkpoint root | 2/2 | 0/2 | 2/2 |
| truncate MMR size | 2/2 | 0/2 | 2/2 |
| forge MMR node | 2/2 | 0/2 | 2/2 |
| omit requested record | 2/2 | 0/2 | 2/2 |
| omit search result (limitation) | 0/2 | 0/2 | 2/2 |

Omitted search results: 15 plaintexts silently lost over 2 trials (inclusion proofs cannot detect omission).

## Part B: multiproof vs. separate paths

| n | k | Multiproof hashes | Separate hashes | Multiverify (ms) | Separate (ms) |
|---|---|---|---|---|---|
| 1,000 | 1 | 12 | 12 | 0.01 | 0.01 |
| 1,000 | 10 | 61 | 130 | 0.10 | 0.10 |
| 1,000 | 100 | 264 | 1,294 | 0.49 | 1.05 |
| 1,000 | 1000 | 0 | 13,120 | 2.05 | 10.26 |
| 10,000 | 1 | 17 | 17 | 0.02 | 0.02 |
| 10,000 | 10 | 99 | 164 | 0.10 | 0.14 |
| 10,000 | 100 | 586 | 1,642 | 0.87 | 1.44 |
| 10,000 | 1000 | 2,603 | 16,372 | 5.21 | 14.27 |
| 100,000 | 1 | 20 | 20 | 0.02 | 0.02 |
| 100,000 | 10 | 131 | 204 | 0.13 | 0.18 |
| 100,000 | 100 | 904 | 2,051 | 1.18 | 1.81 |
| 100,000 | 1000 | 5,794 | 20,521 | 10.23 | 18.09 |

## Part C: investigation latency (512-bit keys)

| Attack | Window | Verified records | Plaintexts | Identity | Latency (ms) | Bytes |
|---|---|---|---|---|---|---|
| multi_source | 1 | 12 | 9 | yes | 6.9 | 11,421 |
| multi_source | 2 | 27 | 19 | yes | 8.9 | 26,327 |
| multi_source | 2 | 10 | 8 | yes | 0.5 | 11,517 |
| cred_access | 3 | 62 | 60 | yes | 10.3 | 49,717 |
| cred_access | 3 | 23 | 13 | yes | 1.0 | 24,576 |
| multi_source | 3 | 68 | 65 | yes | 1.5 | 54,194 |
| multi_source | 3 | 43 | 26 | yes | 1.4 | 42,332 |
| cred_access | 4 | 27 | 17 | yes | 8.2 | 29,320 |
| exfil | 4 | 41 | 27 | yes | 1.5 | 42,183 |
| exfil | 4 | 24 | 24 | yes | 1.0 | 25,210 |

Total time 6s
