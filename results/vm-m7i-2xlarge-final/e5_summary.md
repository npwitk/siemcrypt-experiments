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

Omitted search results: 47 plaintexts silently lost over 5 trials (inclusion proofs cannot detect omission).

## Part B: multiproof vs. separate paths

| n | k | Multiproof hashes | Separate hashes | Multiverify (ms) | Separate (ms) |
|---|---|---|---|---|---|
| 1,000 | 1 | 12 | 12 | 0.02 | 0.02 |
| 1,000 | 10 | 61 | 130 | 0.15 | 0.21 |
| 1,000 | 100 | 264 | 1,294 | 0.84 | 2.03 |
| 1,000 | 1000 | 0 | 13,120 | 3.26 | 20.38 |
| 10,000 | 1 | 17 | 17 | 0.03 | 0.03 |
| 10,000 | 10 | 99 | 164 | 0.17 | 0.28 |
| 10,000 | 100 | 586 | 1,642 | 1.44 | 2.74 |
| 10,000 | 1000 | 2,603 | 16,372 | 8.39 | 27.95 |
| 100,000 | 1 | 20 | 20 | 0.03 | 0.03 |
| 100,000 | 10 | 131 | 204 | 0.23 | 0.37 |
| 100,000 | 100 | 904 | 2,051 | 2.02 | 3.46 |
| 100,000 | 1000 | 5,794 | 20,521 | 17.27 | 35.50 |
| 1,000,000 | 1 | 25 | 25 | 0.04 | 0.04 |
| 1,000,000 | 10 | 159 | 240 | 0.35 | 0.42 |
| 1,000,000 | 100 | 1,254 | 2,427 | 3.43 | 4.22 |
| 1,000,000 | 1000 | 9,102 | 24,199 | 30.28 | 42.62 |

## Part C: investigation latency (2048-bit keys)

| Attack | Window | Verified records | Plaintexts | Identity | Latency (ms) | Bytes |
|---|---|---|---|---|---|---|
| multi_source | 2 | 19 | 19 | yes | 22.4 | 40,797 |
| multi_source | 2 | 8 | 8 | yes | 0.9 | 18,796 |
| cred_access | 3 | 60 | 60 | yes | 14.7 | 115,343 |
| multi_source | 3 | 26 | 26 | yes | 2.0 | 56,556 |
| multi_source | 3 | 65 | 65 | yes | 2.8 | 124,696 |
| multi_source | 4 | 37 | 37 | yes | 13.0 | 80,022 |
| cred_access | 5 | 61 | 61 | yes | 13.8 | 118,590 |
| exfil | 5 | 36 | 36 | yes | 2.9 | 78,367 |
| multi_source | 5 | 41 | 41 | yes | 3.2 | 89,533 |
| cred_access | 6 | 60 | 60 | yes | 14.3 | 116,739 |

Total time 46s
