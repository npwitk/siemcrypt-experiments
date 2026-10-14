# Published baselines: B5 PriSIEM, B7 EVSEB, B8 MK-Tree

Seeds [1, 2, 3]. TFHE gate time for B5: 20,717 µs (measured).

## A. Ingestion on the synthetic test stream

| System | µs / event | Bytes / event | Work per event |
|---|---|---|---|
| S | 681.421 ± 1.344 | 678.042 ± 0.020 | 512-bit Paillier; see E2 for 2048-bit |
| B7 EVSEB | 37.570 ± 0.273 | 223.491 ± 0.030 | AES, 4 keyword PRFs, Bloom, DHT, quaternary Merkle |
| B8 MK-Tree | 145.099 ± 1.502 | 219.425 ± 0.039 | AEAD, Ed25519 sign + verify, binary Merkle, certificates |
| B5 PriSIEM | 34631219.220 ± 0.000 | n/a | 1672 TFHE gates / event, 1 thread |

B5 per-event cost uses 1653 gates (3 contexts × (Filter 256 + T-Count 295), PriSIEM Table 5), a lower bound; PriSIEM reports 1-4 tuples/s for its Rule-1 with 1-8 threads.

## B. Verifying k records out of n

| n | k | S hashes | S ms | B7 hashes | B7 ms | B8 hashes | B8 ms | B9 audit ms |
|---|---|---|---|---|---|---|---|---|
| 1,000 | 1 | 12 | 0.06 | 335 | 1.61 | 13 | 0.15 | 53.2 |
| 1,000 | 10 | 83 | 0.20 | 344 | 1.60 | 115 | 1.75 | 53.2 |
| 1,000 | 100 | 462 | 0.96 | 434 | 1.55 | 612 | 11.78 | 53.2 |
| 1,000 | 1000 | 1,999 | 4.37 | 1,334 | 0.98 | 3,051 | 106.58 | 53.2 |
| 10,000 | 1 | 15 | 0.06 | 3,337 | 16.16 | 17 | 0.18 | 513.8 |
| 10,000 | 10 | 111 | 0.26 | 3,346 | 16.26 | 145 | 1.25 | 513.8 |
| 10,000 | 100 | 783 | 1.71 | 3,436 | 16.21 | 915 | 11.41 | 513.8 |
| 10,000 | 1000 | 4,615 | 10.14 | 4,336 | 16.23 | 5,651 | 110.12 | 513.8 |
| 100,000 | 1 | 22 | 0.08 | 33,338 | 170.72 | 20 | 0.25 | 5119.9 |
| 100,000 | 10 | 152 | 3.96 | 33,347 | 174.51 | 180 | 1.37 | 5119.9 |
| 100,000 | 100 | 1,134 | 2.14 | 33,437 | 172.23 | 1,268 | 15.46 | 5119.9 |
| 100,000 | 1000 | 7,812 | 18.45 | 34,337 | 175.33 | 8,854 | 117.13 | 5119.9 |

B9 audits a random third of the n blocks whatever k is (the paper's setting); its time is the paper's cost formula (Section VII-A) with BN254 unit costs from tools/pairing_bench (pairing 936 µs, G1 exponentiation 76 µs).

## C. Manipulation detected (S: see E5)

| Manipulation | B7 EVSEB | B8 MK-Tree |
|---|---|---|
| modify payload ciphertext | 3/3 | 3/3 |
| substitute record | 3/3 | 3/3 |
| reorder records | 3/3 | 3/3 |
| cross-epoch splice | 3/3 | 3/3 |
| rewrite record and off-chain proofs | 3/3 | 3/3 |
| omit search result | 0/3 | n/a |

## C2. B9 (Zhang et al.): share of audits that detect one manipulated record

| Manipulation | Detected / audits | Predicted 1 - (1 - t/n)^l2 |
|---|---|---|
| modify payload ciphertext | 22/60 | 0.29 |
| substitute record | 18/60 | 0.29 |
| reorder records | 27/60 | 0.49 |
| cross-epoch splice | 20/60 | 0.29 |

n = 48 blocks, l2 = 16; a failed audit marks the whole epoch file non-integral and does not identify the record.

## D. Frequency attack on entity tokens (same workload and auxiliary data as E3)

| System | U tokens recovered | U volume recovered | Cross-epoch linkage |
|---|---|---|---|
| S | 0.090 ± 0.008 | 0.482 ± 0.013 | see E3 |
| B7 EVSEB | 0.157 ± 0.019 | 0.599 ± 0.016 | 1.000 (static trapdoors) |

Total time 300s
