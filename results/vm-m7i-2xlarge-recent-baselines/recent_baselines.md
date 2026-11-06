# 2024-2026 journal baselines (B10-B13) against SIEMCrypt

Machine: Linux-7.0.0-1014-aws-x86_64-with-glibc2.39 / x86_64 / Python 3.12.3. Unit costs (median µs):

| Unit | µs |
|---|---|
| paillier2048_enc | 9,929.866 |
| paillier2048_dec | 2,808.654 |
| paillier1024_dec | 424.736 |
| rsa_priv | 834.000 |
| rsa_pub | 24.069 |
| aes_field | 1.452 |
| aes_payload | 1.111 |
| hash | 0.465 |
| prf | 1.955 |

## A. Protection cost per event (2048-bit keys, offline work included, one core)

| System | µs / event | bytes / event | encrypted analytics | note |
|---|---|---|---|---|
| S-NoPad | 29,799.9 | - | yes (Paillier, exact) | 3.0 HE enc / real event |
| S, k=3 | 39,928.4 | - | yes (Paillier, exact) | 4.02 HE enc / real event |
| S, k=5 | 50,652.6 | - | yes (Paillier, exact) | 5.1 HE enc / real event |
| B10 Zhang 2025 | 11,648.4 | 1,004 | no | Paillier CID + RSA blind sig + RSA sig |
| B11 Naresh 2025, F=77 | 764,599.6 | 39,424 | no (model on ciphertext values) | one Paillier ciphertext per flow feature |
| B11 Naresh 2025, F=3 | 29,789.6 | 1,536 | no (model on ciphertext values) | favourable case: our 3 features |
| B12 Ji 2026 (ref7), P3 | 7.3 | 258 | no | 5 AES-GCM fields |

## B. Verifying k records out of n (ms)

| n | k | B10 Zhang 2025 | B13 Wu 2025 (lower bound) |
|---|---|---|---|
| 1,000 | 10 | 28.3 | 18.7 |
| 1,000 | 1,000 | 2,833.7 | 1,700.6 |
| 10,000 | 10 | 28.3 | 18.7 |
| 10,000 | 1,000 | 2,833.7 | 1,700.6 |
| 100,000 | 10 | 28.3 | 18.7 |
| 100,000 | 1,000 | 2,833.7 | 1,700.6 |

B13 counts only the user's 2(2L+2) Paillier-1024 decryptions with L = k and one keyword; root finding, server search and the trapdoor are excluded, so it is a lower bound. Neither B10 nor B13 depends on n.

Total time 4s
