# 2024-2026 journal baselines (B10-B13) against SIEMCrypt

Machine: macOS-27.2-arm64-arm-64bit-Mach-O / arm / Python 3.13.5. Unit costs (median µs):

| Unit | µs |
|---|---|
| paillier2048_enc | 4,854.563 |
| paillier2048_dec | 1,292.750 |
| paillier1024_dec | 193.812 |
| rsa_priv | 389.688 |
| rsa_pub | 11.375 |
| aes_field | 2.083 |
| aes_payload | 2.000 |
| hash | 0.209 |
| prf | 1.000 |

## A. Protection cost per event (2048-bit keys, offline work included, one core)

| System | µs / event | bytes / event | encrypted analytics | note |
|---|---|---|---|---|
| S-NoPad | 14,570.3 | - | yes (Paillier, exact) | 3.0 HE enc / real event |
| S, k=3 | 19,522.0 | - | yes (Paillier, exact) | 4.02 HE enc / real event |
| S, k=5 | 24,764.9 | - | yes (Paillier, exact) | 5.1 HE enc / real event |
| B10 Zhang 2025 | 5,659.2 | 1,004 | no | Paillier CID + RSA blind sig + RSA sig |
| B11 Naresh 2025, F=77 | 373,801.3 | 39,424 | no (model on ciphertext values) | one Paillier ciphertext per flow feature |
| B11 Naresh 2025, F=3 | 14,563.7 | 1,536 | no (model on ciphertext values) | favourable case: our 3 features |
| B12 Ji 2026 (ref7), P3 | 10.4 | 258 | no | 5 AES-GCM fields |

## B. Verifying k records out of n (ms)

| n | k | B10 Zhang 2025 | B13 Wu 2025 (lower bound) |
|---|---|---|---|
| 1,000 | 10 | 13.0 | 8.5 |
| 1,000 | 1,000 | 1,304.5 | 776.0 |
| 10,000 | 10 | 13.0 | 8.5 |
| 10,000 | 1,000 | 1,304.5 | 776.0 |
| 100,000 | 10 | 13.0 | 8.5 |
| 100,000 | 1,000 | 1,304.5 | 776.0 |

B13 counts only the user's 2(2L+2) Paillier-1024 decryptions with L = k and one keyword; root finding, server search and the trapdoor are excluded, so it is a lower bound. Neither B10 nor B13 depends on n.

Total time 1s
