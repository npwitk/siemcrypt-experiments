"""Cost models of the 2024-2026 journal baselines requested for the IEEE TCC version
(instructor, 2026-11-05: "2024-2026 only"; replaces Boudguiga et al. ICISSP 2020 as the main
HE comparison). Same method as PriSIEM (prisiem.py): count each scheme's primitive operations
per event (Exp 2) and per verification of k of n records (Exp 6) from the paper, then price
them with unit costs measured on our machine with the paper's parameters
(experiments/e_recent_baselines.py). Where a paper leaves a parameter open, the choice below
favours the baseline and is stated.

  B10 Zhang, Zhang, Liang, Li, Dobre, Computing 107(7) 148, 2025
      (doi 10.1007/s00607-025-01506-y). Blocks RSA-encrypted on IPFS; the content hash (CID)
      Paillier-encrypted (g = 1 + n, eq. 6) and RSA-signed (eq. 7) on Ethereum.
      Upload per block: RSA blind signature with the gateway (eqs. 3-5: 2 public + 1 private
      exponentiation, 1 hash), 1 Paillier encryption of the CID, 1 hash + 1 RSA private
      exponentiation for the signature. Block encryption: RSA in the paper, priced here as
      hybrid AES-GCM (cheaper, favours B10). Verification per block (eqs. 10-13): signature
      check (1 RSA public exp + hash), Paillier decryption of the CID, hash of the block
      (content addressing). Linear in k, independent of n; no batching, no completeness.
      Key sizes are not fixed in the paper (64-1024-bit Paillier tested): 2048 bits for both.
      No encrypted analytics.

  B11 Naresh, Ayyappa, J. Inf. Secur. Appl. 92, 104084, 2025 (doi 10.1016/j.jisa.2025.104084).
      Every flow feature Paillier-encrypted at the client (pp. 3-4); the IDS model is trained
      and run on the ciphertext values, not homomorphically, so accuracy falls from 99.99 % to
      87.11 % (Table 3). Key size and feature count are not given: 2048 bits; F = 77 numeric
      InSDN flow features (and F = 3, our feature count, as the favourable case).

  B12 Ji, Song, Cho, J. Inf. Secur. Appl. 101, 104550, 2026 (our ref7). AES-256-GCM per
      sensitive field with a fresh 96-bit nonce and base64url token (pp. 3, 5); policy P3
      encrypts 5 fields per record (+258 B, Table 15). No HE, no verification.

  B13 Wu et al. (SAP-ECKS / SAP-VECKS), Security and Safety 4, 2024022, 2025
      (doi 10.1051/sands/2024022). Two non-colluding servers return two encrypted polynomials of
      degree 2L+1 (L = largest posting list, so L >= k); the user decrypts 2(2L+2) Paillier
      ciphertexts (1024-bit N, p. 17), checks that beta is a root, and finds the roots
      (p. 12). Priced as decryptions only, with L = k and one keyword (m = 1): root finding,
      the servers' (8L+6)m exponentiations and the trapdoor are left out, so it is a lower bound.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- Exp 2: per event


def zhang_event_us(u: dict[str, float]) -> float:
    blind = 2 * u["rsa_pub"] + u["rsa_priv"] + u["hash"]  # eqs. 3-5
    block = u["aes_field"]  # block encryption (RSA in the paper; hybrid here, favours B10)
    cid = u["paillier2048_enc"]  # eq. 6
    sig = u["hash"] + u["rsa_priv"]  # eq. 7
    return blind + block + cid + sig


def zhang_event_bytes(payload: int = 200) -> int:
    return payload + 28 + 512 + 256 + 8  # AEAD block, CT_CID (2048-bit Paillier), Sig, T_c


def naresh_event_us(u: dict[str, float], features: int = 77) -> float:
    return features * u["paillier2048_enc"]


def naresh_event_bytes(features: int = 77) -> int:
    return features * 512


def ji_event_us(u: dict[str, float], fields: int = 5) -> float:
    return fields * u["aes_field"]


JI_EVENT_BYTES_P3 = 258  # Table 15, overhead per record under P3


def siemcrypt_event_us(u: dict[str, float], he_per_event: float) -> float:
    """S per real event: HE encryptions (decoys and realness indicator included, from
    tab:e3-volume) priced without precomputation, plus the symmetric work (AES-GCM payload,
    4 PRF tokens, MMR leaf and posting hashes)."""
    return he_per_event * u["paillier2048_enc"] + u["aes_payload"] + 4 * u["prf"] + 3 * u["hash"]


# --------------------------------------------------------------------------- Exp 6: verify k of n


def zhang_verify_ms(k: int, u: dict[str, float]) -> float:
    return k * (u["rsa_pub"] + u["hash"] + u["paillier2048_dec"] + u["hash"]) / 1e3


def wu_verify_ms(k: int, u: dict[str, float]) -> float:
    L = k
    return 2 * (2 * L + 2) * u["paillier1024_dec"] / 1e3
