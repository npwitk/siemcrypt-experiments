# SIEMCrypt experiments

Prototype and experiment code for **SIEMCrypt: Privacy-Preserving Security Event Analytics over Multi-Source Encrypted Log Data**. It is a CSS453 research project at SIIT (team: Phinnawat Yaemsanguan, Lapitsala Chimpad, Nonprawich Intakaew; advisor: Dr. Somchart Fugkeaw).

The prototype implements all six phases of the paper with explicit parties and message passing:

| Party | Role | Module |
|---|---|---|
| EE (Edge Encryptor) | Tokens, AES-GCM payloads, Paillier features, optional decoy padding, MMR and checkpoints; trusted history, scoring and alerts; label-free screening | `siemcrypt/parties/ee.py` |
| KA (Key Authority) | Epoch keys, release with minimum support `k_min`, checkpoint signatures, payload keys after verification | `siemcrypt/parties/ka.py` |
| TD (Token Directory) | (epoch, token) to identity, for authorized resolution | `siemcrypt/parties/td.py` |
| Cloud SIEM | Encrypted inverted index, SG-HEF (search-scoped homomorphic aggregation), attack-aware graph contraction, evidence with MMR multiproofs | `siemcrypt/parties/cloud.py` |
| SA (Security Analyst) | Verify-before-decrypt investigation | `siemcrypt/parties/sa.py` |

Cryptographic building blocks are in `siemcrypt/crypto/`:
- `paillier.py`: Paillier with parallel offline randomizer precomputation.
- `mmr.py`: domain-separated Merkle Mountain Range with multiproofs.
- `cms.py`: Count-Min sketch.
- `primitives.py`: AES-GCM, HMAC PRF, HKDF and Ed25519, from `cryptography`.

Every module cites the paper equation it implements (e.g. `eq:mmr-leaf`). A message bus (`siemcrypt/bus.py`) counts bytes and records the cloud's complete view, which is the input of the leakage attacks.

## Setup
Python 3.11 or later is required.
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,experiments]"
pytest -q
```

## Data
- **Synthetic** (`siemcrypt/data/synth.py`): benign multi-source background with injected brute-force, low-and-slow, exfiltration and coordinated multi-source attacks, with exact ground truth.
- **AIT Log Data Set V2.0** (Landauer et al., [Zenodo 5789064](https://zenodo.org/records/5789064), CC BY-NC-SA 4.0): 8 scenarios of real multi-host logs, each with one labeled multi-step attack chain.
  - The archives total about 130 GB, mostly packet captures. `tools/ait_fetch.py` reads only the text logs and labels out of the zips over HTTP range requests, about 1 GB in total, and stores them in `~/data/ait-ldsv2/`.
  - `siemcrypt/data/ait.py` normalizes web, DNS, VPN, auth, audit, mail and Suricata logs into SIEMCrypt events. It turns the labels into incidents of four classes: recon, web_attack, priv_esc and dns_exfil.
```bash
python tools/ait_fetch.py              # all 8 scenarios; rerun to resume
```

## Systems and variants
| ID | System |
|---|---|
| S | SIEMCrypt, default configuration: no decoys (`gamma=1`), epoch token rotation, `k_min=3` |
| SD | SIEMCrypt with decoy padding (`gamma=2`): the optional frequency-hiding mode |
| B2 | Plaintext twin: same correlation logic, no protection |
| B1-default / B1-tuned | Wazuh-style frequency rules (default rule parameters / one-hour window calibrated to the same alert budget). This is an emulation in Python, not Wazuh. |
| A2 | No trusted history (one-epoch window) |
| A3 | No label-free screening |
| A4 | Persistent tokens (no epoch rotation) |
| A5 | No minimum support (`k_min=0`) |

Switches live in `siemcrypt/model.py:Config`.

## Experiments
| Script | Question | Output |
|---|---|---|
| `experiments/e1_accuracy.py` | E1: detection accuracy, low-and-slow sweep, McNemar, threshold-free AUC and recall@FP2 (synthetic) | `results/e1_*` |
| `experiments/e2_microbench.py` | E2: unit costs of every primitive (2048-bit) | `results/e2_microbench.csv` |
| `experiments/e3_leakage.py` | E3: frequency analysis, decoy distinguisher, cross-epoch linkage, release attacks (synthetic) | `results/e3_*` |
| `experiments/e4_tradeoff.py` | E4: sweeps of gamma, epoch length and `k_min` | `results/e4_*` |
| `experiments/e5_integrity.py` | E5: 12 tampering types, multiproof vs. separate paths, investigation latency | `results/e5_*` |
| `experiments/ait_eval.py` | E1, E2 and E3 on AIT-LDSv2: real attack chains, injected low-and-slow attacks on real background, leakage, 2048-bit throughput | `results/ait_*` |
| `experiments/smoke.py` | End-to-end run of Phases 1–6 | stdout |

Methodology:
- **Calibration.** Weights are learned by logistic regression and thresholds are calibrated on development data that is never used for testing: separate seeds for synthetic data, separate scenarios for AIT.
- **Key size.** Accuracy and leakage use 512-bit Paillier keys, because releases are exact (tested) and results do not depend on the key size. Timings use 2048-bit keys.

```bash
bash experiments/run_all.sh --quick    # dry run of everything
bash experiments/run_all.sh            # full run; see docs/aws.md for the evaluation VM
```

## Results
Curated runs are committed under `results/<machine>[-<date>]/`, each with its `full.log` and environment files. The top level of `results/` is scratch space and is git-ignored. All numbers reported in the paper come from the evaluation VM described in `docs/aws.md`.

## Layout
```
siemcrypt/          prototype (crypto/, parties/, data/, model.py, protocol.py, system.py, bus.py)
experiments/        experiment scripts and shared helpers (common.py, leakage.py)
tools/ait_fetch.py  dataset fetcher
tests/              unit and end-to-end tests
docs/aws.md         how to run on AWS
results/            curated results per machine
```
