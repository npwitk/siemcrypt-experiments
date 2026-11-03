"""D29: cohort-aligned padding against the volume attacks of e3_laph.py, and its effect on detection.

Systems
  NP       no padding
  LAPH-E   epoch-scoped LAPH (D26), gamma = (2, 4)
  CPt-5    D29: AQRS groups of 5 consecutive volume ranks, every member padded to the group
           maximum on its total (padding="cohort", cpad_cats=False)   <- the proposed default
  CP-5     the same, padded per category (exact for category-filtered hunts, about twice the decoys)
Part A  frequency recovery (overall, high-exposure, bucket tie-break), cross-epoch linkage,
        decoy distinguisher AUC, decoy ratio and HE encryptions per event (e3_laph.attacks)
Part B  detection on the E1 test stream: per-class precision / recall at the calibrated
        threshold and threshold-free AUC, weights and thresholds re-learned per system

Usage:  python experiments/e3_d29_padding.py [--seeds 5] [--workers 8]
Writes results/e3_d29_padding.csv and e3_d29_padding.md.
"""

from __future__ import annotations

import argparse
import statistics
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (RESULTS, generate, run, score_alerts, siemcrypt_alerts, siemcrypt_scores,  # noqa: E402
                    threshold_free, write_csv)
from e1_accuracy import CLASSES, TEST  # noqa: E402
from e3_laph import attacks, make_cfg, prepare, spec  # noqa: E402

G = dict(aqrs="fixed", aqrs_fixed_k=5, aqrs_select="partition", padding="cohort")
SYSTEMS = {"NP": spec("NP"), "LAPH-E": spec("LAPH-E"),
           "CPt-5": dict(variant="S", cpad_cats=False, **G), "CP-5": dict(variant="S", **G)}
COLS_A = [("delta", "δ"), ("he_enc_per_event", "HE enc/event"), ("U_recovery", "U recovery"),
          ("U_recovery_high", "high-exposure U"), ("U_recovery_tb_high", "high-exposure U (bucket tie-break)"),
          ("U_recovery_da", "U recovery (decoy-aware)"), ("R_recovery", "R recovery"), ("linkage", "linkage"),
          ("linkage_high", "linkage high"), ("decoy_auc", "decoy AUC")]


def detect(name: str, sp: dict, prof, seed: int) -> dict:
    events, truth = generate(replace(TEST, seed=seed))
    s = run(make_cfg(sp, seed=seed, precompute_workers=1), events, prof)
    al, _ = siemcrypt_alerts(s)
    sc, _ = score_alerts(al, truth, CLASSES)
    tf = threshold_free(siemcrypt_scores(s), truth, CLASSES)
    row = dict(part="B", system=name, seed=seed, macro_f1=statistics.mean(sc[c].f1 for c in CLASSES),
               macro_auc=float(statistics.mean(tf[c]["auc"] for c in CLASSES)))
    for c in CLASSES:
        row.update({f"{c}_p": sc[c].precision, f"{c}_r": sc[c].recall, f"{c}_auc": float(tf[c]["auc"])})
    return row


def mean(rows, k):
    v = [r[k] for r in rows if isinstance(r.get(k), (int, float))]
    return f"{statistics.mean(v):.3f}" if v else "-"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    seeds = range(1, a.seeds + 1)
    with ProcessPoolExecutor(a.workers) as ex:
        rowsA = [dict(part="A", **r) for r in ex.map(attacks, *zip(*[(n, sp, sd) for n, sp in SYSTEMS.items()
                                                                     for sd in seeds]))]
        profs = dict(zip(SYSTEMS, ex.map(prepare, SYSTEMS.values())))
        rowsB = list(ex.map(detect, *zip(*[(n, sp, profs[n], sd) for n, sp in SYSTEMS.items() for sd in seeds])))
    write_csv("e3_d29_padding.csv", rowsA + rowsB)
    md = ["# D29 cohort-aligned padding vs LAPH-E (synthetic data)", "",
          f"Seeds {list(seeds)}; mean. Lower is better for every attack column (decoy AUC: 0.5 ideal).", "",
          "## Part A: volume attacks", "", "| System | " + " | ".join(c[1] for c in COLS_A) + " |",
          "|---" * (len(COLS_A) + 1) + "|"]
    for n in SYSTEMS:
        rs = [r for r in rowsA if r["system"] == n]
        md.append(f"| {n} | " + " | ".join(mean(rs, k) for k, _ in COLS_A) + " |")
    cols_b = [("macro_f1", "macro F1"), ("macro_auc", "macro AUC")] + [
        (f"{c}_{m}", f"{c} {m}") for c in CLASSES for m in ("p", "r", "auc")]
    md += ["", "## Part B: detection (E1 test stream)", "", "| System | " + " | ".join(c[1] for c in cols_b) + " |",
           "|---" * (len(cols_b) + 1) + "|"]
    for n in SYSTEMS:
        rs = [r for r in rowsB if r["system"] == n]
        md.append(f"| {n} | " + " | ".join(mean(rs, k) for k, _ in cols_b) + " |")
    (RESULTS / "e3_d29_padding.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
