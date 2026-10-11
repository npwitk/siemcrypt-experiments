"""E4: privacy-utility-cost trade-off (DS2 Section "Experiment 4", RQ4).

One-at-a-time sweeps around the default (gamma=1 i.e. no decoys, epoch 60 min, k_min=3):
  gamma   in {1, 1.5, 2, 3, 4}
  epoch   in {15, 60, 240} minutes
  k_min   in {1, 3, 5, 10}
For every setting, weights and thresholds are re-learned and re-calibrated on the
development stream, then each test seed is run once. Measures:
  cost     decoy ratio delta, HE encryptions per real event, EE online and offline time
           per event (at the experiment key size), bytes EE->cloud per real event, and the
           offline randomizer cost per event predicted at 2048 bits from E2's T_rand
  utility  macro F1, mean detection delay (hours)
  privacy  U-token frequency recovery, decoy-distinguisher AUC, cross-epoch linkage,
           single-record VALUE releases under per-entity contexts (k_min sweep)

Usage:  python experiments/e4_tradeoff.py [--quick] [--seeds 3] [--workers 8]
Writes results/e4_tradeoff.csv and e4_summary.md.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    RESULTS,
    benign,
    calibrate,
    config,
    generate,
    learn_weights,
    mean_sd,
    remap_truth,
    run,
    score_alerts,
    siemcrypt_alerts,
    write_csv,
)
from e1_accuracy import CLASSES, DEV, TARGET_FPR, TEST  # noqa: E402
from e3_leakage import release_attacks  # noqa: E402
from leakage import aux_distribution, decoy_distinguisher, frequency_attack, linkage_attack  # noqa: E402

SWEEPS = {
    "gamma": [1.0, 1.5, 2.0, 3.0, 4.0],
    "epoch_len": [900.0, 3600.0, 14400.0],
    "k_min": [1, 3, 5, 10],
}


def t_rand_2048() -> float | None:
    """Offline randomizer time (us) from E2, if E2 was run at 2048 bits on this machine."""
    path = RESULTS / "e2_microbench.csv"
    if not path.exists():
        return None
    rows = list(csv.reader(path.open()))
    bits = next((r[1] for r in rows if r and r[0] == "paillier_bits"), None)
    if bits != "2048":
        return None
    return next((float(r[2]) for r in rows if r and r[0] == "T_rand (offline)"), None)


def prepare(param: str, value) -> list:
    cfg = config("S", **{param: value})
    return calibrate(cfg, DEV, TARGET_FPR, profiles=learn_weights(cfg, DEV))


def evaluate(param: str, value, profiles, seed: int) -> dict:
    cfg = config("S", **{param: value}, seed=seed, precompute_workers=1)  # offline timed apart
    sc = replace(TEST, seed=seed)
    events, truth = generate(sc)
    truth = remap_truth(truth, sc.epoch_len, cfg.epoch_len)
    s = run(cfg, events, profiles)
    st = s.ee.stats
    real = max(st["real"], 1)
    alerts, _ = siemcrypt_alerts(s)
    scores, _ = score_alerts(alerts, truth, CLASSES)
    f1 = statistics.mean(x.f1 for x in scores.values())
    delays = [x.mean_delay for x in scores.values() if x.mean_delay is not None]
    aux, _ = generate(replace(benign(TEST), seed=1001))
    out = dict(param=param, value=value, seed=seed,
               delta=st["decoy"] / real, he_enc_per_event=st["he_enc"] / real,
               online_us_per_event=st["t_online"] / real * 1e6,
               offline_us_per_event=st["t_offline"] / real * 1e6,
               bytes_per_event=s.bus.total("ee", "cloud") / real,
               macro_f1=f1, delay_hours=statistics.mean(delays) * cfg.epoch_len / 3600 if delays else None,
               U_token_recovery=frequency_attack(s, aux_distribution(aux, "U"), "U")["token_recovery"],
               decoy_auc=decoy_distinguisher(s)["auc"],
               linkage_accuracy=linkage_attack(s)["linkage_accuracy"])
    if param == "k_min":
        out["single_record_releases"] = release_attacks("S", seed, k_min=value)["single_record_value_releases"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    seeds = list(range(1, (1 if args.quick else args.seeds) + 1))
    settings = [(p, v) for p, vs in SWEEPS.items() for v in vs]
    t0 = time.time()
    with ProcessPoolExecutor(args.workers) as ex:
        profs = dict(zip(settings, ex.map(prepare, *zip(*settings))))
        print(f"calibrated {len(settings)} settings in {time.time() - t0:.0f}s", flush=True)
        jobs = [(p, v, profs[(p, v)], sd) for p, v in settings for sd in seeds]
        rows = list(ex.map(evaluate, *zip(*jobs)))
    t_rand = t_rand_2048()
    for r in rows:
        r["pred_offline_ms_per_event_2048"] = r["he_enc_per_event"] * t_rand / 1e3 if t_rand else None
    write_csv("e4_tradeoff.csv", rows)

    cols = [("delta", "δ"), ("he_enc_per_event", "HE enc / event"), ("online_us_per_event", "Online µs / event"),
            ("offline_us_per_event", "Offline µs / event"), ("pred_offline_ms_per_event_2048", "Offline ms / event @2048"),
            ("bytes_per_event", "Bytes / event"), ("macro_f1", "Macro F1"), ("delay_hours", "Delay (h)"),
            ("U_token_recovery", "U recovery"), ("decoy_auc", "Decoy AUC"), ("linkage_accuracy", "Linkage"),
            ("single_record_releases", "Single-record releases")]
    md = ["# E4 results (synthetic data, 512-bit keys unless noted)\n",
          f"Seeds {seeds}; one-at-a-time sweeps around gamma=1 (no decoys), epoch=60 min, k_min=3.",
          "2048-bit offline cost is predicted from E2's T_rand when results/e2_microbench.csv is a 2048-bit run.\n"]
    for p, vs in SWEEPS.items():
        use = [c for c in cols if any(r.get(c[0]) is not None for r in rows if r["param"] == p)]
        md += [f"\n## {p}\n", f"| {p} | " + " | ".join(c[1] for c in use) + " |", "|---|" + "---|" * len(use)]
        for v in vs:
            sel = [r for r in rows if r["param"] == p and r["value"] == v]
            md.append(f"| {v} | " + " | ".join(mean_sd([r.get(k) for r in sel]) for k, _ in use) + " |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e4_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
