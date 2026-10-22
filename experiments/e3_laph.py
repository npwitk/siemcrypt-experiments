"""Journal Experiment 3: LAPH privacy-utility-cost trade-off (synthetic data).

Systems
  NP    no padding (S)
  FP    fixed padding over real values: one gamma for every entity and resource value,
        gamma chosen on the development stream so that its decoy ratio matches LAPH's
  LAPH  leakage-adaptive pattern hiding (cfg.padding = "laph", default parameters)
  SD    the earlier dummy-token padding (gamma = 2), for reference
Part A  attacks at the matched budget, ten seeds: frequency recovery of U and R tokens,
        overall and per exposure tier (low / medium / high, from the LAPH exposure score of
        the plaintext stream, identical for every system), cross-epoch linkage (overall and
        per tier), decoy distinguisher AUC (0.5 ideal), decoy ratio, cost per event
Part B  budget sweep: LAPH with scaled (gamma_1, gamma_2) and FP with gamma; for every
        setting weights and thresholds are re-learned on the development stream, then
        macro F1 (E1 test stream), recovery, linkage, AUC, delta, HE encryptions, bytes and
        online time per event; offline cost at 2048 bits predicted from E2's T_rand

Usage:  python experiments/e3_laph.py [--quick] [--seeds 10] [--sweep-seeds 3] [--workers 8]
Writes results/e3_laph_attacks.csv, e3_laph_sweep.csv, e3_laph_summary.md.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from collections import defaultdict
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
    run,
    score_alerts,
    siemcrypt_alerts,
    siemcrypt_scores,
    threshold_free,
    write_csv,
)
from e1_accuracy import CLASSES, DEV, TARGET_FPR  # noqa: E402
from e1_accuracy import TEST as E1_TEST  # noqa: E402
from e3_leakage import AUX, TEST  # noqa: E402
from e4_tradeoff import t_rand_2048  # noqa: E402
from leakage import aux_distribution, decoy_distinguisher, frequency_attack, linkage_attack  # noqa: E402

from siemcrypt.laph import exposure_by_epoch  # noqa: E402

TIERS = ("low", "medium", "high")
BUDGET_DEV = replace(TEST, seed=101)
LAPH_GAMMAS = [(1.25, 1.5), (1.5, 2.0), (2.0, 3.0), (3.0, 4.0)]
FP_GAMMAS = [1.25, 1.5, 2.0, 3.0]


def spec(name: str, fp_gamma: float | None = None, laph_gamma=None) -> dict:
    if name == "NP":
        return dict(variant="S")
    if name == "FP":
        return dict(variant="FP", gamma=fp_gamma)
    if name == "LAPH":
        return dict(variant="LAPH", **({"laph_gamma": tuple(laph_gamma)} if laph_gamma else {}))
    if name == "SD":
        return dict(variant="SD")
    raise KeyError(name)


def make_cfg(sp: dict, **kw):
    sp = dict(sp)
    return config(sp.pop("variant"), **sp, **kw)


def decoy_ratio(sp: dict, sc) -> float:
    events, _ = generate(sc)
    s = run(make_cfg(sp, seed=sc.seed), events)
    return s.ee.stats["decoy"] / max(s.ee.stats["real"], 1)


def match_fp_gamma(target: float, workers: int) -> tuple[float, float]:
    """gamma on a 0.05 grid whose FP decoy ratio on the development stream is closest to target."""
    grid = [round(1.05 + 0.05 * i, 2) for i in range(40)]
    with ProcessPoolExecutor(workers) as ex:
        ds = list(ex.map(decoy_ratio, [spec("FP", g) for g in grid], [BUDGET_DEV] * len(grid)))
    g, d = min(zip(grid, ds), key=lambda gd: abs(gd[1] - target))
    return g, d


def tier_of(score: float, cfg) -> str:
    t1, t2 = cfg.laph_theta
    return TIERS[0] if score < t1 else (TIERS[1] if score < t2 else TIERS[2])


def stratify(per_value, exposure, dim: str, cfg) -> dict[str, float | None]:
    hits = defaultdict(list)
    for e, v, ok in per_value:
        hits[tier_of(exposure.get((e, dim, v), 0.0), cfg)].append(ok)
    return {t: (sum(hits[t]) / len(hits[t]) if hits[t] else None) for t in TIERS}


def attacks(name: str, sp: dict, seed: int) -> dict:
    cfg = make_cfg(sp, seed=seed)
    events, _ = generate(replace(TEST, seed=seed))
    aux, _ = generate(AUX)
    s = run(cfg, events)
    st = s.ee.stats
    real = max(st["real"], 1)
    expo = exposure_by_epoch(events, cfg)
    out = dict(system=name, seed=seed, delta=st["decoy"] / real, he_enc_per_event=st["he_enc"] / real,
               bytes_per_event=s.bus.total("ee", "cloud") / real, online_us_per_event=st["t_online"] / real * 1e6)
    for dim in ("U", "R"):
        r = frequency_attack(s, aux_distribution(aux, dim), dim)
        out[f"{dim}_recovery"] = r["token_recovery"]
        out[f"{dim}_volume_recovery"] = r["volume_recovery"]
        for t, v in stratify(r["per_value"], expo, dim, cfg).items():
            out[f"{dim}_recovery_{t}"] = v
    lk = linkage_attack(s)
    out["linkage"] = lk["linkage_accuracy"]
    for t, v in stratify(lk["per_value"], expo, "U", cfg).items():
        out[f"linkage_{t}"] = v
    out["decoy_auc"] = decoy_distinguisher(s)["auc"]
    shares = defaultdict(int)
    for (e, d, v), L in expo.items():
        shares[(d, tier_of(L, cfg))] += 1
    for d in ("U", "R"):
        tot = sum(shares[(d, t)] for t in TIERS)
        for t in TIERS:
            out[f"{d}_share_{t}"] = shares[(d, t)] / max(tot, 1)
    return out


def prepare(sp: dict):
    cfg = make_cfg(sp)
    return calibrate(cfg, DEV, TARGET_FPR, profiles=learn_weights(cfg, DEV))


def sweep_eval(name: str, setting, sp: dict, profiles, seed: int) -> dict:
    cfg = make_cfg(sp, seed=seed, precompute_workers=1)  # offline randomizers timed apart
    events, truth = generate(replace(E1_TEST, seed=seed))
    s = run(cfg, events, profiles)
    st = s.ee.stats
    real = max(st["real"], 1)
    alerts, _ = siemcrypt_alerts(s)
    scores, _ = score_alerts(alerts, truth, CLASSES)
    tf = threshold_free(siemcrypt_scores(s), truth, CLASSES)
    aux, _ = generate(replace(benign(E1_TEST), seed=1001))
    return dict(system=name, setting=str(setting), seed=seed, delta=st["decoy"] / real,
                he_enc_per_event=st["he_enc"] / real, bytes_per_event=s.bus.total("ee", "cloud") / real,
                online_us_per_event=st["t_online"] / real * 1e6, offline_us_per_event=st["t_offline"] / real * 1e6,
                macro_f1=statistics.mean(x.f1 for x in scores.values()),
                macro_auc=statistics.mean(tf[c]["auc"] for c in CLASSES),
                U_recovery=frequency_attack(s, aux_distribution(aux, "U"), "U")["token_recovery"],
                linkage=linkage_attack(s)["linkage_accuracy"], decoy_auc=decoy_distinguisher(s)["auc"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--sweep-seeds", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    seeds = list(range(1, (2 if args.quick else args.seeds) + 1))
    sweep_seeds = list(range(1, (1 if args.quick else args.sweep_seeds) + 1))
    t0 = time.time()

    target = decoy_ratio(spec("LAPH"), BUDGET_DEV)
    fp_gamma, fp_delta = match_fp_gamma(target, args.workers)
    print(f"LAPH delta on dev {target:.3f}; FP gamma {fp_gamma} gives {fp_delta:.3f}", flush=True)
    systems = {"NP": spec("NP"), "FP": spec("FP", fp_gamma), "LAPH": spec("LAPH"), "SD": spec("SD")}
    with ProcessPoolExecutor(args.workers) as ex:
        jobs = [(n, sp, sd) for n, sp in systems.items() for sd in seeds]
        rowsA = list(ex.map(attacks, *zip(*jobs)))
    write_csv("e3_laph_attacks.csv", rowsA)
    print(f"part A done in {time.time() - t0:.0f}s", flush=True)

    settings = [("NP", None, spec("NP"))]
    settings += [("LAPH", g, spec("LAPH", laph_gamma=g)) for g in LAPH_GAMMAS]
    settings += [("FP", g, spec("FP", g)) for g in FP_GAMMAS]
    if args.quick:
        settings = settings[:2] + settings[-1:]
    with ProcessPoolExecutor(args.workers) as ex:
        profs = list(ex.map(prepare, [sp for *_, sp in settings]))
        jobs = [(n, g, sp, pr, sd) for (n, g, sp), pr in zip(settings, profs) for sd in sweep_seeds]
        rowsB = list(ex.map(sweep_eval, *zip(*jobs)))
    t_rand = t_rand_2048()
    for r in rowsB:
        r["pred_offline_ms_per_event_2048"] = r["he_enc_per_event"] * t_rand / 1e3 if t_rand else None
    write_csv("e3_laph_sweep.csv", rowsB)

    md = ["# Journal Experiment 3: LAPH (synthetic data)\n",
          f"Budget matching on the development stream (seed {BUDGET_DEV.seed}): LAPH δ = {target:.3f}, "
          f"FP gamma = {fp_gamma} (δ = {fp_delta:.3f}). LAPH parameters: w = {config('LAPH').laph_w}, "
          f"theta = {config('LAPH').laph_theta}, gamma = {config('LAPH').laph_gamma}.\n",
          f"## Part A: attacks at the matched budget (seeds {seeds}; mean ± sd)\n"]
    colsA = [("delta", "δ"), ("U_recovery", "U recovery"), ("R_recovery", "R recovery"),
             ("linkage", "Linkage"), ("decoy_auc", "Decoy AUC"), ("he_enc_per_event", "HE enc / event"),
             ("bytes_per_event", "Bytes / event")]
    md += ["| System | " + " | ".join(c[1] for c in colsA) + " |", "|---|" + "---|" * len(colsA)]
    for n in systems:
        sel = [r for r in rowsA if r["system"] == n]
        md.append(f"| {n} | " + " | ".join(mean_sd([r[k] for r in sel]) for k, _ in colsA) + " |")
    for title, pre in (("U-token recovery", "U_recovery"), ("R-token recovery", "R_recovery"),
                       ("cross-epoch linkage", "linkage")):
        md += ["", f"### {title} by exposure tier (lower is better)\n",
               "| System | " + " | ".join(TIERS) + " |", "|---|" + "---|" * len(TIERS)]
        for n in systems:
            sel = [r for r in rowsA if r["system"] == n]
            md.append(f"| {n} | " + " | ".join(mean_sd([r[f"{pre}_{t}"] for r in sel]) for t in TIERS) + " |")
    sel = [r for r in rowsA if r["system"] == "NP"]
    md.append("\nShare of values per tier: " + "; ".join(
        f"{d}: " + ", ".join(f"{t} {statistics.mean(r[f'{d}_share_{t}'] for r in sel):.2f}" for t in TIERS)
        for d in ("U", "R")))

    colsB = [("delta", "δ"), ("macro_f1", "Macro F1"), ("macro_auc", "Macro AUC"), ("U_recovery", "U recovery"),
             ("linkage", "Linkage"), ("decoy_auc", "Decoy AUC"), ("he_enc_per_event", "HE enc / event"),
             ("bytes_per_event", "Bytes / event"), ("online_us_per_event", "Online µs / event"),
             ("pred_offline_ms_per_event_2048", "Offline ms / event @2048")]
    md += ["", f"## Part B: budget sweep (E1 streams, seeds {sweep_seeds}; 512-bit keys for online time)\n",
           "| System | Setting | " + " | ".join(c[1] for c in colsB) + " |", "|---|---|" + "---|" * len(colsB)]
    for n, g, _ in settings:
        sel = [r for r in rowsB if r["system"] == n and r["setting"] == str(g)]
        md.append(f"| {n} | {g if g is not None else '-'} | "
                  + " | ".join(mean_sd([r.get(k) for r in sel]) for k, _ in colsB) + " |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e3_laph_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
