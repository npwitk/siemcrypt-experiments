"""E1: detection accuracy and time to detect (DS2 Section "Experiment 1", RQ1).

Part A  all attack families, systems S, SD, B2, A2, A3, B1-default, B1-tuned, several seeds:
        precision / recall / F1 per class, detection delay, screening contribution, exact
        McNemar tests of S against each system on identical incidents (Holm-adjusted).
Part B  low-and-slow sweep: recall and delay vs. rate r (failed logins per epoch) and span.

Weights theta are learned and thresholds Theta calibrated per system on development
streams (different seeds) before any test run, then frozen.
Accuracy does not depend on the Paillier key size (releases are exact; tested), so 512-bit
keys are used here; timings come from E2/E4 at 2048 bits.

Usage:  python experiments/e1_accuracy.py [--quick] [--workers 8]
Writes results/e1_main.csv, e1_incidents.csv, e1_lns_sweep.csv, e1_summary.md.
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
    WAZUH_DEFAULT,
    SynthConfig,
    calibrate,
    calibrate_rules,
    config,
    generate,
    learn_weights,
    mean_sd,
    rule_alerts,
    rule_scores,
    run,
    score_alerts,
    siemcrypt_alerts,
    siemcrypt_scores,
    threshold_free,
    write_csv,
)

CLASSES = ["cred_access", "exfil", "multi_source"]
SIEMCRYPT_SYSTEMS = ["S", "SD", "B2", "A2", "A3"]
RULE_SYSTEMS = ["B1-default", "B1-tuned"]
TARGET_FPR = 0.005

DEV = SynthConfig(epochs=12, events_per_epoch=600, n_users=80, seed=101, n_brute_force=2,
                  n_low_and_slow=4, n_exfil=2, n_coordinated=3, lns_epochs=6)
TEST = SynthConfig(epochs=12, events_per_epoch=600, n_users=80, n_brute_force=2,
                   n_low_and_slow=2, n_exfil=1, n_coordinated=2, lns_epochs=6)
SWEEP = SynthConfig(epochs=16, events_per_epoch=600, n_users=80, n_brute_force=0,
                    n_low_and_slow=3, n_exfil=0, n_coordinated=0)


def prepare(system: str):
    """Frozen per-system parameters from the development streams."""
    if system == "B1-default":
        return WAZUH_DEFAULT
    if system == "B1-tuned":
        return calibrate_rules(DEV, timeframe=DEV.epoch_len, target_fpr=TARGET_FPR)
    cfg = config(system)
    return calibrate(cfg, DEV, TARGET_FPR, profiles=learn_weights(cfg, DEV))


def evaluate(system: str, params, sc: SynthConfig) -> dict:
    events, truth = generate(sc)
    unl = set()
    if system.startswith("B1"):
        alerts = rule_alerts(events, params, sc.epoch_len)
        raw = rule_scores(events, params, sc.epoch_len)
    else:
        s = run(config(system), events, params)
        alerts, unl = siemcrypt_alerts(s)
        raw = siemcrypt_scores(s)
    scores, per = score_alerts(alerts, truth, CLASSES)
    tf = threshold_free(raw, truth, CLASSES)
    # screening: incidents whose user gets an unclassified alert inside the span
    scr = {gt.attack_id: int(any((gt.user, e) in unl for e in gt.epochs)) for gt in truth}
    attackers = {gt.user for gt in truth}
    unl_users = {u for u, _ in unl}
    return dict(system=system, seed=sc.seed, scores=scores, per=per, screen=scr, tf=tf,
                kinds={gt.attack_id: gt.kind for gt in truth},
                unl_alerts=len(unl), unl_users=len(unl_users), unl_attack_users=len(unl_users & attackers))


def mcnemar_holm(per_sys: dict[str, dict], ref: str = "S") -> dict[str, tuple[int, int, float, float]]:
    from scipy.stats import binomtest

    raw = {}
    for name, det in per_sys.items():
        if name == ref:
            continue
        b = sum(1 for k in det if per_sys[ref][k] and not det[k])
        c = sum(1 for k in det if det[k] and not per_sys[ref][k])
        raw[name] = (b, c, binomtest(b, b + c, 0.5).pvalue if b + c else 1.0)
    order = sorted(raw, key=lambda k: raw[k][2])
    out, m, running = {}, len(order), 0.0
    for i, name in enumerate(order):
        running = max(running, min(1.0, (m - i) * raw[name][2]))
        out[name] = (*raw[name], running)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seeds", type=int, default=5)
    args = ap.parse_args()
    seeds = list(range(1, (2 if args.quick else args.seeds) + 1))
    rates = [2, 8, 16] if args.quick else [1, 2, 4, 6, 8, 12, 16, 20]
    spans = [6] if args.quick else [3, 6, 12]
    systems = SIEMCRYPT_SYSTEMS + RULE_SYSTEMS
    t0 = time.time()

    with ProcessPoolExecutor(args.workers) as ex:
        params = dict(zip(systems, ex.map(prepare, systems)))
        print(f"calibrated {len(systems)} systems in {time.time() - t0:.0f}s", flush=True)

        # ---------------- Part A
        jobs = [(sy, params[sy], replace(TEST, seed=sd)) for sy in systems for sd in seeds]
        resA = list(ex.map(evaluate, *zip(*jobs)))
        print(f"part A done in {time.time() - t0:.0f}s", flush=True)

        # ---------------- Part B
        sweep_sys = ["S", "SD", "B2", "A2", "B1-default", "B1-tuned"]
        jobsB = [(sy, params[sy], replace(SWEEP, seed=sd, lns_per_epoch=r, lns_epochs=sp))
                 for sy in sweep_sys for r in rates for sp in spans for sd in seeds]
        resB = list(ex.map(evaluate, *zip(*jobsB)))
        print(f"part B done in {time.time() - t0:.0f}s", flush=True)

    # ---------------- outputs A
    rows, inc_rows = [], []
    for r in resA:
        for c, x in r["scores"].items():
            rows.append(dict(system=r["system"], seed=r["seed"], attack_class=c, incidents=x.incidents,
                             detected=x.detected, alerted_pairs=x.alerted_pairs, true_pairs=x.true_pairs,
                             precision=x.precision, recall=x.recall, f1=x.f1, mean_delay=x.mean_delay,
                             auc=r["tf"][c]["auc"], recall_at_fp2=r["tf"][c]["recall_at_fp"]))
        for aid, (det, delay) in r["per"].items():
            inc_rows.append(dict(system=r["system"], seed=r["seed"], attack_id=aid, kind=r["kinds"][aid],
                                 detected=det, delay=delay, screening_hit=r["screen"][aid]))
    write_csv("e1_main.csv", rows)
    write_csv("e1_incidents.csv", inc_rows)

    import platform

    md = [f"# E1 results (synthetic data; {platform.node()}, {platform.platform()})\n",
          f"Seeds {seeds}; target benign FPR {TARGET_FPR} per (entity, epoch) on development streams.\n",
          "## Part A: per-class detection (mean ± sd over seeds)\n",
          "| System | Class | Precision | Recall | F1 | Delay (epochs) |", "|---|---|---|---|---|---|"]
    for sy in systems:
        for c in CLASSES:
            sel = [x for x in rows if x["system"] == sy and x["attack_class"] == c]
            md.append(f"| {sy} | {c} | {mean_sd([x['precision'] for x in sel])} | "
                      f"{mean_sd([x['recall'] for x in sel])} | {mean_sd([x['f1'] for x in sel])} | "
                      f"{mean_sd([x['mean_delay'] for x in sel])} |")
    md += ["", "| System | Macro F1 |", "|---|---|"]
    for sy in systems:
        f1s = [statistics.mean([x["f1"] for x in rows if x["system"] == sy and x["seed"] == sd])
               for sd in seeds]
        md.append(f"| {sy} | {mean_sd(f1s)} |")

    md += ["", "## Threshold-free comparison (independent of the calibrated operating point)\n",
           "AUC over (entity, epoch) scores; recall@FP2 = incident recall when exactly two benign "
           "entities are allowed to alert. B1 scores are the largest rule window count.\n",
           "| System | " + " | ".join(f"{c} AUC | {c} recall@FP2" for c in CLASSES) + " |",
           "|---|" + "---|---|" * len(CLASSES)]
    for sy in systems:
        cells = []
        for c in CLASSES:
            sel = [x for x in rows if x["system"] == sy and x["attack_class"] == c]
            cells += [mean_sd([x["auc"] for x in sel]), mean_sd([x["recall_at_fp2"] for x in sel])]
        md.append(f"| {sy} | " + " | ".join(cells) + " |")

    per_sys = defaultdict(dict)
    for r in inc_rows:
        per_sys[r["system"]][(r["seed"], r["attack_id"])] = r["detected"]
    md += ["", "## McNemar (exact) of S vs. each system on identical incidents, Holm-adjusted\n",
           "| System | S only | system only | p | p (Holm) |", "|---|---|---|---|---|"]
    for name, (b, c, p, ph) in sorted(mcnemar_holm(per_sys).items()):
        md.append(f"| {name} | {b} | {c} | {p:.3g} | {ph:.3g} |")

    md += ["", "## Screening path (S has screening; A3 does not)\n",
           "| System | Unclassified alerts / run | Entities / run | Attacker entities / run | "
           "Incidents hit by screening | Found only by screening |", "|---|---|---|---|---|---|"]
    for sy in ("S", "A3"):
        sel = [r for r in resA if r["system"] == sy]
        hit = sum(sum(r["screen"].values()) for r in sel)
        only = sum(1 for r in sel for k, v in r["screen"].items() if v and not r["per"][k][0])
        tot = sum(len(r["per"]) for r in sel)
        md.append(f"| {sy} | {statistics.mean(r['unl_alerts'] for r in sel):.1f} | "
                  f"{statistics.mean(r['unl_users'] for r in sel):.1f} | "
                  f"{statistics.mean(r['unl_attack_users'] for r in sel):.1f} | {hit}/{tot} | {only} |")

    # ---------------- outputs B
    rowsB = []
    for (sy, _, sc), r in zip(jobsB, resB):
        x = r["scores"]["cred_access"]
        rowsB.append(dict(system=sy, rate=sc.lns_per_epoch, span=sc.lns_epochs, seed=sc.seed,
                          recall=x.recall, precision=x.precision, false_pairs=x.alerted_pairs - x.true_pairs,
                          mean_delay=x.mean_delay, auc=r["tf"]["cred_access"]["auc"],
                          recall_at_fp2=r["tf"]["cred_access"]["recall_at_fp"]))
    write_csv("e1_lns_sweep.csv", rowsB)
    for key, title in (("recall", "recall at the calibrated threshold"),
                       ("false_pairs", "falsely alerted benign entities at the calibrated threshold"),
                       ("recall_at_fp2", "recall@FP2 (threshold-free)")):
        md += ["", f"## Part B: low-and-slow, {title} (mean over seeds) by rate r per epoch\n"]
        for sp in spans:
            md += [f"\nSpan {sp} epochs\n", "| System | " + " | ".join(f"r={r}" for r in rates) + " |",
                   "|---|" + "---|" * len(rates)]
            for sy in sweep_sys:
                cells = []
                for r in rates:
                    sel = [x for x in rowsB if x["system"] == sy and x["rate"] == r and x["span"] == sp]
                    cells.append(f"{statistics.mean(x[key] for x in sel):.2f}")
                md.append(f"| {sy} | " + " | ".join(cells) + " |")

    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e1_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
