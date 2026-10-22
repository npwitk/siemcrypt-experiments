"""Journal Experiment 4: lineage-gated multi-epoch correlation (synthetic data).

Systems: S (full), NoHist (= A2, no historical evidence), FixedDecay (lambda = lambda0, no
drift or risk adaptation), NoContract (explicit per-epoch history; same scores as S),
B1-default (Wazuh-style rules).
Part A  low-and-slow sweep: rate r per epoch x span {3, 6, 12} epochs; recall@FP2 (two benign
        entities may alert), recall and false alarms at the calibrated threshold
Part B  environmental drift d (synthetic generator: per-epoch benign volume +-d and d*n_users
        popularity swaps): recall@FP2 of S, FixedDecay and NoHist for r = 4 over 6 epochs,
        each system re-calibrated on a development stream with the same drift; mean measured
        drift D_e, mean decay lambda and mean retention horizon ell
Part C  historical state: floats and references held in trusted state, and Phase 5 time, per
        processed epoch, S vs NoContract

Usage:  python experiments/e4_temporal.py [--quick] [--seeds 5] [--workers 8]
Writes results/e4_temporal_lns.csv, e4_temporal_drift.csv, e4_temporal_state.csv,
e4_temporal_summary.md.
"""

from __future__ import annotations

import argparse
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
    WAZUH_DEFAULT,
    SynthConfig,
    calibrate,
    config,
    generate,
    learn_weights,
    mean_sd,
    write_csv,
)
from e1_accuracy import DEV, SWEEP, TARGET_FPR, evaluate  # noqa: E402

from siemcrypt.data.synth import default_profiles_and_contexts  # noqa: E402
from siemcrypt.system import SIEMCrypt  # noqa: E402

SYSTEMS_A = ["S", "NoHist", "FixedDecay", "B1-default"]
SYSTEMS_B = ["S", "FixedDecay", "NoHist"]
DRIFTS = [0.0, 0.1, 0.25, 0.5, 1.0]
STATE = SynthConfig(epochs=48, events_per_epoch=300, n_users=80, n_brute_force=0, n_low_and_slow=2,
                    n_exfil=1, lns_epochs=12)


def prepare(system: str, drift: float = 0.0):
    if system == "B1-default":
        return WAZUH_DEFAULT
    cfg = config(system)
    dev = replace(DEV, drift=drift)
    return calibrate(cfg, dev, TARGET_FPR, profiles=learn_weights(cfg, dev))


def drift_eval(system: str, drift: float, params, seed: int) -> dict:
    from common import run, score_alerts, siemcrypt_alerts, siemcrypt_scores, threshold_free

    sc = replace(SWEEP, seed=seed, lns_per_epoch=4, lns_epochs=6, drift=drift)
    events, truth = generate(sc)
    s = run(config(system), events, params)
    alerts, _ = siemcrypt_alerts(s)
    x = score_alerts(alerts, truth, ["cred_access"])[0]["cred_access"]
    tf = threshold_free(siemcrypt_scores(s), truth, ["cred_access"])["cred_access"]
    hz = s.ee.horizon_log
    att = {gt.user for gt in truth}
    return dict(system=system, drift=drift, seed=seed, recall_at_fp2=tf["recall_at_fp"], auc=tf["auc"],
                recall=x.recall, false_pairs=x.alerted_pairs - x.true_pairs,
                measured_drift=statistics.mean(r.drift for r in s.reports[1:]),
                mean_lambda=statistics.mean(r[4] for r in hz), mean_horizon=statistics.mean(r[3] for r in hz),
                attacker_horizon=statistics.mean([r[3] for r in hz if r[1] in att] or [float("nan")]))


def state_run(system: str, seed: int) -> list[dict]:
    events, _ = generate(replace(STATE, seed=seed))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(config(system, seed=seed), profiles, contexts)
    by_epoch = {}
    for ev in events:
        by_epoch.setdefault(s.epoch_of(ev.ts), []).append(ev)
    rows = []
    for e in sorted(by_epoch):
        t5 = s.timing["phase5"]
        s.run_epoch(e, by_epoch[e])
        rows.append(dict(system=system, seed=seed, epoch=e, state_size=s.ee.state_size(), pairs=len(s.ee.state),
                         phase5_ms=(s.timing["phase5"] - t5) * 1e3))
    s.close()
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    seeds = list(range(1, (2 if args.quick else args.seeds) + 1))
    rates = [2, 4, 8] if args.quick else [1, 2, 4, 6, 8, 12, 16, 20]
    spans = [6] if args.quick else [3, 6, 12]
    drifts = [0.0, 0.5] if args.quick else DRIFTS
    t0 = time.time()
    with ProcessPoolExecutor(args.workers) as ex:
        params = dict(zip(SYSTEMS_A, ex.map(prepare, SYSTEMS_A)))
        jobs = [(sy, params[sy], replace(SWEEP, seed=sd, lns_per_epoch=r, lns_epochs=sp))
                for sy in SYSTEMS_A for r in rates for sp in spans for sd in seeds]
        resA = list(ex.map(evaluate, *zip(*jobs)))
        print(f"part A done in {time.time() - t0:.0f}s", flush=True)
        dkeys = [(sy, d) for sy in SYSTEMS_B for d in drifts]
        dparams = dict(zip(dkeys, ex.map(prepare, *zip(*dkeys))))
        jobsB = [(sy, d, dparams[(sy, d)], sd) for sy, d in dkeys for sd in seeds]
        resB = list(ex.map(drift_eval, *zip(*jobsB)))
        print(f"part B done in {time.time() - t0:.0f}s", flush=True)
        jobsC = [(sy, sd) for sy in ("S", "NoContract") for sd in seeds[:3]]
        resC = [r for rows in ex.map(state_run, *zip(*jobsC)) for r in rows]
        print(f"part C done in {time.time() - t0:.0f}s", flush=True)

    rowsA = []
    for (sy, _, sc), r in zip(jobs, resA):
        x = r["scores"]["cred_access"]
        rowsA.append(dict(system=sy, rate=sc.lns_per_epoch, span=sc.lns_epochs, seed=sc.seed, recall=x.recall,
                          false_pairs=x.alerted_pairs - x.true_pairs, auc=r["tf"]["cred_access"]["auc"],
                          recall_at_fp2=r["tf"]["cred_access"]["recall_at_fp"]))
    write_csv("e4_temporal_lns.csv", rowsA)
    write_csv("e4_temporal_drift.csv", resB)
    write_csv("e4_temporal_state.csv", resC)

    md = ["# Journal Experiment 4: multi-epoch correlation (synthetic data)\n", f"Seeds {seeds}.\n"]
    for key, title in (("recall_at_fp2", "recall@FP2"), ("recall", "recall at the calibrated threshold"),
                       ("false_pairs", "falsely alerted benign entities")):
        md += ["", f"## Part A: low-and-slow, {title}\n"]
        for sp in spans:
            md += [f"\nSpan {sp} epochs\n", "| System | " + " | ".join(f"r={r}" for r in rates) + " |",
                   "|---|" + "---|" * len(rates)]
            for sy in SYSTEMS_A:
                cells = [f"{statistics.mean(x[key] for x in rowsA if x['system'] == sy and x['rate'] == r and x['span'] == sp):.2f}"
                         for r in rates]
                md.append(f"| {sy} | " + " | ".join(cells) + " |")
    cols = [("recall_at_fp2", "Recall@FP2"), ("auc", "AUC"), ("recall", "Recall"), ("false_pairs", "False alerts"),
            ("measured_drift", "Mean D_e"), ("mean_lambda", "Mean λ"), ("mean_horizon", "Mean ℓ (epochs)"),
            ("attacker_horizon", "Attacker ℓ")]
    md += ["", "## Part B: drift (r = 4, span 6)\n", "| System | Drift | " + " | ".join(c[1] for c in cols) + " |",
           "|---|---|" + "---|" * len(cols)]
    for sy, d in dkeys:
        sel = [r for r in resB if r["system"] == sy and r["drift"] == d]
        md.append(f"| {sy} | {d} | " + " | ".join(mean_sd([r[k] for r in sel]) for k, _ in cols) + " |")
    md += ["", f"## Part C: trusted historical state over {STATE.epochs} epochs\n",
           "| Epoch | S state | NoContract state | S Phase 5 (ms) | NoContract Phase 5 (ms) |", "|---|---|---|---|---|"]
    for e in [1, 6, 12, 24, 36, 48]:
        cell = []
        for k in ("state_size", "phase5_ms"):
            for sy in ("S", "NoContract"):
                sel = [r[k] for r in resC if r["system"] == sy and r["epoch"] == e]
                cell.append(f"{statistics.mean(sel):,.1f}" if sel else "-")
        md.append(f"| {e} | {cell[0]} | {cell[1]} | {cell[2]} | {cell[3]} |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e4_temporal_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
