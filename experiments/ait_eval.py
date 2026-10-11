"""E1, E2 and E3 on real data: AIT Log Data Set V2.0 (DS2 Section "Evaluation Protocol").

Split by scenario (no scenario contributes to both parts):
  development  russellmitchell, santos, fox     learn theta, calibrate Theta and B1-tuned
  test         harrison, wardbeck, shaw, wheeler, wilson
Development runs also contain one injected low-and-slow attack per family (rate 8, span 12),
so that weights can be learned for slow attacks.

Parts
  e1  A: the real attack chains of the test scenarios, per class (recon, web_attack,
         priv_esc, dns_exfil): calibrated precision/recall/F1 and threshold-free AUC and
         recall@FP2; systems S, SD, B2, A2, B1-default, B1-tuned
      B: low-and-slow DNS exfiltration and slow web scanning injected into the clean
         background of a test scenario, rate r per epoch for `span` epochs: recall, false
         alarms, recall@FP2 (the real-data test of multi-epoch correlation)
  e3  leakage on days 2-4 of each test scenario; the adversary's prior is day 1 of the
      same scenario; systems S, SD, A4, SD+A4
  e2  2048-bit throughput and bytes per event on the first day of one test scenario

Thresholds are calibrated to an alert budget (benign (entity, epoch) alerts per class per
day on the development scenarios), which is how a SOC sizes alert volume.

Usage:  python experiments/ait_eval.py [--parts e1,e3,e2] [--quick] [--workers 8]
                                       [--data ~/data/ait-ldsv2]
"""

from __future__ import annotations

import argparse
import math
import platform
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
    FreqRule,
    config,
    fit_weights,
    mean_sd,
    rule_alerts,
    rule_scores,
    run,
    score_alerts,
    siemcrypt_alerts,
    siemcrypt_scores,
    theta_for_budget,
    threshold_free,
    write_csv,
)
from leakage import aux_distribution, decoy_distinguisher, frequency_attack, linkage_attack  # noqa: E402

from siemcrypt.data.ait import (  # noqa: E402
    CLASSES,
    INJECT_FAMILIES,
    ait_profiles_and_contexts,
    attack_entities,
    benign_background,
    inject,
    load_scenario,
)

DEV = ["russellmitchell", "santos", "fox"]
TEST = ["harrison", "wardbeck", "shaw", "wheeler", "wilson"]
SYSTEMS = ["S", "SD", "B2", "A2"]
ALERTS_PER_DAY = 2          # benign alert budget per class per day (development scenarios)
EPOCH = 3600.0
DATA = Path.home() / "data" / "ait-ldsv2"


# ============================================================================ data
def scenario(name: str, max_epoch: int | None = None):
    ev, truth, meta = load_scenario(DATA / name, EPOCH)
    if max_epoch is not None:
        ev = [e for e in ev if e.ts < max_epoch * EPOCH]
        truth = [replace(gt, epochs=[x for x in gt.epochs if x <= max_epoch]) for gt in truth]
        truth = [gt for gt in truth if gt.epochs]
    return ev, truth, meta


def dev_stream(name: str, max_epoch: int | None):
    """A development scenario plus one injected slow attack per family."""
    ev, truth, meta = scenario(name, max_epoch)
    n_ep = max_epoch or meta["epochs"]
    for k, fam in enumerate(sorted(INJECT_FAMILIES)):
        start = max(1, n_ep // 4 + 6 * k)
        ev, gt = inject(ev, fam, 8, min(12, n_ep - start), start, seed=100 + k, epoch_len=EPOCH)
        truth = truth + [gt]
    return ev, truth, n_ep


# ============================================================================ workers
def w_dev(system: str, profiles, name: str, max_epoch: int | None):
    ev, truth, n_ep = dev_stream(name, max_epoch)
    _, contexts = ait_profiles_and_contexts()
    s = run(config(system), ev, profiles, contexts)
    pos = {(gt.user, gt.attack_class, e) for gt in truth for e in gt.epochs}
    bad = attack_entities(ev)
    return s.ee.score_log, pos, bad, n_ep


def w_test(system: str, params, name: str, max_epoch: int | None):
    ev, truth, meta = scenario(name, max_epoch)
    unl = set()
    if system.startswith("B1"):
        alerts, raw = rule_alerts(ev, params, EPOCH), rule_scores(ev, params, EPOCH)
    else:
        _, contexts = ait_profiles_and_contexts()
        s = run(config(system), ev, params, contexts)
        alerts, unl = siemcrypt_alerts(s)
        raw = siemcrypt_scores(s)
    scores, per = score_alerts(alerts, truth, CLASSES)
    return dict(system=system, scenario=name, scores=scores, per=per, tf=threshold_free(raw, truth, CLASSES),
                kinds={gt.attack_id: gt.attack_class for gt in truth}, events=len(ev),
                unl_users=len({u for u, _ in unl}))


def w_inject(system: str, params, name: str, family: str, rate: int, span: int, max_epoch: int, seed: int):
    ev, _, _ = scenario(name, max_epoch)
    bg = benign_background(ev)
    start = max(1, (max_epoch - span) // 2)
    ev2, gt = inject(bg, family, rate, span, start, seed=seed, epoch_len=EPOCH)
    if system.startswith("B1"):
        alerts, raw = rule_alerts(ev2, params, EPOCH), rule_scores(ev2, params, EPOCH)
    else:
        _, contexts = ait_profiles_and_contexts()
        s = run(config(system), ev2, params, contexts)
        alerts, _ = siemcrypt_alerts(s)
        raw = siemcrypt_scores(s)
    sc, per = score_alerts(alerts, [gt], [family])
    x = sc[family]
    tf = threshold_free(raw, [gt], [family])[family]
    return dict(system=system, family=family, rate=rate, span=span, seed=seed, recall=x.recall,
                false_entities=x.alerted_pairs - x.true_pairs, delay=x.mean_delay, recall_at_fp2=tf["recall_at_fp"])


def w_leak(name_sys: str, scen: str, max_epoch: int | None):
    from siemcrypt.data.ait import load_scenario as _ls  # noqa: F401

    variant, persistent = {"S": ("S", False), "SD": ("SD", False), "A4": ("S", True), "SD+A4": ("SD", True)}[name_sys]
    ev, _, _ = scenario(scen, max_epoch)
    day = 24 * EPOCH
    aux, target = [e for e in ev if e.ts < day], [e for e in ev if e.ts >= day]
    _, contexts = ait_profiles_and_contexts()
    s = run(config(variant, persistent_tokens=persistent), target, None, contexts)
    out = dict(system=name_sys, scenario=scen, decoy_ratio=s.ee.stats["decoy"] / max(s.ee.stats["real"], 1))
    for dim in ("U", "R"):
        r = frequency_attack(s, aux_distribution(aux, dim), dim, cumulative=persistent)
        out[f"{dim}_token_recovery"], out[f"{dim}_volume_recovery"] = r["token_recovery"], r["volume_recovery"]
    d = decoy_distinguisher(s)
    lk = linkage_attack(s)
    out.update(decoy_auc=d["auc"], linkage_accuracy=lk["linkage_accuracy"], linkage_chance=lk["chance"])
    return out


# ============================================================================ calibration
def calibrate_all(ex, systems, max_epoch):
    p0, _ = ait_profiles_and_contexts()
    profiles = {sy: p0 for sy in systems}
    days = None
    for step in ("learn", "theta", "theta"):
        jobs = [(sy, profiles[sy], sc, max_epoch) for sy in systems for sc in DEV]
        res = list(ex.map(w_dev, *zip(*jobs)))
        by_sys = defaultdict(list)
        for (sy, *_), r in zip(jobs, res):
            by_sys[sy].append(r)
        for sy in systems:
            runs = by_sys[sy]
            if step == "learn":
                profiles[sy] = fit_weights([(log, pos) for log, pos, _, _ in runs], profiles[sy],
                                           history=config(sy).history)
            else:
                days = sum(n for *_, n in runs) / 24
                allowed = math.floor(ALERTS_PER_DAY * days)
                profiles[sy] = theta_for_budget([(log, bad) for log, _, bad, _ in runs], profiles[sy], allowed)
        print(f"  calibration step {step} done", flush=True)
    return profiles


def rules(max_epoch):
    p, _ = ait_profiles_and_contexts()
    default = [FreqRule(x.name, x.categories, 14 if x.name == "recon" else 8, 90.0 if x.name == "recon" else 120.0)
               for x in p]
    # tuned: one-hour window, smallest frequency within the same alert budget on development data
    devs = [dev_stream(sc, max_epoch) for sc in DEV]
    allowed = math.floor(ALERTS_PER_DAY * sum(n for *_, n in devs) / 24)
    tuned = []
    for r in default:
        f = 2
        while True:
            rr = replace(r, frequency=f, timeframe=EPOCH)
            n = sum(len({a for a in rule_alerts(ev, [rr], EPOCH) if a[0] not in attack_entities(ev)})
                    for ev, _, _ in devs)
            if n <= allowed:
                break
            f += 1
        tuned.append(rr)
    return default, tuned


# ============================================================================ main
def main() -> None:
    global DATA, DEV, TEST
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", default="e1,e3,e2")
    ap.add_argument("--quick", action="store_true", help="first 24 epochs, 1 test scenario, few rates")
    ap.add_argument("--workers", type=int, default=8, help="workers for windowed jobs (injection sweep)")
    ap.add_argument("--heavy-workers", type=int, default=3,
                    help="workers for full-scenario jobs; each needs up to ~10 GB (32 GB VM: 3)")
    ap.add_argument("--data", default=str(DATA))
    ap.add_argument("--dev", default=",".join(DEV), help="development scenarios (comma separated)")
    ap.add_argument("--test", default=",".join(TEST), help="test scenarios (comma separated)")
    args = ap.parse_args()
    DEV, TEST = args.dev.split(","), args.test.split(",")
    if set(DEV) & set(TEST):
        print(f"WARNING: scenarios in both development and test: {set(DEV) & set(TEST)} (smoke test only)")
    DATA = Path(args.data).expanduser()
    parts = set(args.parts.split(","))
    max_ep = 24 if args.quick else None
    tests = TEST[:1] if args.quick else TEST
    t0 = time.time()
    md = [f"# AIT-LDSv2 results ({platform.node()}, {platform.platform()})\n",
          f"Development: {', '.join(DEV)}; test: {', '.join(tests)}; "
          f"{'first 24 epochs only (quick)' if args.quick else 'full scenarios'}; "
          f"alert budget {ALERTS_PER_DAY} benign alerts per class per day.\n"]
    missing = [s for s in DEV + tests if not (DATA / s / "dataset.yaml").exists()]
    if missing:
        sys.exit(f"missing scenarios {missing}: run tools/ait_fetch.py first")
    for sc in DEV + tests:  # build the event caches once, before the workers start
        load_scenario(DATA / sc, EPOCH)

    heavy = args.workers if args.quick else args.heavy_workers
    with ProcessPoolExecutor(heavy) as ex, ProcessPoolExecutor(args.workers) as light:
        if "e1" in parts:
            prof = calibrate_all(ex, SYSTEMS, max_ep)
            b1d, b1t = rules(max_ep)
            params = {**prof, "B1-default": b1d, "B1-tuned": b1t}
            systems = SYSTEMS + ["B1-default", "B1-tuned"]
            print(f"calibrated in {time.time() - t0:.0f}s", flush=True)

            jobs = [(sy, params[sy], sc, max_ep) for sy in systems for sc in tests]
            resA = list(ex.map(w_test, *zip(*jobs)))
            rows, inc = [], []
            for r in resA:
                for c, x in r["scores"].items():
                    rows.append(dict(system=r["system"], scenario=r["scenario"], attack_class=c, incidents=x.incidents,
                                     detected=x.detected, false_entities=x.alerted_pairs - x.true_pairs,
                                     precision=x.precision, recall=x.recall, f1=x.f1, delay=x.mean_delay,
                                     auc=r["tf"][c]["auc"], recall_at_fp2=r["tf"][c]["recall_at_fp"]))
                for aid, (d, delay) in r["per"].items():
                    inc.append(dict(system=r["system"], scenario=r["scenario"], incident=aid,
                                    attack_class=r["kinds"][aid], detected=d, delay=delay))
            write_csv("ait_e1_main.csv", rows)
            write_csv("ait_e1_incidents.csv", inc)
            md += ["## E1-A: real attack chains (pooled over test scenarios)\n",
                   "| System | Class | Incidents | Detected | False entities | AUC | Recall@FP2 |",
                   "|---|---|---|---|---|---|---|"]
            for sy in systems:
                for c in CLASSES:
                    sel = [x for x in rows if x["system"] == sy and x["attack_class"] == c]
                    md.append(f"| {sy} | {c} | {sum(x['incidents'] for x in sel)} | {sum(x['detected'] for x in sel)} | "
                              f"{sum(x['false_entities'] for x in sel)} | {mean_sd([x['auc'] for x in sel])} | "
                              f"{mean_sd([x['recall_at_fp2'] for x in sel])} |")
            print(f"E1-A done in {time.time() - t0:.0f}s", flush=True)

            rates = [2, 8, 32] if args.quick else [1, 2, 4, 8, 16, 32]
            spans = [6] if args.quick else [6, 24]
            seeds = [1] if args.quick else [1, 2]
            win = 24 if args.quick else 36
            sys_b = [sy for sy in systems if sy != "B2"]  # without decoys, B2 detects exactly like S
            jobsB = [(sy, params[sy], tests[0], fam, r, sp, win, sd) for sy in sys_b for fam in sorted(INJECT_FAMILIES)
                     for r in rates for sp in spans for sd in seeds if sp < win]
            resB = list(light.map(w_inject, *zip(*jobsB)))
            write_csv("ait_e1_inject.csv", resB)
            for key, title in (("recall", "recall at the calibrated threshold"),
                               ("false_entities", "falsely alerted benign entities"),
                               ("recall_at_fp2", "recall@FP2 (threshold-free)")):
                md += ["", f"## E1-B: injected low-and-slow attacks on {tests[0]} background, {title}\n"]
                for fam in sorted(INJECT_FAMILIES):
                    for sp in spans:
                        md += [f"\n{fam}, span {sp} epochs\n", "| System | " + " | ".join(f"r={r}" for r in rates) + " |",
                               "|---|" + "---|" * len(rates)]
                        for sy in sys_b:
                            cells = []
                            for r in rates:
                                sel = [x for x in resB if x["system"] == sy and x["family"] == fam
                                       and x["rate"] == r and x["span"] == sp]
                                cells.append(f"{statistics.mean(x[key] for x in sel):.2f}" if sel else "-")
                            md.append(f"| {sy} | " + " | ".join(cells) + " |")
            print(f"E1-B done in {time.time() - t0:.0f}s", flush=True)

        if "e3" in parts:
            jobs = [(n, sc, max_ep if max_ep is None else 48) for n in ("S", "SD", "A4", "SD+A4") for sc in tests]
            res = list(ex.map(w_leak, *zip(*jobs)))
            write_csv("ait_e3_leakage.csv", res)
            cols = [("decoy_ratio", "δ"), ("U_token_recovery", "U tokens"), ("U_volume_recovery", "U volume"),
                    ("R_token_recovery", "R tokens"), ("R_volume_recovery", "R volume"), ("decoy_auc", "Decoy AUC"),
                    ("linkage_accuracy", "Linkage"), ("linkage_chance", "Chance")]
            md += ["", "## E3: leakage on days 2-4 (prior: day 1 of the same scenario)\n",
                   "| System | " + " | ".join(c[1] for c in cols) + " |", "|---|" + "---|" * len(cols)]
            for n in ("S", "SD", "A4", "SD+A4"):
                sel = [r for r in res if r["system"] == n]
                md.append(f"| {n} | " + " | ".join(mean_sd([r[k] for r in sel]) for k, _ in cols) + " |")
            print(f"E3 done in {time.time() - t0:.0f}s", flush=True)

    if "e2" in parts:
        ev, _, _ = scenario(tests[0], 6 if args.quick else 24)
        _, contexts = ait_profiles_and_contexts()
        rows = []
        for v in ("S", "SD"):
            cfg = config(v, paillier_bits=2048, precompute_workers=args.workers)
            t1 = time.time()
            s = run(cfg, ev, None, contexts)
            wall = time.time() - t1
            st = s.ee.stats
            rows.append(dict(system=v, events=len(ev), decoy_ratio=st["decoy"] / st["real"], wall_s=wall,
                             online_s=st["t_online"], offline_s=st["t_offline"],
                             online_ev_per_s=len(ev) / st["t_online"], sustained_ev_per_s=len(ev) / wall,
                             bytes_per_event=s.bus.total("ee", "cloud") / len(ev), ka_decryptions=s.ka.decryptions,
                             phase3_s=s.timing["phase3"], phase4_s=s.timing["phase4"], phase5_s=s.timing["phase5"]))
            print(f"  E2 {v}: {rows[-1]}", flush=True)
        write_csv("ait_e2_throughput.csv", rows)
        md += ["", f"## E2: 2048-bit throughput on {tests[0]} ({rows[0]['events']:,} events, {args.workers} workers)\n",
               "| System | δ | Online ev/s | Sustained ev/s | Offline s | Bytes / event | Phase 3+4+5 s |",
               "|---|---|---|---|---|---|---|"]
        md += [f"| {r['system']} | {r['decoy_ratio']:.2f} | {r['online_ev_per_s']:,.0f} | {r['sustained_ev_per_s']:,.1f} | "
               f"{r['offline_s']:.0f} | {r['bytes_per_event']:,.0f} | {r['phase3_s'] + r['phase4_s'] + r['phase5_s']:.2f} |"
               for r in rows]

    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "ait_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
