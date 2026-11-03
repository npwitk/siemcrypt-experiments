"""Journal v2 Experiment 4: temporal correlation ablations, dormancy and versioned profiles.

Systems (each re-learned and re-calibrated on the development stream)
  S            adaptive decay over contracted, profile-bound state (the protocol)
  NoGraph      graph features of z ignored (SG-HEF slot values only)
  FixedWindow  h = mean of z over the last W = 3 epochs (hard window, no decay)
  FixedDecay   lambda = lambda0 (no drift or risk adaptation)
  NoHist       one-epoch window (no trusted history)
Part A  epoch gap: a low-and-slow attacker active in 5 epochs separated by g dormant epochs,
        g in {0, 1, 2, 3, 4} (4 failed logins per active epoch); recall@FP2 and AUC (cred_access)
Part B  burst / dormant: two bursts of 3 active epochs separated by D dormant epochs,
        D in {2, 4, 8}
Part C  profile change: at epoch k the cred_access profile is redeployed as version 2 (same
        features, Theta lowered 20%: a re-calibration). S binds state to pid_a, so version 2 starts
        new lineages (fresh genesis); No-Profile-Bind keeps the (u, a) state. Reported: alerts
        after the change, alerts whose lineage started under version 1 (mixed lineage), alerts
        whose provenance holds records from before the change, benign alerts after the change
Part D  state dynamics of S over the Part A streams: mean rho, retention horizon ell and |Prov|
        for attacker and benign pairs, idle-decay commitments C_empty per epoch

Usage:  python experiments/e4_v2.py [--quick] [--seeds 5] [--workers 8]
Writes results/e4_v2_gap.csv, e4_v2_burst.csv, e4_v2_profile.csv, e4_v2_state.csv, e4_v2_summary.md.
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

from common import RESULTS, calibrate, config, generate, learn_weights, mean_sd, write_csv  # noqa: E402
from e1_accuracy import DEV, SWEEP, TARGET_FPR, evaluate  # noqa: E402

from siemcrypt.data.synth import default_profiles_and_contexts  # noqa: E402
from siemcrypt.system import SIEMCrypt  # noqa: E402

SYSTEMS = ["S", "NoGraph", "FixedWindow", "FixedDecay", "NoHist"]
LONG = replace(SWEEP, epochs=28, lns_per_epoch=4)
GAPS = [0, 1, 2, 3, 4]
DORMANT = [2, 4, 8]
CHANGE = 8          # epoch of the profile redeployment (Part C)
PROFILE_SC = replace(SWEEP, epochs=16, lns_per_epoch=4, lns_epochs=8, n_low_and_slow=4)


def prepare(system: str):
    cfg = config(system)
    return calibrate(cfg, DEV, TARGET_FPR, profiles=learn_weights(cfg, DEV))


def pattern_eval(part: str, system: str, params, knob: int, seed: int) -> dict:
    if part == "gap":
        sc = replace(LONG, seed=seed, lns_epochs=5, lns_gap=knob)
    else:
        sc = replace(LONG, seed=seed, lns_epochs=6, lns_burst=3, lns_gap=knob)
    r = evaluate(system, params, sc)
    x, tf = r["scores"]["cred_access"], r["tf"]["cred_access"]
    return dict(part=part, system=system, knob=knob, seed=seed, recall_at_fp2=tf["recall_at_fp"], auc=tf["auc"],
                recall=x.recall, false_pairs=x.alerted_pairs - x.true_pairs)


def state_eval(params, gap: int, seed: int) -> dict:
    events, truth = generate(replace(LONG, seed=seed, lns_epochs=5, lns_gap=gap))
    _, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(config("J"), params, contexts)
    s.run(events)
    att = {gt.user for gt in truth}
    hz = s.ee.horizon_log
    out = dict(gap=gap, seed=seed, idle_commit_per_epoch=s.ee.stats["idle_commit"] / LONG.epochs)
    for who, sel in (("attacker", [r for r in hz if r[1] in att]), ("benign", [r for r in hz if r[1] not in att])):
        for i, k in ((6, "rho"), (3, "ell"), (5, "prov")):
            out[f"{who}_{k}"] = statistics.mean(r[i] for r in sel) if sel else float("nan")
    return out


def profile_eval(system: str, params, seed: int) -> dict:
    events, truth = generate(replace(PROFILE_SC, seed=seed))
    _, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(config(system, acl=True), [replace(p) for p in params], contexts)
    by_epoch = {}
    for ev in events:
        by_epoch.setdefault(s.epoch_of(ev.ts), []).append(ev)
    for e in sorted(by_epoch):
        if e == CHANGE:
            p = s.ee.profiles["cred_access"]
            s.ee.update_profile(replace(p, version=2, Theta=0.8 * p.Theta))
        s.run_epoch(e, by_epoch[e])
    s.close()
    att = {gt.user for gt in truth if gt.attack_class == "cred_access"}
    after = [a for a in s.ee.alert_log if a["attack"] == "cred_access" and a["epoch"] >= CHANGE]
    active_after = {gt.user for gt in truth if gt.attack_class == "cred_access" and any(e >= CHANGE for e in gt.epochs)}
    return dict(system=system, seed=seed, alerts_after=len(after),
                mixed_lineage=sum(a["born"] < a["version"] for a in after),
                stale_provenance=sum(any(ep < CHANGE for ep in a["prov_epochs"]) for a in after),
                benign_after=len({a["user"] for a in after if a["user"] not in att}),
                attackers_detected_after=len({a["user"] for a in after if a["user"] in active_after}),
                attackers_active_after=len(active_after), retired=s.ee.stats["lineage_retired"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    seeds = list(range(1, (2 if a.quick else a.seeds) + 1))
    gaps = [0, 2, 4] if a.quick else GAPS
    dormant = [2, 8] if a.quick else DORMANT
    t0 = time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        params = dict(zip(SYSTEMS + ["NoProfileBind"], ex.map(prepare, SYSTEMS + ["NoProfileBind"])))
        jobs = [("gap", sy, params[sy], g, sd) for sy in SYSTEMS for g in gaps for sd in seeds]
        jobs += [("burst", sy, params[sy], d, sd) for sy in SYSTEMS for d in dormant for sd in seeds]
        rows = list(ex.map(pattern_eval, *zip(*jobs)))
        print(f"parts A/B done in {time.time() - t0:.0f}s", flush=True)
        jc = [(sy, params[sy], sd) for sy in ("S", "NoProfileBind") for sd in seeds]
        prof = list(ex.map(profile_eval, *zip(*jc)))
        jd = [(params["S"], g, sd) for g in gaps for sd in seeds]
        state = list(ex.map(state_eval, *zip(*jd)))
    gap_rows = [r for r in rows if r["part"] == "gap"]
    burst_rows = [r for r in rows if r["part"] == "burst"]
    write_csv("e4_v2_gap.csv", gap_rows)
    write_csv("e4_v2_burst.csv", burst_rows)
    write_csv("e4_v2_profile.csv", prof)
    write_csv("e4_v2_state.csv", state)

    def table(rs, knobs, label, key):
        out = ["| System | " + " | ".join(f"{label}={k}" for k in knobs) + " |", "|---|" + "---|" * len(knobs)]
        for sy in SYSTEMS:
            out.append(f"| {sy} | " + " | ".join(
                f"{statistics.mean(r[key] for r in rs if r['system'] == sy and r['knob'] == k):.2f}" for k in knobs) + " |")
        return out

    md = ["# Journal v2 Experiment 4: temporal ablations, dormancy, versioned profiles (synthetic)", "",
          f"Seeds {seeds}. cred_access (low-and-slow), {LONG.epochs} epochs, 4 failed logins per active epoch.", ""]
    for key, title in (("recall_at_fp2", "recall@FP2"), ("auc", "AUC")):
        md += [f"## Part A: epoch gap g between 5 active epochs, {title}", ""] + table(gap_rows, gaps, "g", key) + [""]
        md += [f"## Part B: two bursts of 3 epochs, D dormant epochs between, {title}", ""]
        md += table(burst_rows, dormant, "D", key) + [""]
    cols = [("alerts_after", "cred_access alerts after change"), ("mixed_lineage", "mixed-lineage alerts"),
            ("stale_provenance", "alerts with pre-change provenance"), ("benign_after", "benign entities alerted"),
            ("attackers_detected_after", "attackers detected"), ("attackers_active_after", "attackers active"),
            ("retired", "lineages retired")]
    md += [f"## Part C: profile redeployed as version 2 at epoch {CHANGE} (Theta x 0.8)", "",
           "| System | " + " | ".join(c[1] for c in cols) + " |", "|---|" + "---|" * len(cols)]
    for sy in ("S", "NoProfileBind"):
        sel = [r for r in prof if r["system"] == sy]
        md.append(f"| {sy} | " + " | ".join(mean_sd([r[k] for r in sel]) for k, _ in cols) + " |")
    cols = [(f"{w}_{k}", f"{w} {k}") for w in ("attacker", "benign") for k in ("rho", "ell", "prov")]
    cols.append(("idle_commit_per_epoch", "C_empty per epoch"))
    md += ["", "## Part D: state dynamics of S (Part A streams)", "",
           "| g | " + " | ".join(c[1] for c in cols) + " |", "|---|" + "---|" * len(cols)]
    for g in gaps:
        sel = [r for r in state if r["gap"] == g]
        md.append(f"| {g} | " + " | ".join(mean_sd([r[k] for r in sel]) for k, _ in cols) + " |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e4_v2_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
