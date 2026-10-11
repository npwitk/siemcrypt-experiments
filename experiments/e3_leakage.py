"""E3: leakage to the honest-but-curious Cloud SIEM (DS2 Section "Experiment 3", RQ3).

Attacks on what the cloud stores and receives:
  (a) frequency analysis of entity (U) and resource (R) tokens vs. an auxiliary
      distribution taken from a development stream (different seed)
  (b) decoy distinguisher (random forest on cloud-visible features), AUC 0.5 is ideal
  (c) cross-epoch linkage of entity tokens
  (d) release attacks: individual values disclosed by single-record VALUE releases under a
      fine-grained (per-entity) context configuration; repeated release requests; and the
      documented residual: differencing two overlapping authorized contexts
Systems: S (no decoys), SD (decoys, gamma = 2), A4 (persistent tokens, as with static
searchable-encryption tokens such as B7), SD+A4, A5 (k_min = 0, for (d)).

Usage:  python experiments/e3_leakage.py [--quick] [--seeds 10] [--workers 8]
Writes results/e3_leakage.csv, e3_release.csv, e3_summary.md.
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

from common import RESULTS, SynthConfig, benign, config, generate, mean_sd, run, write_csv  # noqa: E402
from leakage import aux_distribution, decoy_distinguisher, frequency_attack, linkage_attack  # noqa: E402

from siemcrypt.data.synth import default_profiles_and_contexts  # noqa: E402
from siemcrypt.model import Context, Policy  # noqa: E402

TEST = SynthConfig(epochs=8, events_per_epoch=600, n_users=80)
AUX = replace(benign(TEST), seed=1001)
SYSTEMS = {
    "S": dict(variant="S"),
    "SD": dict(variant="SD"),
    "A4": dict(variant="A4"),
    "SD+A4": dict(variant="SD", persistent_tokens=True),
}


def token_attacks(name: str, seed: int) -> dict:
    spec = dict(SYSTEMS[name])
    cfg = config(spec.pop("variant"), **spec, seed=seed)
    events, _ = generate(replace(TEST, seed=seed))
    aux_events, _ = generate(AUX)
    s = run(cfg, events)
    cumulative = cfg.persistent_tokens
    out = dict(system=name, seed=seed, decoy_ratio=s.ee.stats["decoy"] / max(s.ee.stats["real"], 1))
    for dim in ("U", "R"):
        r = frequency_attack(s, aux_distribution(aux_events, dim), dim, cumulative)
        out[f"{dim}_token_recovery"] = r["token_recovery"]
        out[f"{dim}_volume_recovery"] = r["volume_recovery"]
    d = decoy_distinguisher(s)
    out.update(decoy_auc=d["auc"], decoy_acc=d["accuracy"], decoy_majority=d.get("majority_baseline"))
    lk = linkage_attack(s)
    out.update(linkage_accuracy=lk["linkage_accuracy"], linkage_chance=lk["chance"])
    return out


def release_attacks(variant: str, seed: int, **overrides) -> dict:
    """Per-entity VALUE contexts (an over-fine configuration the EE could be given)."""
    events, _ = generate(replace(TEST, seed=seed))
    users = sorted({ev.user for ev in events})
    profiles, contexts = default_profiles_and_contexts()
    probe = [Context(f"q_u_{u}", "probe", users=frozenset({u}), categories=frozenset({"auth_fail"}),
                     feats=("count",), policy=Policy.VALUE) for u in users]
    # two overlapping authorized contexts that differ by one entity (residual leakage)
    target = users[len(users) // 2]
    others = frozenset(users) - {target}
    overlap = [Context("q_all", "probe", categories=frozenset({"auth_fail"}), feats=("count",), policy=Policy.VALUE),
               Context("q_minus", "probe", users=others, categories=frozenset({"auth_fail"}),
                       feats=("count",), policy=Policy.VALUE)]
    s = run(config(variant, seed=seed, **overrides), events, profiles, contexts + probe + overlap)
    # individual disclosure: a VALUE release whose support is exactly one real record
    audit = s.ka.audit
    single = [r for r in audit if r.qid.startswith("q_u_") and r.support == 1 and r.effective is Policy.VALUE]
    down = [r for r in audit if r.policy is Policy.VALUE and r.effective is Policy.DECISION]
    # repeated release request for an already released context
    refused = 0
    q = s.ee.make_queries()[0]
    try:
        s.cloud.sghef([q], s.feat_index)
    except PermissionError:
        refused = 1
    # differencing of overlapping contexts
    diff_ok = 0
    for rep in s.reports:
        y = {z["qid"]: z["y"].get("count") for z in rep.releases}
        real = sum(1 for ev in events if s.epoch_of(ev.ts) == rep.epoch and ev.user == target and ev.cat == "auth_fail")
        eff = {r.qid: r.effective for r in audit if r.epoch == rep.epoch}
        if eff.get("q_all") is Policy.VALUE and eff.get("q_minus") is Policy.VALUE:
            diff_ok += int(y["q_all"] - y["q_minus"] == real)
    return dict(system=variant, seed=seed, per_entity_releases=sum(1 for r in audit if r.qid.startswith("q_u_")),
                single_record_value_releases=len(single), downgraded=len(down),
                repeated_request_refused=refused, differencing_epochs_recovered=diff_ok,
                epochs=len(s.reports))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    seeds = list(range(1, (2 if args.quick else args.seeds) + 1))
    t0 = time.time()
    with ProcessPoolExecutor(args.workers) as ex:
        jobs = [(n, sd) for n in SYSTEMS for sd in seeds]
        rows = list(ex.map(token_attacks, *zip(*jobs)))
        jobs2 = [(v, sd) for v in ("S", "A5") for sd in seeds]
        rows2 = list(ex.map(release_attacks, *zip(*jobs2)))
    write_csv("e3_leakage.csv", rows)
    write_csv("e3_release.csv", rows2)

    cols = [("decoy_ratio", "δ"), ("U_token_recovery", "U tokens recovered"),
            ("U_volume_recovery", "U volume recovered"), ("R_token_recovery", "R tokens recovered"),
            ("R_volume_recovery", "R volume recovered"), ("decoy_auc", "Decoy AUC"),
            ("linkage_accuracy", "Linkage acc."), ("linkage_chance", "Linkage chance")]
    md = ["# E3 results (synthetic data)\n", f"Seeds {seeds}; mean ± sd.\n",
          "## Token attacks (a)-(c)\n", "| System | " + " | ".join(c[1] for c in cols) + " |",
          "|---|" + "---|" * len(cols)]
    for n in SYSTEMS:
        sel = [r for r in rows if r["system"] == n]
        md.append(f"| {n} | " + " | ".join(mean_sd([r[k] for r in sel]) for k, _ in cols) + " |")
    md += ["", "## Release attacks (d), per run\n",
           "| System | Per-entity releases | Single-record VALUE releases | Downgraded to DECISION | "
           "Repeated request refused | Differencing recovered (epochs) |", "|---|---|---|---|---|---|"]
    for v in ("S", "A5"):
        sel = [r for r in rows2 if r["system"] == v]
        md.append(f"| {v} | {statistics.mean(r['per_entity_releases'] for r in sel):.0f} | "
                  f"{mean_sd([r['single_record_value_releases'] for r in sel])} | "
                  f"{mean_sd([r['downgraded'] for r in sel])} | "
                  f"{sum(r['repeated_request_refused'] for r in sel)}/{len(sel)} | "
                  f"{mean_sd([r['differencing_epochs_recovered'] for r in sel])} of {sel[0]['epochs']} |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e3_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
