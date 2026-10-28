"""Journal v2 Experiment 3: AQRS query-identification resistance and cost.

A hunting workload (analyst queries on one entity or resource, optionally restricted to a
category) runs on top of the normal pipeline of J (cfg.acl). Per issue the EE sends an AQRS
cohort; the cloud tries to tell which member is real using only what it holds: the cohort
messages, its own EPII (posting volumes, candidate sets), and the evidence later sent to it.

Attacks (one guess per issue; success probability with uniform tie-breaking)
  uniform       1 / |cohort|: the ideal of Proposition 1
  central       the member whose volume is most central in the cohort; targets "nearest"
                cover selection, where the real query sits in the middle of its covers
  intersect     intersect the cohort with every other cohort of the epoch that shares a
                member (repeated issues; a query first issued alone and later in a cohort)
  downstream    the member whose candidate set equals a candidate set the cloud later
                receives as real evidence for Phase 4 graph contraction (eq:epoch-real-scope)
  learned       random forest on member features (volume rank, centrality, recurrence),
                trained with labels on the first half of the epochs, tested on the rest
  combined      downstream, then intersect, then learned within what is left

Workload per epoch: 3 watch-list targets (one attacker, two popular users) issued every epoch,
plus 20 ad-hoc queries (U 80% / R 20%; attacker users 30% of the U queries, otherwise drawn
by popularity; category filter none / auth_fail / data_transfer / conn_denied), each issued
1-4 times. Exposure class = the AQRS profile the journal's risk score assigns.

Usage:  python experiments/e3_aqrs.py [--seeds 5] [--workers 8] [--bits 512] [--quick]
Writes results/e3_aqrs_issues.csv, e3_aqrs_summary.csv and e3_aqrs_summary.md.
"""

from __future__ import annotations

import argparse
import math
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, SynthConfig, config, generate, write_csv  # noqa: E402

from siemcrypt.aqrs import Spec  # noqa: E402
from siemcrypt.data.synth import default_profiles_and_contexts  # noqa: E402
from siemcrypt.system import SIEMCrypt  # noqa: E402

SYSTEMS = {
    "Direct": dict(aqrs="direct"),
    "Fixed-3": dict(aqrs="fixed", aqrs_fixed_k=3),
    "Fixed-5": dict(aqrs="fixed", aqrs_fixed_k=5),
    "AQRS": dict(aqrs="adaptive"),                                    # journal as written
    "AQRS-rand": dict(aqrs="adaptive", aqrs_select="random"),
    "Dynamic-Cover": dict(aqrs="adaptive", aqrs_select="random", aqrs_dynamic=True),
    "AQRS-D28": dict(aqrs="adaptive", aqrs_select="random", aqrs_sticky=True, aqrs_graph="ee"),
    "AQRS-D28w": dict(aqrs="adaptive", aqrs_select="near-random", aqrs_compat="sigma", aqrs_sticky=True,
                      aqrs_graph="ee"),
    "Fixed-5-D28w": dict(aqrs="fixed", aqrs_fixed_k=5, aqrs_select="near-random", aqrs_compat="sigma",
                         aqrs_sticky=True, aqrs_graph="ee"),
}
CATS = [(None, 0.5), (frozenset({"auth_fail"}), 0.2), (frozenset({"data_transfer"}), 0.15),
        (frozenset({"conn_denied"}), 0.15)]
REPEATS = [(1, 0.6), (2, 0.2), (3, 0.1), (4, 0.1)]


def _w(rng, pairs):
    return rng.choices([a for a, _ in pairs], [b for _, b in pairs])[0]


def workload(events, truth, epoch_len: float, seed: int) -> dict[int, list[Spec]]:
    rng = random.Random(seed * 31 + 5)
    by_e = defaultdict(list)
    for ev in events:
        by_e[int(ev.ts // epoch_len) + 1].append(ev)
    attackers = sorted({gt.user for gt in truth})
    users = Counter(ev.user for ev in events)
    popular = [u for u, _ in users.most_common(30) if u not in attackers]
    watch = [Spec("U", attackers[0], None) if attackers else Spec("U", popular[2], None),
             Spec("U", popular[0], frozenset({"auth_fail"})), Spec("U", popular[5], None)]
    out = {}
    for e, evs in sorted(by_e.items()):
        u_pop = Counter(ev.user for ev in evs)
        r_pop = Counter(ev.res for ev in evs)
        issues = []
        for s in watch:
            issues += [s] * rng.randint(1, 3)
        for _ in range(20):
            cats = _w(rng, CATS)
            if rng.random() < 0.8:
                if attackers and rng.random() < 0.3:
                    v = rng.choice(attackers)
                else:
                    ks = sorted(u_pop)
                    v = rng.choices(ks, [u_pop[k] for k in ks])[0]
                s = Spec("U", v, cats)
            else:
                ks = sorted(r_pop)
                s = Spec("R", rng.choices(ks, [r_pop[k] for k in ks])[0], cats)
            issues += [s] * _w(rng, REPEATS)
        rng.shuffle(issues)
        out[e] = issues
    return out


# ============================================================================ cloud observer
def _key(q) -> frozenset:
    return frozenset((d, T) for d, toks in q["tokens"].items() for T in toks)


def observe(s: SIEMCrypt) -> list[dict]:
    """Per issue: the cloud-side features of each member plus the non-learned attacks."""
    cloud = s.cloud
    cohorts = [obj for src, kind, obj in s.bus.cloud_view if kind == "cohort"]
    evidence = defaultdict(list)
    for src, kind, obj in s.bus.cloud_view:
        if kind == "evidence_z" and obj.get("attack") == "hunt":
            evidence[obj["epoch"]].append(frozenset(obj["Q"]))
    logs = s.ee.hunt_log
    assert len(cohorts) == len(logs)
    by_epoch = defaultdict(list)
    for c in cohorts:
        by_epoch[c["epoch"]].append([_key(q) for q in c["queries"]])
    rows = []
    for c, log in zip(cohorts, logs):
        e = c["epoch"]
        qs = c["queries"]
        keys = [_key(q) for q in qs]
        cand = [frozenset(cloud.candidates(e, q["tokens"])) for q in qs]
        n = [len(x) for x in cand]
        real = [q["qid"] for q in qs].index(log["real"])
        k = len(qs)
        ln = [math.log1p(x) for x in n]
        cent = [sum(abs(a - b) for b in ln) for a in ln]
        # recurrence of each member's token set in the epoch's cohorts (alone / at all)
        alone = Counter(ks[0] for ks in by_epoch[e] if len(ks) == 1)
        seen = Counter(x for ks in by_epoch[e] for x in set(ks))

        def p_of(S):
            return (1.0 / len(S)) if real in S else 0.0

        S_c = {i for i in range(k) if cent[i] == min(cent)}
        # intersection over cohorts sharing a member
        S_i = set(keys)
        for other in sorted(by_epoch[e], key=len):
            inter = S_i & set(other)
            if inter:
                S_i = inter
        S_i = {i for i in range(k) if keys[i] in S_i}
        match = {i for i in range(k) if cand[i] in set(evidence[e])}
        S_d = match or set(range(k))
        S_comb = (S_d & S_i) or S_d
        feats = []
        rank = sorted(range(k), key=lambda i: n[i])
        med = statistics.median(n) if n else 0
        for i in range(k):
            feats.append([k, ln[i], rank.index(i) / max(1, k - 1), n[i] / (med + 1), cent[i] / max(1e-9, max(cent)),
                          int(i in S_c), int(n[i] == max(n)), alone[keys[i]], seen[keys[i]],
                          seen[keys[i]] / max(seen[x] for x in keys)])
        rows.append(dict(epoch=e, cls=log["cls"], pi=log["pi"], k=log["k"], k_eff=k, n_issue=log["n_issue"],
                         real=real, feats=feats, S_comb=sorted(S_comb),
                         uniform=1.0 / k, central=p_of(S_c), intersect=p_of(S_i), downstream=p_of(S_d),
                         members=k, retrieved=log["retrieved"], real_size=log["real_size"],
                         he_adds=log["he_adds"], seconds=log["seconds"], ok=int(log["ok"])))
    return rows


def run_one(args) -> list[dict]:
    name, seed, bits, sc = args
    cfg = config("J", paillier_bits=bits, seed=seed, **SYSTEMS[name])
    events, truth = generate(replace(sc, seed=seed))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(cfg, profiles, contexts)
    wl = workload(events, truth, cfg.epoch_len, seed)
    s.hunter = lambda e: wl.get(e, [])
    t0 = time.perf_counter()
    s.run(events)
    rows = observe(s)
    hunt_bytes = sum(v for (a, b, kind), v in s.bus.bytes.items() if kind in ("cohort", "cohort_req"))
    for r in rows:
        r.update(system=name, seed=seed, bytes_per_issue=hunt_bytes / max(1, len(rows)),
                 run_seconds=time.perf_counter() - t0, acl_reject=s.ee.stats["acl_reject"],
                 graph_reject=s.ee.stats["graph_reject"] + s.ee.stats["graph_omitted"])
    return rows


def learned(rows: list[dict], n_epochs: int) -> None:
    """RF per system: train on epochs <= n_epochs/2 (all seeds), test on the rest."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    half = n_epochs // 2
    by_sys = defaultdict(list)
    for r in rows:
        by_sys[r["system"]].append(r)
    for name, rs in by_sys.items():
        train = [r for r in rs if r["epoch"] <= half and r["k_eff"] > 1]
        X = [f for r in train for f in r["feats"]]
        y = [int(i == r["real"]) for r in train for i in range(r["k_eff"])]
        model = None
        if len(set(y)) == 2:
            model = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, random_state=0,
                                           class_weight="balanced").fit(np.array(X), y)
        for r in rs:
            k = r["k_eff"]
            if k == 1:
                r["learned"] = r["combined"] = 1.0
                continue
            if model is None:
                pr = [1.0] * k
            else:
                pr = list(model.predict_proba(np.array(r["feats"]))[:, 1])
            best = {i for i in range(k) if pr[i] == max(pr)}
            r["learned"] = (1.0 / len(best)) if r["real"] in best else 0.0
            sub = r["S_comb"]
            bsub = {i for i in sub if pr[i] == max(pr[j] for j in sub)}
            r["combined"] = (1.0 / len(bsub)) if r["real"] in bsub else 0.0


ATTACKS = ("uniform", "central", "intersect", "downstream", "learned", "combined")


def summarize(rows: list[dict], n_epochs: int) -> list[dict]:
    half = n_epochs // 2
    test = [r for r in rows if r["epoch"] > half]
    out = []
    for name in SYSTEMS:
        for cls in ("all", 0, 1, 2):
            rs = [r for r in test if r["system"] == name and (cls == "all" or r["cls"] == cls)]
            if not rs:
                continue
            row = dict(system=name, cls=cls, issues=len(rs))
            for a in ATTACKS:
                row[a] = statistics.mean(r[a] for r in rs)
            row["best"] = max(row[a] for a in ATTACKS)  # the attacker keeps its strongest attack
            row["k_eff"] = statistics.mean(r["k_eff"] for r in rs)
            row["short"] = statistics.mean(int(r["k_eff"] < r["k"]) for r in rs)
            row["retrieved_x"] = (sum(r["retrieved"] for r in rs) / max(1, sum(r["real_size"] for r in rs)))
            row["he_adds"] = statistics.mean(r["he_adds"] for r in rs)
            row["ms"] = 1000 * statistics.mean(r["seconds"] for r in rs)
            row["bytes"] = statistics.mean(r["bytes_per_issue"] for r in rs)
            row["false_reject"] = sum(1 - r["ok"] for r in rs)
            out.append(row)
    return out


def write_md(summary: list[dict], path: Path, meta: str) -> None:
    def f(x):
        return f"{x:.3f}" if isinstance(x, float) else str(x)

    lines = ["# Journal v2 Experiment 3: AQRS", "", meta, "",
             "Identification rate = probability the cloud picks the real query (lower is better; "
             "Direct = 1). Test epochs only (second half).", "",
             "| System | class | issues | uniform | central | intersect | downstream | learned | combined | best | "
             "k_eff | short | retrieved x | HE adds | ms | bytes |",
             "|---" * 16 + "|"]
    for r in summary:
        lines.append("| " + " | ".join(f(r[k]) for k in ("system", "cls", "issues", *ATTACKS, "best", "k_eff", "short",
                                                           "retrieved_x", "he_adds", "ms", "bytes")) + " |")
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--bits", type=int, default=512)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--systems", default=",".join(SYSTEMS))
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    sc = SynthConfig(epochs=8, events_per_epoch=1500, n_users=200, n_low_and_slow=2, n_exfil=1, n_coordinated=1)
    if a.quick:
        sc = replace(sc, epochs=4, events_per_epoch=500, n_users=80)
        a.seeds = min(a.seeds, 2)
    names = a.systems.split(",")
    jobs = [(n, seed, a.bits, sc) for n in names for seed in range(1, a.seeds + 1)]
    t0 = time.perf_counter()
    with ProcessPoolExecutor(a.workers) as ex:
        rows = [r for rs in ex.map(run_one, jobs) for r in rs]
    learned(rows, sc.epochs)
    summary = summarize(rows, sc.epochs)
    tag = f"_{a.tag}" if a.tag else ""
    write_csv(f"e3_aqrs_issues{tag}.csv", [{k: v for k, v in r.items() if k not in ("feats", "S_comb")} for r in rows])
    write_csv(f"e3_aqrs_summary{tag}.csv", summary)
    meta = (f"{a.seeds} seeds, {sc.epochs} epochs x {sc.events_per_epoch} events, {sc.n_users} users, "
            f"Paillier {a.bits} bits, {time.perf_counter() - t0:.0f} s.")
    write_md(summary, RESULTS / f"e3_aqrs_summary{tag}.md", meta)
    print((RESULTS / f"e3_aqrs_summary{tag}.md").read_text())


if __name__ == "__main__":
    main()
