"""Journal Experiment 5 (table): cloud-side analytical deviations against ACL.

The system J (cfg.acl) processes a few epochs honestly; the Cloud SIEM then deviates in one
way during the next epoch. Per deviation and trial we record whether the EE rejected it,
and whether the inconsistent evidence was nevertheless released by the KA (Phase 3) or
admitted into trusted temporal state (Phase 4). The cloud is a consistent cheater: when it
changes inputs it recomputes its own outputs and commitments over the changed inputs, so
only the EE's independent reconstruction can expose it.

Usage:  python experiments/e5_acl.py [--trials 5] [--workers 8]
Writes results/e5_acl_deviation.csv and e5_acl_summary.md.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, SynthConfig, config, generate, run, write_csv  # noqa: E402

from siemcrypt import lineage  # noqa: E402

DATA = SynthConfig(epochs=5, events_per_epoch=400, n_users=60, n_low_and_slow=1, n_exfil=1, n_coordinated=1)


# ============================================================================ Phase 3 deviations
def _first_list(postings):
    k = next((k for k in sorted(postings) if len(postings[k]) > 1), None)
    return k


def _requote(s, q, fi, Q, postings, proof, aggs_over=None, chi_cp=None):
    """The cloud's consistent request for (possibly altered) candidates and aggregates."""
    e = q["epoch"]
    aggs, realness = s.cloud.aggregate(q, Q if aggs_over is None else aggs_over, fi)
    cp = chi_cp or s.cloud.checkpoints[e][0]
    chi = lineage.c_chi(q, cp)
    cq = lineage.c_q(chi, {r[1] for r in Q})
    return dict(Q=Q, postings=postings, proof=proof, aggs=aggs, realness=realness,
                C_Q=cq, C_A=lineage.c_a(cq, q["feats"], aggs, realness, spec=lineage.c_spec(q)))


def d_omit_posting(s, rng):
    def req(q, fi):
        Q, P, pf = s.cloud.auth_candidates(q["epoch"], q["tokens"])
        k = _first_list(P)
        if k is None:
            return _requote(s, q, fi, Q, P, pf)
        drop = rng.choice(P[k])
        P = {**P, k: [i for i in P[k] if i != drop]}
        Q = {(q["epoch"], i) for i in lineage.candidates_from(q["tokens"], P, len(s.cloud.by_epoch[q["epoch"]]))}
        return _requote(s, q, fi, Q, P, pf)
    return "acl_request", req


def d_substitute_posting(s, rng):
    def req(q, fi):
        e = q["epoch"]
        Q, P, pf = s.cloud.auth_candidates(e, q["tokens"])
        k = _first_list(P)
        if k is None:
            return _requote(s, q, fi, Q, P, pf)
        other = rng.choice([i for i in range(len(s.cloud.by_epoch[e])) if i not in P[k]])
        lst = list(P[k])
        lst[rng.randrange(len(lst))] = other
        P = {**P, k: sorted(lst)}
        Q = {(e, i) for i in lineage.candidates_from(q["tokens"], P, len(s.cloud.by_epoch[e]))}
        return _requote(s, q, fi, Q, P, pf)
    return "acl_request", req


def d_stale_index(s, rng):
    """Answer from the previous epoch's authenticated index state (rollback of R^IDX)."""
    def req(q, fi):
        e = q["epoch"]
        _, P, pf = s.cloud.auth_candidates(e - 1, q["tokens"])
        Q = {(e, i) for i in lineage.candidates_from(q["tokens"], P, len(s.cloud.by_epoch[e]))
             if i < len(s.cloud.by_epoch[e])}
        return _requote(s, q, fi, Q, P, pf)
    return "acl_request", req


def d_stale_checkpoint(s, rng):
    """Bind the commitments to the previous epoch's (validly signed) checkpoint."""
    def req(q, fi):
        Q, P, pf = s.cloud.auth_candidates(q["epoch"], q["tokens"])
        return _requote(s, q, fi, Q, P, pf, chi_cp=s.cloud.checkpoints[q["epoch"] - 1][0])
    return "acl_request", req


def d_omit_candidate(s, rng):
    def req(q, fi):
        Q, P, pf = s.cloud.auth_candidates(q["epoch"], q["tokens"])
        if Q:
            Q = Q - {rng.choice(sorted(Q))}
        return _requote(s, q, fi, Q, P, pf)
    return "acl_request", req


def d_add_candidate(s, rng):
    def req(q, fi):
        e = q["epoch"]
        Q, P, pf = s.cloud.auth_candidates(e, q["tokens"])
        Q = Q | {rng.choice([r for r in s.cloud.by_epoch[e] if r not in Q])}
        return _requote(s, q, fi, Q, P, pf)
    return "acl_request", req


def d_modify_aggregate(s, rng):
    def req(q, fi):
        Q, P, pf = s.cloud.auth_candidates(q["epoch"], q["tokens"])
        r = _requote(s, q, fi, Q, P, pf)
        f = q["feats"][0]
        r["aggs"] = {**r["aggs"], f: s.cloud.he.add(r["aggs"][f], s.cloud.he.encrypt(1))}
        cq = r["C_Q"]
        r["C_A"] = lineage.c_a(cq, q["feats"], r["aggs"], r["realness"], spec=lineage.c_spec(q))
        return r
    return "acl_request", req


def d_modify_spec(s, rng):
    """Specification manipulation (journal v2): aggregate another feature (count <-> bytes)
    in place of the prescribed one, and commit consistently to the prescribed spec."""
    def req(q, fi):
        Q, P, pf = s.cloud.auth_candidates(q["epoch"], q["tokens"])
        swapped = {f: (len(fi) - 1 - j) for f, j in fi.items()}
        r = _requote(s, q, swapped, Q, P, pf)
        return r
    return "acl_request", req


def d_wrong_set(s, rng):
    """Report the authenticated candidate set but aggregate over a different one."""
    def req(q, fi):
        Q, P, pf = s.cloud.auth_candidates(q["epoch"], q["tokens"])
        sub = Q - {rng.choice(sorted(Q))} if Q else Q
        return _requote(s, q, fi, Q, P, pf, aggs_over=sub)
    return "acl_request", req


# ============================================================================ Phase 4 deviations
def d_modify_relation(s, rng):
    """Contract over a modified relation (one candidate record moved to another bucket)."""
    def contract(epoch, Z):
        Qall = sorted(set().union(*(z["Q"] for z in Z))) if Z else []
        victim = rng.choice(Qall) if Qall else None

        def entry_of(rid):
            ent = s.cloud.entries[rid]
            return replace(ent, bucket=ent.bucket + 1) if rid == victim else ent
        return lineage.contract(Z, entry_of, s.cloud.graph_profiles.get(epoch, {}), lineage.H)
    return "contract", contract


def d_omit_graph_evidence(s, rng):
    """Drop one contributing record from the accepted evidence before contraction."""
    def contract(epoch, Z):
        Qall = sorted(set().union(*(z["Q"] for z in Z))) if Z else []
        victim = rng.choice(Qall) if Qall else None
        Z2 = [{**z, "Q": z["Q"] - {victim}} for z in Z]
        ups, mu = lineage.contract(Z2, s.cloud.entries.__getitem__, s.cloud.graph_profiles.get(epoch, {}), lineage.H)
        return ups, mu
    return "contract", contract


def d_modify_features(s, rng):
    orig = s.cloud.contract

    def contract(epoch, Z):
        ups, mu = orig(epoch, Z)
        if ups:
            k = rng.randrange(len(ups))
            tu, a, z, refs, cg = ups[k]
            ups[k] = (tu, a, [z[0] * 2 + 1] + list(z[1:]), refs, cg)
        return ups, mu
    return "contract", contract


def d_drop_update(s, rng):
    """Suppress one entity's graph update (the entity silently leaves trusted state)."""
    orig = s.cloud.contract

    def contract(epoch, Z):
        ups, mu = orig(epoch, Z)
        if ups:
            ups.pop(rng.randrange(len(ups)))
        return ups, mu
    return "contract", contract


def d_modify_drift(s, rng):
    orig = s.cloud.phase4

    def phase4(epoch, Z):
        ups, dr = orig(epoch, Z)
        return ups, dr + 0.5
    return "phase4", phase4


DEVIATIONS = {
    "Omit queried posting entry": ("Authenticated EPII", d_omit_posting),
    "Substitute posting entry": ("Authenticated EPII", d_substitute_posting),
    "Replay stale index state": ("Checkpoint/EPII root", d_stale_index),
    "Bind to stale checkpoint": ("Context commitment", d_stale_checkpoint),
    "Omit valid candidate": ("Candidate recomputation", d_omit_candidate),
    "Add invalid candidate": ("Candidate recomputation", d_add_candidate),
    "Modify HE aggregate": ("ACL recomputation", d_modify_aggregate),
    "Aggregate wrong candidate set": ("ACL recomputation", d_wrong_set),
    "Swap prescribed HE feature": ("ACL recomputation (C_spec)", d_modify_spec),
    "Modify contracted relation": ("Graph-lineage verification", d_modify_relation),
    "Omit contributing graph evidence": ("Graph-lineage verification", d_omit_graph_evidence),
    "Modify graph evidence/features": ("C_G/recomputation", d_modify_features),
    "Suppress an entity update": ("Graph-lineage verification", d_drop_update),
    "Modify drift D_e": ("Graph-lineage verification", d_modify_drift),
}


LEVELS = {"ACL": "full", "Retrieval-Only": "retrieval", "No-ACL": "none"}
VARIANT = "J"
RATES = [0.01, 0.05, 0.1, 0.25, 0.5]


def rate_trial(name: str, p: float, seed: int) -> dict:
    """Journal v2 rate sweep: over the whole run the cloud deviates on each Phase 3 request with
    probability p; every deviating request is counted, and the EE's rejections with it."""
    events, _ = generate(replace(DATA, seed=seed))
    from siemcrypt.data.synth import default_profiles_and_contexts
    from siemcrypt.system import SIEMCrypt
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(config(VARIANT, seed=seed), profiles, contexts)
    rng = random.Random(seed * 7 + int(p * 1000))
    attr, fn = DEVIATIONS[name][1](s, rng)
    orig = getattr(s.cloud, attr)
    n = {"calls": 0, "dev": 0, "changed": 0}

    def wrapped(q, fi):
        n["calls"] += 1
        if rng.random() >= p:
            return orig(q, fi)
        n["dev"] += 1
        bad, good = fn(q, fi), orig(q, fi)
        n["changed"] += int(bad["C_A"] != good["C_A"] or bad["Q"] != good["Q"] or bad["postings"] != good["postings"])
        return bad

    setattr(s.cloud, attr, wrapped)
    s.run(events)
    return dict(deviation=name, rate=p, seed=seed, requests=n["calls"], deviated=n["dev"], effective=n["changed"],
                rejected=s.ee.stats["acl_reject"])


def trial(name: str, seed: int, level: str = "ACL") -> dict:
    events, _ = generate(replace(DATA, seed=seed))
    last = max(int(ev.ts // 3600) + 1 for ev in events)
    s = run(config(VARIANT, seed=seed, acl_level=LEVELS[level]), [ev for ev in events if int(ev.ts // 3600) + 1 < last])
    rng = random.Random(seed)
    attr, fn = DEVIATIONS[name][1](s, rng)
    setattr(s.cloud, attr, fn)
    before = dict(s.ee.stats)
    n_audit = len(s.ka.audit)
    s.run_epoch(last, [ev for ev in events if int(ev.ts // 3600) + 1 == last])
    st = s.ee.stats
    delta = {k: st[k] - before.get(k, 0) for k in ("acl_reject", "graph_reject", "graph_omitted", "drift_reject")}
    detected = any(delta.values())
    released = len(s.ka.audit) - n_audit
    ph4 = next((r for r in reversed(s.ee.acl_log) if r["kind"] == "phase4"), None)  # none below full ACL
    return dict(deviation=name, stage=DEVIATIONS[name][0], level=level, seed=seed, detected=int(detected), **delta,
                releases=released, contexts=len(s.ee.contexts),
                inconsistent_admitted=None if ph4 is None else (0 if ph4["ok"] or detected else 1))


def honest(seed: int) -> dict:
    events, _ = generate(replace(DATA, seed=seed))
    s = run(config(VARIANT, seed=seed), events)
    st = s.ee.stats
    return dict(seed=seed, false_rejects=st["acl_reject"] + st["graph_reject"] + st["graph_omitted"] + st["drift_reject"],
                checks=len(s.ee.acl_log))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--variant", default="J", choices=["J", "J2"])
    args = ap.parse_args()
    global VARIANT
    VARIANT = args.variant
    seeds = list(range(1, args.trials + 1))
    t0 = time.time()
    with ProcessPoolExecutor(args.workers) as ex:
        jobs = [(n, sd, lv) for lv in LEVELS for n in DEVIATIONS for sd in seeds]
        rows = list(ex.map(trial, *zip(*jobs)))
        clean = list(ex.map(honest, seeds))
        rate_devs = [n for n, (_, f) in DEVIATIONS.items() if f.__name__ in (
            "d_omit_posting", "d_substitute_posting", "d_omit_candidate", "d_add_candidate",
            "d_modify_aggregate", "d_wrong_set", "d_modify_spec")]
        rjobs = [(n, p, sd) for n in rate_devs for p in RATES for sd in seeds]
        rrows = list(ex.map(rate_trial, *zip(*rjobs)))
    write_csv("e5_acl_rate.csv", rrows)
    write_csv("e5_acl_deviation.csv", rows)
    md = ["# Journal Experiment 5: deviations against ACL (synthetic data)\n",
          f"Trials {seeds}; the deviation happens in the last epoch. Released = KA releases in that epoch "
          f"(out of {rows[0]['contexts']} contexts per trial).\n",
          "| Injected deviation | Detection stage | Detected | Contexts rejected | Updates rejected / omitted | Released |",
          "|---|---|---|---|---|---|"]
    for n, (stage, _) in DEVIATIONS.items():
        sel = [r for r in rows if r["deviation"] == n and r["level"] == "ACL"]
        md.append(f"| {n} | {stage} | {sum(r['detected'] for r in sel)}/{len(sel)} | "
                  f"{sum(r['acl_reject'] for r in sel)} | {sum(r['graph_reject'] for r in sel)} / "
                  f"{sum(r['graph_omitted'] for r in sel)} | {sum(r['releases'] for r in sel)} |")
    md += ["", "Detection by verification level (journal v2: No-ACL / Retrieval-Only / ACL):", "",
           "| Injected deviation | " + " | ".join(LEVELS) + " |", "|---" * (len(LEVELS) + 1) + "|"]
    for n in DEVIATIONS:
        cells = []
        for lv in LEVELS:
            sel = [r for r in rows if r["deviation"] == n and r["level"] == lv]
            cells.append(f"{sum(r['detected'] for r in sel)}/{len(sel)}")
        md.append(f"| {n} | " + " | ".join(cells) + " |")
    md += ["", f"Rate sweep ({VARIANT}): the cloud deviates on each Phase 3 request with probability p over "
           f"the whole run; rejected / effective deviations (effective = the answer actually differs).", "",
           "| Injected deviation | " + " | ".join(f"p={p}" for p in RATES) + " |", "|---" * (len(RATES) + 1) + "|"]
    for n in rate_devs:
        cells = []
        for p in RATES:
            sel = [r for r in rrows if r["deviation"] == n and r["rate"] == p]
            cells.append(f"{sum(r['rejected'] for r in sel)}/{sum(r['effective'] for r in sel)}")
        md.append(f"| {n} | " + " | ".join(cells) + " |")
    md.append(f"\nHonest runs: {sum(r['false_rejects'] for r in clean)} false rejections over "
              f"{sum(r['checks'] for r in clean)} verifications ({len(clean)} runs).")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e5_acl_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
