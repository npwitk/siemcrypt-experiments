"""D29 grouping design: padding cost against privacy and detection (instructor request, 2026-11-04).

Designs (all total-only cohort padding, AQRS fixed-k partition)
  G<k>   consecutive groups of k volume ranks (D29 as run on AWS, k = 5)
  O<k>   cost-optimal groups of k..2k-1 consecutive ranks (dynamic programming, min sum(max - v))
  +R     D30: the EE recomputes graph features over real records after the C_G check
         (the cloud's degree / bucket features count decoys)
  NP, LAPH-E   references

Part A  default stream (e3_leakage.TEST / e1 TEST): volume attacks (delta, HE enc/event, high-exposure
        user recovery, linkage, decoy AUC) and detection (macro F1 / AUC, per-class recall)
Part B  query identification (e3_aqrs attacks) for G/O x k in {3, 5, 8}
Part C  data size: delta, HE enc/event, user recovery and identification as the stream grows,
        (i) more users at a fixed per-user rate, (ii) more events per user at 80 users

Usage:  python experiments/e3_d29_design.py [--parts ABC] [--seeds 5] [--workers 8] [--quick]
Writes results/e3_d29_design_{A,B,C}.csv and e3_d29_design.md.
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

from common import RESULTS, SynthConfig, write_csv  # noqa: E402
from e1_accuracy import CLASSES  # noqa: E402
from e3_aqrs import learned, run_one, summarize  # noqa: E402
from e3_d29_padding import detect  # noqa: E402
from e3_laph import attacks, prepare, spec  # noqa: E402
from e3_leakage import TEST  # noqa: E402


def design(k: int, opt: bool, real: bool = False) -> dict:
    return dict(variant="S", aqrs="fixed", aqrs_fixed_k=k, aqrs_select="partition", padding="cohort",
                cpad_cats=False, aqrs_part="opt" if opt else "chunk", graph_real_only=real)


SYS_A = {"NP": spec("NP"), "LAPH-E": spec("LAPH-E"), "NP+R": dict(spec("NP"), graph_real_only=True),
         "LAPH-E+R": dict(spec("LAPH-E"), graph_real_only=True),
         **{f"{p}{k}{r}": design(k, p == "O", r == "+R") for k in (3, 5, 8) for p in ("G", "O") for r in ("", "+R")}}
SYS_B = [f"D29-{p}{k}" for k in (3, 5, 8) for p in ("G", "O")]
SIZE_SYS = {"G5": design(5, False), "O5": design(5, True), "G3": design(3, False), "O3": design(3, True)}
USERS = [80, 200, 500, 1000]
EPE = [600, 1500, 3000, 6000]
COLS_A = [("delta", "decoys / real"), ("he_enc_per_event", "HE enc / event"), ("U_recovery", "U recovery"),
          ("U_recovery_high", "high-exposure U"), ("U_recovery_da", "U (decoy-aware)"),
          ("linkage", "linkage"), ("linkage_high", "linkage high"), ("decoy_auc", "decoy AUC")]
COLS_D = [("macro_f1", "macro F1"), ("macro_auc", "macro AUC")] + [(f"{c}_r", f"{c} recall") for c in CLASSES]


def mean(rows, k):
    v = [r[k] for r in rows if isinstance(r.get(k), (int, float))]
    return f"{statistics.mean(v):.3f}" if v else "-"


def table(rows, keys, cols, label):
    out = [f"| {label} | " + " | ".join(c[1] for c in cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for k in keys:
        rs = [r for r in rows if r["system"] == k]
        if rs:
            out.append(f"| {k} | " + " | ".join(mean(rs, c) for c, _ in cols) + " |")
    return out


def ident(name: str, seeds, sc, ex) -> list[dict]:
    jobs = [(n, s, 512, sc) for n in ([name] if isinstance(name, str) else name) for s in seeds]
    rows = [r for rs in ex.map(run_one, jobs) for r in rs]
    learned(rows, sc.epochs)
    return [r for r in summarize(rows, sc.epochs) if r["cls"] in ("all", "atk", 2)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", default="ABC")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    seeds = list(range(1, (2 if a.quick else a.seeds) + 1))
    md = ["# D29 grouping design: padding cost vs privacy and detection (synthetic)", "",
          f"Seeds {seeds}. Lower is better for every attack column (decoy AUC: 0.5 ideal). "
          "G = consecutive groups of k, O = cost-optimal groups of k..2k-1, +R = graph features over real "
          "records (D30).", ""]
    t0 = time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        if "A" in a.parts:
            names = list(SYS_A)
            rowsA = list(ex.map(attacks, *zip(*[(n, SYS_A[n], s) for n in names for s in seeds])))
            profs = dict(zip(names, ex.map(prepare, [SYS_A[n] for n in names])))
            rowsD = list(ex.map(detect, *zip(*[(n, SYS_A[n], profs[n], s) for n in names for s in seeds])))
            write_csv("e3_d29_design_A.csv", [dict(part="attacks", **r) for r in rowsA] +
                      [{**r, "part": "detect"} for r in rowsD])
            md += ["## Part A: volume attacks (e3_leakage stream: 80 users, 600 events / epoch)", ""]
            md += table(rowsA, [n for n in names if not n.endswith("+R")], COLS_A, "Design") + [""]
            md += ["## Part A: detection (E1 test stream)", ""] + table(rowsD, names, COLS_D, "Design") + [""]
            print(f"A done {time.time() - t0:.0f}s", flush=True)
        if "B" in a.parts:
            sc = SynthConfig(epochs=8, events_per_epoch=1500, n_users=200, n_low_and_slow=2, n_exfil=1,
                             n_coordinated=1)
            if a.quick:
                sc = replace(sc, epochs=4, events_per_epoch=500, n_users=80)
            summ = ident(SYS_B, seeds, sc, ex)
            write_csv("e3_d29_design_B.csv", summ)
            md += ["## Part B: query identification (best attack; ideal = mean 1/|cohort|)", "",
                   "| Design | all | attacker hunts | high-risk | ideal (uniform) | mean cohort | decoys / real | "
                   "HE adds / hunt | bytes / hunt |", "|---" * 9 + "|"]
            for n in SYS_B:
                r = {x["cls"]: x for x in summ if x["system"] == n}
                if "all" in r:
                    al = r["all"]
                    md.append(f"| {n[4:]} | {al['best']:.3f} | {r.get('atk', {}).get('best', float('nan')):.3f} | "
                              f"{r.get(2, {}).get('best', float('nan')):.3f} | {al['uniform']:.3f} | "
                              f"{al['k_eff']:.2f} | {al['delta']:.3f} | {al['he_adds']:.0f} | {al['bytes']:.0f} |")
            md.append("")
            print(f"B done {time.time() - t0:.0f}s", flush=True)
        if "C" in a.parts:
            users = [80, 200] if a.quick else USERS
            epe = [600, 1500] if a.quick else EPE
            shapes = [("users", n, replace(TEST, n_users=n, events_per_epoch=int(7.5 * n))) for n in users]
            shapes += [("events", n, replace(TEST, events_per_epoch=n)) for n in epe]
            jobs = [(f"{kind}={x}|{nm}", sp, s, sc) for kind, x, sc in shapes for nm, sp in SIZE_SYS.items()
                    for s in seeds]
            rowsC = list(ex.map(attacks, *zip(*jobs)))
            for r in rowsC:
                shape, r["design"] = r["system"].split("|")
                r["axis"], r["size"] = shape.split("=")
            # identification at each size for G5 / O5 (2 seeds: the query attack is the slow part)
            idrows = []
            for kind, x, sc in shapes:
                sc2 = SynthConfig(epochs=6, events_per_epoch=sc.events_per_epoch, n_users=sc.n_users,
                                  n_low_and_slow=2, n_exfil=1, n_coordinated=1)
                for r in ident(["D29-G5", "D29-O5"], seeds[:2], sc2, ex):
                    if r["cls"] == "all":
                        idrows.append(dict(axis=kind, size=x, design=r["system"][4:], ident=r["best"],
                                           uniform=r["uniform"]))
            write_csv("e3_d29_design_C.csv", rowsC)
            write_csv("e3_d29_design_C_ident.csv", idrows)
            for axis, title, xs in (("users", "more users, 7.5 events per user per epoch", users),
                                    ("events", "more events per user, 80 users", epe)):
                md += [f"## Part C: data size, {title}", "",
                       "| Design | " + " | ".join(f"{axis}={x}" for x in xs) + " |", "|---" * (len(xs) + 1) + "|"]
                for metric, lab in (("delta", "decoys / real"), ("he_enc_per_event", "HE enc / event"),
                                    ("U_recovery_high", "high-exposure U"), ("linkage", "linkage")):
                    for d in SIZE_SYS:
                        cells = [mean([r for r in rowsC if r["axis"] == axis and r["size"] == str(x)
                                       and r["design"] == d], metric) for x in xs]
                        md.append(f"| {d} {lab} | " + " | ".join(cells) + " |")
                for d in ("G5", "O5"):
                    cells = []
                    for x in xs:
                        v = [r["ident"] for r in idrows if r["axis"] == axis and r["size"] == x and r["design"] == d]
                        cells.append(f"{statistics.mean(v):.3f}" if v else "-")
                    md.append(f"| {d} identification | " + " | ".join(cells) + " |")
                md.append("")
            print(f"C done {time.time() - t0:.0f}s", flush=True)
    md.append(f"Total time {time.time() - t0:.0f}s")
    out = RESULTS / f"e3_d29_design{'_' + a.parts if a.parts != 'ABC' else ''}.md"
    out.write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
