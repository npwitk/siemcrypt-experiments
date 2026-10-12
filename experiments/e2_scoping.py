"""E2 (part B3): benefit of search-scoped aggregation (SG-HEF) against a full-HE SIEM.

B3 has no encrypted index to scope aggregation: every record carries, for every context q
and feature f, Enc(w * x_f * 1[record matches q]), and the cloud aggregates each context
over every record of the epoch. Its releases equal SIEMCrypt's (tests/test_pipeline.py),
so only cost differs. The sweep varies the number of correlation contexts K, since a
deployed SIEM runs many rules and B3's cost grows with K while SG-HEF's ingestion does not.

Measures per real event: HE encryptions, bytes EE -> cloud, and the offline randomizer
cost predicted at 2048 bits from E2's T_rand; per epoch: homomorphic additions in Phase 3
and their predicted 2048-bit time from E2's T_Add. Counts do not depend on the key size,
so the runs use 512-bit keys.

Usage:  python experiments/e2_scoping.py [--quick] [--seeds 3] [--workers 8]
Writes results/e2_scoping.csv and e2_scoping.md.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, config, generate, mean_sd, run, write_csv  # noqa: E402
from e1_accuracy import TEST  # noqa: E402

from siemcrypt.data.synth import default_profiles_and_contexts  # noqa: E402
from siemcrypt.model import Context, Policy  # noqa: E402

KS = [3, 12, 48]


def contexts_for(k: int) -> list[Context]:
    """The default contexts, then one single-category context per (category, source) pair
    of the synthetic stream until there are k (a SIEM with k correlation rules)."""
    _, base = default_profiles_and_contexts()
    out = list(base[:k])
    events, _ = generate(replace(TEST, seed=1))
    cats = sorted({ev.cat for ev in events})
    srcs = sorted({ev.src for ev in events})
    pairs = itertools.cycle(itertools.product(cats, srcs))
    attacks = [c.attack for c in base]
    i = 0
    while len(out) < k:
        c, s = next(pairs)
        out.append(Context(f"q_extra_{i}", attacks[i % len(attacks)], categories=frozenset({c}),
                           sources=frozenset({s}), feats=("count", "bytes"), policy=Policy.VALUE))
        i += 1
    return out


def unit_costs() -> dict[str, float]:
    """T_rand and T_Add (us) from E2 if it ran at 2048 bits on this machine."""
    path = RESULTS / "e2_microbench.csv"
    if not path.exists():
        return {}
    rows = list(csv.reader(path.open()))
    if next((r[1] for r in rows if r and r[0] == "paillier_bits"), None) != "2048":
        return {}
    get = lambda name: next((float(r[2]) for r in rows if r and r[0] == name), None)  # noqa: E731
    return {"T_rand": get("T_rand (offline)"), "T_Add": get("T_Add")}


def measure(system: str, k: int, seed: int) -> dict:
    profiles, _ = default_profiles_and_contexts()
    cfg = config("S", seed=seed, full_he=(system == "B3"))
    events, _ = generate(replace(TEST, seed=seed))
    s = run(cfg, events, profiles, contexts_for(k))
    st, epochs = s.ee.stats, len(s.reports)
    real = max(st["real"], 1)
    return dict(system=system, contexts=k, seed=seed, events=real,
                he_enc_per_event=st["he_enc"] / real,
                bytes_per_event=s.bus.total("ee", "cloud") / real,
                he_adds_per_epoch=s.cloud.he_adds / epochs,
                phase3_s_per_epoch_512=s.timing["phase3"] / epochs)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    seeds = list(range(1, (1 if args.quick else args.seeds) + 1))
    ks = KS[:2] if args.quick else KS
    t0 = time.time()
    jobs = [(sy, k, sd) for sy in ("S", "B3") for k in ks for sd in seeds]
    with ProcessPoolExecutor(args.workers) as ex:
        rows = list(ex.map(measure, *zip(*jobs)))
    uc = unit_costs()
    for r in rows:
        r["pred_offline_ms_per_event_2048"] = r["he_enc_per_event"] * uc["T_rand"] / 1e3 if uc.get("T_rand") else None
        r["pred_phase3_ms_per_epoch_2048"] = r["he_adds_per_epoch"] * uc["T_Add"] / 1e3 if uc.get("T_Add") else None
    write_csv("e2_scoping.csv", rows)

    cols = [("he_enc_per_event", "HE enc / event"), ("bytes_per_event", "Bytes / event"),
            ("pred_offline_ms_per_event_2048", "Offline ms / event @2048"),
            ("he_adds_per_epoch", "HE additions / epoch"), ("pred_phase3_ms_per_epoch_2048", "Phase 3 ms / epoch @2048")]
    use = [c for c in cols if any(r.get(c[0]) is not None for r in rows)]
    md = ["# E2: SG-HEF (S) vs. full-HE SIEM (B3)\n",
          f"Synthetic test stream, seeds {seeds}; K = number of correlation contexts. Releases are identical "
          "(tested); only cost differs. 2048-bit times are predicted from E2's T_rand and T_Add.\n",
          "| System | K | " + " | ".join(c[1] for c in use) + " |", "|---|---|" + "---|" * len(use)]
    for k in ks:
        for sy in ("S", "B3"):
            sel = [r for r in rows if r["system"] == sy and r["contexts"] == k]
            md.append(f"| {sy} | {k} | " + " | ".join(mean_sd([r.get(c) for r in sel]) for c, _ in use) + " |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e2_scoping.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
