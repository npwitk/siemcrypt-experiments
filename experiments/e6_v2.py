"""Journal v2 Experiment 6: lineage-scoped investigation over multiple epochs.

One 24-epoch stream (J2: ACL + D29 AQRS/padding) with low-and-slow, exfiltration and coordinated
attacks; the alerts of the last 12 epochs are investigated (up to --alerts per seed) under
  Lineage      the protocol: window = the alert's adaptive horizon ell, profile-scoped
               historical queries plus the lineage provenance
  Span-L       the same with a fixed window of L epochs, L in {1, 2, 4, 8, 16}
  Full-History every epoch since the first, every record of the entity (no profile scope)
Per investigation: window, verified / decrypted records (what the SA gets to see), decoys
dropped, identity resolved, latency split (EPII, checkpoint, MMR, C_Inv), bytes, and the proof
size of one MMR multiproof per epoch against independent per-record paths (S-IndPath).

Usage:  python experiments/e6_v2.py [--quick] [--seeds 3] [--alerts 8] [--bits 2048] [--workers 4]
Writes results/e6_v2.csv and e6_v2_summary.md.
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

from common import RESULTS, SynthConfig, config, generate, run, write_csv  # noqa: E402

from siemcrypt import lineage  # noqa: E402
from siemcrypt.crypto.mmr import proof_size  # noqa: E402

DATA = SynthConfig(epochs=24, events_per_epoch=400, n_users=80, n_brute_force=1, n_low_and_slow=3, n_exfil=1,
                   n_coordinated=1, lns_epochs=8, lns_per_epoch=4)
SPANS = [1, 2, 4, 8, 16]


def trial(seed: int, bits: int, n_alerts: int, spans: list[int]) -> list[dict]:
    events, truth = generate(replace(DATA, seed=seed))
    s = run(config("J2", paillier_bits=bits, seed=seed, precompute_workers=0), events)
    att = {gt.user for gt in truth}
    alerts = [d for d in s.sa.alerts if d.attack and d.epoch > DATA.epochs // 2][:n_alerts]
    modes = [("Lineage", {})] + [(f"Span-{L}", {"span": L}) for L in spans] + [("Full-History", {"full_history": True})]
    rows = []
    for i, d in enumerate(alerts):
        user = s.ee.resolve_current(d.epoch, d.token)
        for name, kw in modes:
            b0, h0 = sum(s.bus.bytes.values()), 0
            t0 = time.perf_counter()
            inv = s.investigate(d, **kw)
            dt = time.perf_counter() - t0
            multi = sum(proof_size(p["proof"]) for p in inv.evidence["packages"].values())
            indep = 0
            for tau, pkg in inv.evidence["packages"].items():
                t = s.cloud._mmr(tau)
                indep += sum(proof_size(t.multiprove({rid[1]})) for rid in pkg["records"])
            rows.append(dict(seed=seed, alert=i, attack=d.attack, attacker=int(user in att), mode=name,
                             window=len(inv.window), refs=len(inv.refs), verified=inv.verified_records,
                             plaintexts=len(inv.plaintexts), decoys=inv.decoys_dropped,
                             identity=int(inv.identity is not None), failed=len(inv.failed_epochs),
                             c_inv=int(inv.c_inv is not None), latency_ms=dt * 1e3,
                             bytes=sum(s.bus.bytes.values()) - b0, multiproof_hashes=multi, indpath_hashes=indep,
                             **{f"{k}_ms": v * 1e3 for k, v in inv.timing.items()}))
    # C_Inv binds the investigation: changing the window or the reference set changes it
    if alerts:
        inv = s.investigate(alerts[0])
        cps = inv.evidence["checkpoints"]
        roots = {tau: cp[0][1] for tau, cp in cps.items()}
        same = lineage.c_inv(alerts[0].state_commitment, inv.window, alerts[0].attack, inv.refs, roots,
                             {r for p in inv.evidence["packages"].values() for r in p["records"]})
        drop = set(list(inv.refs)[1:])
        alt = lineage.c_inv(alerts[0].state_commitment, inv.window, alerts[0].attack, drop, roots,
                            {r for p in inv.evidence["packages"].values() for r in p["records"]})
        for r in rows:
            r["c_inv_recomputes"] = int(same == inv.c_inv)
            r["c_inv_binds_refs"] = int(alt != inv.c_inv)
    s.close()
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--alerts", type=int, default=8)
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    spans = SPANS
    if a.quick:
        a.seeds, a.alerts, a.bits, spans = 1, 3, 512, [1, 4, 16]
    t0 = time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        rows = [r for rs in ex.map(trial, range(1, a.seeds + 1), [a.bits] * a.seeds, [a.alerts] * a.seeds,
                                   [spans] * a.seeds) for r in rs]
    write_csv("e6_v2.csv", rows)
    modes = ["Lineage"] + [f"Span-{L}" for L in spans] + ["Full-History"]
    cols = [("window", "window"), ("refs", "references"), ("verified", "verified"), ("plaintexts", "decrypted"),
            ("decoys", "decoys dropped"), ("identity", "identity resolved"), ("latency_ms", "latency (ms)"),
            ("epii_ms", "EPII (ms)"), ("checkpoint_ms", "checkpoint (ms)"), ("mmr_ms", "MMR (ms)"),
            ("c_inv_ms", "C_Inv (ms)"), ("bytes", "bytes"), ("multiproof_hashes", "multiproof hashes"),
            ("indpath_hashes", "S-IndPath hashes")]
    md = ["# Journal v2 Experiment 6: lineage-scoped investigation (synthetic)", "",
          f"{a.seeds} seeds x up to {a.alerts} alerts, {DATA.epochs} epochs, J2 (ACL + D29), Paillier {a.bits} bits. "
          "Mean per investigation.", "",
          "| Mode | " + " | ".join(c[1] for c in cols) + " |", "|---|" + "---|" * len(cols)]
    for m in modes:
        sel = [r for r in rows if r["mode"] == m]
        if sel:
            md.append(f"| {m} | " + " | ".join(
                f"{statistics.mean(r.get(k, 0) for r in sel):,.2f}" for k, _ in cols) + " |")
    if rows:
        md += ["", f"Failed epochs (should be 0): {sum(r['failed'] for r in rows)}. C_Inv recomputes from the "
               f"evidence: {all(r.get('c_inv_recomputes', 1) for r in rows)}; changes when one reference is dropped: "
               f"{all(r.get('c_inv_binds_refs', 1) for r in rows)}."]
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e6_v2_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
