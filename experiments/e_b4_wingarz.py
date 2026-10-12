"""B4 (Wingarz et al., CNS 2024): reproduce Baseline50 / CKKS50 on CSE-CIC-IDS2018 and
measure the encrypted-inference cost on this machine, for the E2 comparison with SIEMCrypt.

Fetch the data first:  python tools/cicids2018_fetch.py
Usage:  python experiments/e_b4_wingarz.py [--quick] [--he-batches 3]
  --quick  one day of data (Thursday-01-03-2018), 10^5 rows, 5 epochs, one HE batch
Writes results/b4_wingarz.csv and b4_wingarz.md (paper values alongside, Tables VII-VIII).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, write_csv  # noqa: E402

from siemcrypt.baselines import wingarz as W  # noqa: E402

PAPER = {"Baseline50": dict(acc=0.9872, prec=0.9981, rec=0.9264, f1=0.9610),
         "CKKS50": dict(acc=0.9871, prec=0.9983, rec=0.9257, f1=0.9607, batch_s=1.35, batch_mb=59.6)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="~/data/cse-cic-ids2018")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--he-batches", type=int, default=3)
    ap.add_argument("--max-rows", type=int, default=None, help="subsample the dataset (default: all rows)")
    args = ap.parse_args()
    t0 = time.time()
    data = Path(args.data).expanduser()
    files = sorted(data.glob("*.csv"))
    if args.quick:
        files = [f for f in files if "Thursday-01-03-2018" in f.name] or files[:1]
    if not files:
        sys.exit("no CSV files: run tools/cicids2018_fetch.py first")
    max_rows = 100_000 if args.quick else args.max_rows
    X, y, names, removed = W.load(files, max_rows)
    n_raw = len(X)
    X64, n64 = W.drop_correlated(X, names, 1.0)
    X50, n50 = W.drop_correlated(X64, n64, 0.99)
    print(f"{n_raw:,} rows ({removed:.2%} removed: NaN/inf), {X.shape[1]} non-constant features -> "
          f"{X64.shape[1]} (corr = 1) -> {X50.shape[1]} (corr > 0.99); attacks {y.mean():.2%}", flush=True)
    rng = np.random.default_rng(0)
    perm = rng.permutation(len(X50))
    a, b = int(0.8 * len(perm)), int(0.9 * len(perm))
    tr, va, te = perm[:a], perm[a:b], perm[b:]
    Xtr, Xva, Xte = W.minmax(X50[tr], X50[va], X50[te])
    layers = W.train(Xtr.astype(np.float32), y[tr], Xva.astype(np.float32), y[va],
                     epochs=5 if args.quick else 150)
    plain = W.metrics(y[te], W.plain_predict(layers, Xte))
    print(f"Baseline50 (plaintext) on {len(te):,} test vectors: {plain}", flush=True)

    ctx = W.ckks_context()
    nb = 1 if args.quick else args.he_batches
    rows, preds, ys = [], [], []
    for k in range(nb):
        idx = np.arange(k * W.BATCH, min((k + 1) * W.BATCH, len(te)))
        if not len(idx):
            break
        p, st = W.ckks_infer(ctx, layers, Xte[idx])
        same = float((p == W.plain_predict(layers, Xte[idx])).mean())
        rows.append(dict(batch=k, **st, agree_with_plaintext=same))
        preds.append(p)
        ys.append(y[te][idx])
        print(f"  HE batch {k}: {st['vectors']} vectors, server {st['eval_s']:.2f} s, "
              f"{st['batch_bytes'] / 2**20:.1f} MB, agreement {same:.4%}", flush=True)
    he = W.metrics(np.concatenate(ys), np.concatenate(preds))
    write_csv("b4_wingarz.csv", [dict(model="Baseline50", **plain), dict(model="CKKS50", **he)] + rows)
    ev = np.mean([r["eval_s"] for r in rows])
    full = [r for r in rows if r["vectors"] == W.BATCH]
    mb = np.mean([r["batch_bytes"] for r in rows]) / 2**20
    md = ["# B4: Wingarz et al. (CNS 2024) reproduced\n",
          f"Data: {', '.join(f.name for f in files)}; {n_raw:,} rows after cleaning; {X50.shape[1]} features; "
          f"split 80/10/10; CKKS N = 16384, q = [60, 5x40, 60], scale 2^40 (TenSEAL).\n",
          "| Model | Acc | Prec | Rec | F1 | Server s / batch | MB / batch | µs / vector |", "|---|---|---|---|---|---|---|---|",
          f"| Baseline50 (ours) | {plain['acc']:.4f} | {plain['prec']:.4f} | {plain['rec']:.4f} | {plain['f1']:.4f} | | | |",
          f"| CKKS50 (ours) | {he['acc']:.4f} | {he['prec']:.4f} | {he['rec']:.4f} | {he['f1']:.4f} | {ev:.2f} | {mb:.1f} | "
          f"{ev / W.BATCH * 1e6:.0f} |",
          f"| Baseline50 (paper) | {PAPER['Baseline50']['acc']} | {PAPER['Baseline50']['prec']} | {PAPER['Baseline50']['rec']} | "
          f"{PAPER['Baseline50']['f1']} | | | |",
          f"| CKKS50 (paper) | {PAPER['CKKS50']['acc']} | {PAPER['CKKS50']['prec']} | {PAPER['CKKS50']['rec']} | "
          f"{PAPER['CKKS50']['f1']} | {PAPER['CKKS50']['batch_s']} | {PAPER['CKKS50']['batch_mb']} | 165 |",
          f"\nA batch costs the same time whether full or not ({len(full)} of {len(rows)} batches were full); "
          "per-vector cost assumes full batches of 8,192.",
          f"\nTotal time {time.time() - t0:.0f}s"]
    (RESULTS / "b4_wingarz.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
