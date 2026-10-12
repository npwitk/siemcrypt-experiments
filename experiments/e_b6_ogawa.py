"""B6 (Ogawa et al., COMPSAC 2025): reproduce the privacy-utility trade-off of
privacy-aware anonymization on Kyoto 2016 (Tables III-IV, Section IV-C).

Fetch the data first:  python tools/kyoto_fetch.py
Usage:  python experiments/e_b6_ogawa.py [--years 2007,2011,2015] [--seeds 3] [--synthetic]
  --synthetic  a generated Kyoto-format table (pipeline test only)
Writes results/b6_ogawa.csv and b6_ogawa.md.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, mean_sd, write_csv  # noqa: E402

from siemcrypt.baselines import ogawa as O  # noqa: E402

PAPER_KYOTO = {"original": 0.9867, "proposed": 0.9770, "minus1": 0.9603}  # Table III, F1


def synthetic(n: int = 60_000, seed: int = 0):
    import pandas as pd

    r = np.random.default_rng(seed)
    mal = r.random(n) < 0.5
    df = pd.DataFrame({
        "duration": np.where(mal, r.exponential(0.5, n), r.exponential(20, n)),
        "service": np.where(mal, r.choice(["other", "dns", "ssh"], n), r.choice(["smtp", "http", "dns", "other"], n)),
        "src_bytes": np.where(mal, r.integers(0, 200, n), r.integers(0, 50_000, n)),
        "dst_bytes": np.where(mal, r.integers(0, 50, n), r.integers(0, 80_000, n)),
        **{c: r.random(n) * (5 if "count" in c else 1) for c in O.NUMERIC},
        "flag": np.where(mal, r.choice(["S0", "REJ", "SF"], n), r.choice(["SF", "S1"], n)),
        "label": np.where(mal, -1, 1),
        "src_ip": [f"fd95:{r.integers(0, 40):x}::{r.integers(0, 9)}" for _ in range(n)],
        "src_port": r.integers(0, 65535, n), "dst_ip": [f"fd95:0::{r.integers(0, 30)}" for _ in range(n)],
        "dst_port": np.where(mal, r.choice([22, 445, 3389], n), r.choice([25, 80, 53, 8080], n)),
        "start_time": np.arange(n, dtype=float), "protocol": r.choice(["tcp", "udp"], n),
    })
    return df


def load_year(root: Path, year: int):
    import pandas as pd

    files = sorted(root.rglob(f"{year}*.parquet"))
    files = [f for f in files if "valid" not in f.name] or files
    if not files:
        raise FileNotFoundError(f"no parquet for {year} under {root}")
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    if list(df.columns)[:3] != O.COLS[:3]:
        if len(df.columns) >= len(O.COLS):
            df = df.iloc[:, :len(O.COLS)]
            df.columns = O.COLS
        else:
            raise ValueError(f"unexpected columns {list(df.columns)}")
    for c in ("duration", "src_bytes", "dst_bytes", *O.NUMERIC):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    return df.sort_values("start_time", kind="stable").reset_index(drop=True)


def run_year(df, year, seed: int) -> list[dict]:
    y_all = (df["label"].astype(float) < 0).astype(int).to_numpy()
    r = np.random.default_rng(seed)
    ben, mal = np.flatnonzero(y_all == 0), np.flatnonzero(y_all == 1)
    need = 5000
    if len(ben) < 2 * need or len(mal) < 2 * need:
        need = min(len(ben), len(mal)) // 2
    b, m = r.permutation(ben), r.permutation(mal)
    tr = np.concatenate([b[:need], m[:need]])
    te = np.concatenate([b[need:2 * need], m[need:2 * need]])
    rows = []
    feats = {}
    for mode in ("original", "proposed", "minus1"):
        X, cols, svc, flg = O.features(df, mode)   # IP windows need the full time-ordered table
        feats[mode] = X
        res = O.lightgbm_eval(X[tr], y_all[tr], X[te], y_all[te], seed)
        k = O.k_anonymity(X[te])
        yt = y_all[te]
        rows.append(dict(year=year, seed=seed, mode=mode, n_train=len(tr), **res,
                         unique_benign=float((k[yt == 0] == 1).mean()), unique_malicious=float((k[yt == 1] == 1).mean()),
                         k5_benign=float((k[yt == 0] >= 5).mean()), k5_malicious=float((k[yt == 1] >= 5).mean())))
    # Table IV: uniqueness after anonymization as an extra feature
    Xp = feats["proposed"]
    ktr, kte = O.k_anonymity(Xp[tr]), O.k_anonymity(Xp[te])
    res = O.lightgbm_eval(np.hstack([Xp[tr], (ktr == 1)[:, None]]), y_all[tr],
                          np.hstack([Xp[te], (kte == 1)[:, None]]), y_all[te], seed)
    rows.append(dict(year=year, seed=seed, mode="proposed+uniqueness", n_train=len(tr), **res))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="~/data/kyoto2016")
    ap.add_argument("--years", default="2007,2011,2015")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--synthetic", action="store_true")
    args = ap.parse_args()
    t0 = time.time()
    rows = []
    for year in [int(x) for x in args.years.split(",")]:
        df = synthetic(seed=year) if args.synthetic else load_year(Path(args.data).expanduser(), year)
        print(f"{year}: {len(df):,} sessions, {(df['label'].astype(float) < 0).mean():.1%} malicious", flush=True)
        for sd in range(1, args.seeds + 1):
            rows += run_year(df, year, sd)
    write_csv("b6_ogawa.csv", rows)
    md = ["# B6: Ogawa et al. (COMPSAC 2025) reproduced on Kyoto 2016\n",
          f"Years {args.years}; {args.seeds} seeds; balanced 10,000 train / 10,000 test sessions per year; "
          f"LightGBM.{' SYNTHETIC DATA (pipeline test).' if args.synthetic else ''}\n",
          "| Features | Acc | Prec | Rec | F1 | F1 / original | Unique benign | Unique malicious | k>=5 benign | Paper F1 |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    f1o = np.mean([r["f1"] for r in rows if r["mode"] == "original"])
    for mode in ("original", "proposed", "minus1", "proposed+uniqueness"):
        sel = [r for r in rows if r["mode"] == mode]
        g = lambda k: mean_sd([r.get(k) for r in sel])  # noqa: E731
        md.append(f"| {mode} | {g('acc')} | {g('prec')} | {g('rec')} | {g('f1')} | "
                  f"{np.mean([r['f1'] for r in sel]) / f1o:.2%} | {g('unique_benign')} | {g('unique_malicious')} | "
                  f"{g('k5_benign')} | {PAPER_KYOTO.get(mode, '')} |")
    md.append("\nPaper (Section IV-C): unique sessions 89.91% benign / 96.41% malicious before, "
              "7.40% / 10.62% after anonymization (NII-SOCS); k >= 5 for 78.41% of benign sessions.")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "b6_ogawa.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
