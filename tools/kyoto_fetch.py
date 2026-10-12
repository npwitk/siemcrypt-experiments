"""Fetch Kyoto 2016 (for B6, Ogawa et al.) from the AnoShift benchmark release
(Dragoi et al., NeurIPS 2022 Datasets and Benchmarks; parquet per year), because the
original site takakura.com/Kyoto_data is not reachable. The 8.1 GB archive is streamed and
only the requested years are written to ~/data/kyoto2016.

Usage:  python tools/kyoto_fetch.py [--years 2007,2011,2015]
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

URL = "https://storage.googleapis.com/bitdefender_ml_artifacts/anoshift/Kyoto-2016_AnoShift.tar"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", default="2007,2011,2015")
    ap.add_argument("--dest", default="~/data/kyoto2016")
    args = ap.parse_args()
    dest = Path(args.dest).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    pats = [f"*{y}*" for y in args.years.split(",")]
    cmd = f"curl -sSfL {URL} | tar -x -C '{dest}' --wildcards " + " ".join(f"'{p}'" for p in pats)
    print(cmd, flush=True)
    subprocess.run(cmd, shell=True, check=True)
    for p in sorted(dest.rglob("*.parquet")):
        print(f"{p.stat().st_size / 2**20:8.1f} MB  {p.relative_to(dest)}")


if __name__ == "__main__":
    main()
